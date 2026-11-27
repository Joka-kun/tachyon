//! Exact, router-local admission for the managed provider group.
use crate::store::{RouterStoreData, unix_now_secs};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashSet},
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
};

/// Router-local binding; no deployment identifiers are compiled into the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    pub source_id: String,
    pub section_id: String,
    pub group_id: String,
    pub global_auto_tag: String,
    pub managed_auto_tag: String,
    pub managed_selector_tag: String,
}

impl AdmissionPolicy {
    fn validate(&self) -> Result<()> {
        let fields = [
            &self.source_id, &self.section_id, &self.group_id,
            &self.global_auto_tag, &self.managed_auto_tag, &self.managed_selector_tag,
        ];
        if fields.iter().any(|id| id.is_empty() || id.len() > 128 ||
            !id.bytes().all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))) {
            bail!("invalid router-local admission policy identifier");
        }
        if self.global_auto_tag == self.managed_auto_tag
            || self.global_auto_tag == self.managed_selector_tag
            || self.managed_auto_tag == self.managed_selector_tag {
            bail!("admission policy graph tags must be distinct");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Admission {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<AdmissionPolicy>,
    pub identities: BTreeSet<String>,
    pub checked_at: i64,
    pub tested: usize,
    pub rejected: usize,
    pub retained: usize,
}

impl Admission {
    pub fn policy(&self) -> Result<&AdmissionPolicy> {
        let policy = self.policy.as_ref().context("missing router-local admission policy")?;
        policy.validate()?;
        Ok(policy)
    }
}

pub fn store_digest(store: &RouterStoreData) -> Result<[u8; 32]> {
    // Value canonicalizes map order, including the store's HashMaps.
    Ok(Sha256::digest(serde_json::to_vec(&serde_json::to_value(store)?)?).into())
}

fn outbound<'a>(graph: &'a Value, tag: &str) -> Option<&'a Value> {
    graph["outbounds"]
        .as_array()?
        .iter()
        .find(|node| node["tag"] == tag)
}

fn identity(graph: &Value, tag: &str) -> Option<String> {
    let mut node = outbound(graph, tag)?.as_object()?.clone();
    // The bounded qualifier currently supports the independent native VLESS paths from the configured provider.
    if node.get("type")?.as_str()? != "vless" || node.get("detour").is_some() {
        return None;
    }
    node.remove("tag");
    // DNS health can replace the resolver endpoints during a reload without
    // changing the configured outbound or its authenticated transport.
    let context = json!({
        "leaf": node,
        "resolver": graph["route"]["default_domain_resolver"],
        "direct": outbound(graph, "direct"),
    });
    Some(format!(
        "{:x}",
        Sha256::digest(context.to_string().as_bytes())
    ))
}

fn global_candidates<'a>(graph: &'a Value, global_auto: &str) -> Vec<(usize, &'a str, String)> {
    outbound(graph, global_auto)
        .and_then(|global| global["outbounds"].as_array())
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(index, tag)| {
            let tag = tag.as_str()?;
            Some((index + 1, tag, identity(graph, tag)?))
        })
        .collect()
}

pub fn include_patterns(store: &RouterStoreData, admission: &Admission) -> Result<Vec<String>> {
    let policy = admission.policy()?;
    let graph = crate::config_gen::compile_core_config(store)?;
    let mut patterns = Vec::new();
    for (_, tag, hash) in global_candidates(&graph, &policy.global_auto_tag) {
        if !admission.identities.contains(&hash) {
            continue;
        }
        let mut pattern = String::from("^");
        for c in tag.chars() {
            if "\\.^$|?*+()[]{}".contains(c) {
                pattern.push('\\');
            }
            pattern.push(c);
        }
        pattern.push('$');
        patterns.push(pattern);
    }
    // Preserve a usable, fail-closed name list even if an upstream binary is restored.
    if patterns.is_empty() {
        patterns.push("^__TACHYON_NO_PROVIDER_ADMISSION__$".into());
    }
    Ok(patterns)
}

pub fn write_patterns(store: &mut RouterStoreData, patterns: Vec<String>) -> Result<bool> {
    let group_id = store.provider_admission.as_ref()
        .context("missing admission state")?.policy()?.group_id.clone();
    let group = store
        .outbound_groups
        .iter_mut()
        .find(|g| g.id == group_id)
        .context("missing managed provider group")?;
    let changed = group.filter_mode != "mixed" || group.include_regex != patterns;
    group.filter_mode = "mixed".into();
    group.include_regex = patterns;
    Ok(changed)
}

pub fn enforce(store: &RouterStoreData, graph: &mut Value) -> Result<()> {
    let Some(admission) = &store.provider_admission else {
        return Ok(());
    };
    let policy = admission.policy()?;
    let section = store.sections.iter().find(|s| s.id == policy.section_id)
        .context("managed admission section missing")?;
    if !section.enabled { return Ok(()); }
    if section.fail_policy != "reject"
        || section.outbound_group_refs.as_slice() != [policy.group_id.as_str()]
        || !section.outbound_source_refs.is_empty()
        || !section.outbound_group_ref.is_empty()
        || !section.section_refs.is_empty()
    {
        bail!("managed provider section has unexpected routing references");
    }

    let allowed: HashSet<String> = global_candidates(graph, &policy.global_auto_tag)
        .into_iter()
        .filter(|(_, _, hash)| admission.identities.contains(hash))
        .map(|(_, tag, _)| tag.to_owned())
        .collect();
    let Some(auto) = outbound(graph, policy.managed_auto_tag.as_str()) else {
        return Ok(());
    };
    let members = auto["outbounds"]
        .as_array()
        .context("missing managed AUTO members")?;
    let allowed: HashSet<String> = members
        .iter()
        .filter_map(Value::as_str)
        .filter(|tag| allowed.contains(*tag))
        .map(str::to_owned)
        .collect();

    let outbounds = graph["outbounds"]
        .as_array_mut()
        .context("missing native outbounds")?;
    for node in outbounds {
        let Some(tag) = node["tag"].as_str().map(str::to_owned) else {
            continue;
        };
        if tag != policy.managed_auto_tag.as_str() && tag != policy.managed_selector_tag.as_str() {
            continue;
        }
        if allowed.is_empty() {
            *node = json!({"type": "block", "tag": tag});
            continue;
        }
        if node["type"]
            != if tag == policy.managed_auto_tag.as_str() {
                "urltest"
            } else {
                "selector"
            }
        {
            bail!("unexpected native type for managed provider group");
        }
        let members = node["outbounds"]
            .as_array_mut()
            .context("missing native managed members")?;
        members.retain(|member| {
            member.as_str().is_some_and(|id| {
                allowed.contains(id) || (tag == policy.managed_selector_tag.as_str() && id == policy.managed_auto_tag.as_str())
            })
        });
        if tag == policy.managed_selector_tag.as_str()
            && node["default"]
                .as_str()
                .is_some_and(|id| id != policy.managed_auto_tag.as_str() && !allowed.contains(id))
        {
            node["default"] = json!(policy.managed_auto_tag.as_str());
        }
    }
    Ok(())
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub async fn qualify(store: &RouterStoreData, previous: &Admission) -> Result<Admission> {
    let policy = previous.policy()?.clone();
    let graph = crate::config_gen::compile_core_config(store)?;
    let path = std::env::temp_dir().join(format!(
        "tachyon-provider-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    let work = Scratch(path);
    fs::create_dir(work.0.join("results"))?;
    fs::write(work.0.join("graph.json"), serde_json::to_vec(&graph)?)?;
    // The shell helper has a bounded, loopback-only test Core and no publishing privileges of its own.
    // Partial results are usable if the helper times out, since each result is published atomically.
    let _ = tokio::process::Command::new("/usr/bin/timeout")
        .args(["240", "/usr/libexec/tachyon-provider-qualify"])
        .arg(&work.0)
        .env("TACHYON_ADMISSION_GLOBAL_AUTO", &policy.global_auto_tag)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .status()
        .await;
    let mut admission = Admission {
        policy: Some(policy.clone()),
        checked_at: unix_now_secs(),
        ..Admission::default()
    };
    let mut rejected = BTreeSet::new();
    let mut retained = BTreeSet::new();
    for (index, _, hash) in global_candidates(&graph, &policy.global_auto_tag) {
        let result =
            fs::read_to_string(work.0.join("results").join(index.to_string())).unwrap_or_default();
        match result.trim() {
            "pass" => {
                admission.tested += 1;
                admission.identities.insert(hash);
            }
            "reject" => {
                admission.tested += 1;
                admission.rejected += 1;
                rejected.insert(hash);
            }
            _ if previous.identities.contains(&hash) => {
                retained.insert(hash);
            }
            _ => {}
        }
    }
    admission.retained = retained.difference(&rejected).count();
    admission.identities.extend(retained);
    admission.identities.retain(|hash| !rejected.contains(hash));
    Ok(admission)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::RoutingSection;

    fn fixture_policy(prefix: &str) -> AdmissionPolicy {
        AdmissionPolicy {
            source_id: format!("{prefix}-source"),
            section_id: format!("{prefix}-section"),
            group_id: format!("{prefix}-group"),
            global_auto_tag: format!("{prefix}-global-auto"),
            managed_auto_tag: format!("{prefix}-managed-auto"),
            managed_selector_tag: format!("{prefix}-managed-selector"),
        }
    }

    fn graph(policy: &AdmissionPolicy) -> Value {
        json!({"outbounds":[
            {"tag":"A","type":"vless","server":"example.test","server_port":443},
            {"tag":"B","type":"vless","server":"example.test","server_port":8443},
            {"tag":policy.global_auto_tag.as_str(),"type":"urltest","outbounds":["A","B"]},
            {"tag":policy.managed_auto_tag.as_str(),"type":"urltest","outbounds":["A","B"]},
            {"tag":policy.managed_selector_tag.as_str(),"type":"selector","outbounds":[policy.managed_auto_tag.as_str(),"A","B"]}
        ]})
    }

    #[test]
    fn dns_failover_preserves_transport_identity() {
        let policy = fixture_policy("test-a");
        let mut config = graph(&policy);
        config["dns"]["servers"] = json!([{"tag":"dns-remote-1","server":"primary.test"}]);
        let before = identity(&config, "A").unwrap();
        config["dns"]["servers"][0]["server"] = json!("backup.test");
        assert_eq!(identity(&config, "A").as_deref(), Some(before.as_str()));
        config["outbounds"][0]["server_port"] = json!(9443);
        assert_ne!(identity(&config, "A").as_deref(), Some(before.as_str()));
    }

    #[test]
    fn changed_transport_cannot_inherit_a_name_and_global_stays_intact() {
        for prefix in ["test-a", "test-b"] {
        let policy = fixture_policy(prefix);
        let mut before = graph(&policy);
        let proof = identity(&before, "A").unwrap();
        let mut store = RouterStoreData::factory_defaults();
        store.sections = vec![RoutingSection {
            id: policy.section_id.as_str().into(),
            enabled: true,
            fail_policy: "reject".into(),
            outbound_group_refs: vec![policy.group_id.as_str().into()],
            ..Default::default()
        }];
        store.provider_admission = Some(Admission {
            policy: Some(policy.clone()),
            identities: [proof].into(),
            ..Default::default()
        });
        enforce(&store, &mut before).unwrap();
        assert_eq!(
            outbound(&before, policy.managed_auto_tag.as_str()).unwrap()["outbounds"],
            json!(["A"])
        );
        let mut changed = graph(&policy);
        changed["outbounds"][0]["server_port"] = json!(444);
        enforce(&store, &mut changed).unwrap();
        assert_eq!(
            outbound(&changed, policy.managed_selector_tag.as_str()).unwrap()["type"],
            "block"
        );
        assert_eq!(
            outbound(&changed, policy.global_auto_tag.as_str()),
            outbound(&before, policy.global_auto_tag.as_str())
        );
        }
    }

    #[test]
    fn configured_admission_requires_valid_local_policy() {
        let policy = fixture_policy("test-c");
        let mut graph = graph(&policy);
        let mut store = RouterStoreData::factory_defaults();
        store.provider_admission = Some(Admission::default());
        assert!(enforce(&store, &mut graph).is_err());
        let mut invalid = policy.clone();
        invalid.managed_auto_tag = invalid.global_auto_tag.clone();
        assert!(invalid.validate().is_err());
    }
}
