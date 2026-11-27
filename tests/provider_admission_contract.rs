//! Qualification-only executable contract. Not linked into production Tachyon.
//! Identity and evidence rules deliberately exclude routing/UI integration.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

type Digest32 = [u8; 32];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Identity(Digest32);

fn identity(
    source: &str,
    policy_revision: Digest32,
    route_context: &Value,
    outbound: &Value,
) -> Option<Identity> {
    let mut leaf = outbound.as_object()?.clone();
    // Initial qualification supports independent VLESS only. A detour or an
    // unrecognized protocol needs its own resolved dependency/identity contract.
    if source.is_empty()
        || !route_context.is_object()
        || leaf.get("type")?.as_str()? != "vless"
        || leaf.contains_key("detour")
        || leaf.get("server")?.as_str()?.is_empty()
        || leaf.get("server_port")?.as_u64().is_none_or(|p| p == 0 || p > 65535)
        || leaf.get("uuid")?.as_str()?.is_empty()
    {
        return None;
    }
    leaf.remove("tag");
    // All transport/auth fields (including Reality short_id) stay in the
    // identity. serde_json's default map ordering is deterministic.
    let material = json!({
        "schema": 1,
        "source": source,
        "policy_revision": policy_revision,
        "route_context": route_context,
        "outbound": leaf,
    });
    Some(Identity(Sha256::digest(material.to_string().as_bytes()).into()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Pass,
    Reject,
}

struct Evidence {
    identity: Identity,
    attempt: Digest32,
    at: u64,
    verdict: Verdict,
}

enum Fetch<'a> {
    Complete(&'a [Identity]),
    Failed,
    Partial,
}

#[derive(Default)]
struct State {
    proofs: BTreeMap<Identity, u64>,
    checked_at: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
enum GateError {
    RevisionChanged,
    InvalidClock,
}

struct Attempt<'a> {
    expected_revision: Digest32,
    current_revision: Digest32,
    nonce: Digest32,
    started_at: u64,
    now: u64,
    max_age: u64,
    cached: &'a [Identity],
    fetch: Fetch<'a>,
    evidence: &'a [Evidence],
}

fn reconcile(previous: &State, a: Attempt<'_>) -> Result<State, GateError> {
    if a.current_revision != a.expected_revision {
        return Err(GateError::RevisionChanged);
    }
    if a.max_age == 0 || a.started_at > a.now {
        return Err(GateError::InvalidClock);
    }

    let (candidates, complete) = match a.fetch {
        Fetch::Complete(nodes) => (nodes, true),
        Fetch::Failed | Fetch::Partial => (a.cached, false),
    };
    let candidates: BTreeSet<_> = candidates.iter().copied().collect();
    let mut passed = BTreeMap::<Identity, u64>::new();
    let mut rejected = BTreeSet::<Identity>::new();

    if complete {
        for e in a.evidence {
            if e.attempt != a.nonce
                || e.at < a.started_at
                || e.at > a.now
                || a.now - e.at > a.max_age
                || !candidates.contains(&e.identity)
            {
                continue;
            }
            match e.verdict {
                Verdict::Pass => {
                    let ts = passed.entry(e.identity).or_insert(e.at);
                    *ts = (*ts).max(e.at);
                }
                Verdict::Reject => {
                    rejected.insert(e.identity);
                }
            }
        }
    }

    let mut proofs = BTreeMap::new();
    for id in &candidates {
        if rejected.contains(id) {
            continue;
        }
        let fresh = previous
            .proofs
            .get(id)
            .copied()
            .filter(|ts| *ts <= a.now && a.now - *ts <= a.max_age);
        let ts = passed.get(id).copied().into_iter().chain(fresh).max();
        if let Some(ts) = ts {
            proofs.insert(*id, ts);
        }
    }
    let fully_checked = complete
        && !candidates.is_empty()
        && candidates
            .iter()
            .all(|id| passed.contains_key(id) || rejected.contains(id));

    Ok(State {
        proofs,
        checked_at: if fully_checked {
            Some(a.now)
        } else {
            previous.checked_at.filter(|ts| *ts <= a.now)
        },
    })
}

fn node() -> Value {
    json!({
        "type":"vless", "tag":"fixture", "server":"example.net", "server_port":443,
        "uuid":"11111111-1111-4111-8111-111111111111",
        "tls":{"enabled":true,"reality":{"enabled":true,"short_id":"abcd"}}
    })
}

fn id(source: &str, rev: u8, ctx: &Value, n: &Value) -> Identity {
    identity(source, [rev; 32], ctx, n).expect("supported fixture")
}

#[test]
fn transport_identity_keeps_auth_and_ignores_only_display_tag() {
    let ctx = json!({"resolver":"fixture-dns"});
    let n = node();
    let original = id("source", 1, &ctx, &n);
    let mut changed = n.clone();
    changed["tag"] = json!("renamed");
    assert!(original == id("source", 1, &ctx, &changed));
    changed["uuid"] = json!("22222222-2222-4222-8222-222222222222");
    assert!(original != id("source", 1, &ctx, &changed));
    changed = n.clone();
    changed["tls"]["reality"]["short_id"] = json!("ef01");
    assert!(original != id("source", 1, &ctx, &changed));
    assert!(original != id("other", 1, &ctx, &n));
    assert!(original != id("source", 2, &ctx, &n));
    assert!(original != id("source", 1, &json!({"resolver":"other"}), &n));
}

#[test]
fn unsupported_or_incomplete_identity_is_not_admitted() {
    let ctx = json!({});
    let mut n = node();
    n["detour"] = json!("other");
    assert!(identity("source", [1; 32], &ctx, &n).is_none());
    n = node();
    n["type"] = json!("unsupported");
    assert!(identity("source", [1; 32], &ctx, &n).is_none());
    n = node();
    n["server_port"] = json!(0);
    assert!(identity("source", [1; 32], &ctx, &n).is_none());
    assert!(identity("", [1; 32], &ctx, &node()).is_none());
    assert!(identity("source", [1; 32], &Value::Null, &node()).is_none());
}

#[test]
fn object_order_does_not_change_identity() {
    let a: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
    let b: Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
    assert!(id("source", 1, &a, &node()) == id("source", 1, &b, &node()));
}

fn attempt<'a>(cached: &'a [Identity], fetch: Fetch<'a>, evidence: &'a [Evidence]) -> Attempt<'a> {
    Attempt {
        expected_revision: [1; 32],
        current_revision: [1; 32],
        nonce: [9; 32],
        started_at: 990,
        now: 1000,
        max_age: 100,
        cached,
        fetch,
        evidence,
    }
}

fn proof(id: Identity, verdict: Verdict, at: u64) -> Evidence {
    Evidence {
        identity: id,
        attempt: [9; 32],
        at,
        verdict,
    }
}

#[test]
fn empty_fetch_is_not_failed_or_partial_fetch() {
    let a = Identity([1; 32]);
    let b = Identity([2; 32]);
    let prior = State {
        proofs: [(a, 950), (b, 800)].into(),
        checked_at: Some(900),
    };
    let cached = [a, b];
    let forged = [proof(b, Verdict::Pass, 999)];
    for fetch in [Fetch::Failed, Fetch::Partial] {
        let out = reconcile(&prior, attempt(&cached, fetch, &forged)).unwrap();
        assert_eq!(out.proofs.len(), 1);
        assert_eq!(out.proofs.get(&a), Some(&950));
        assert_eq!(out.checked_at, Some(900));
    }
    let out = reconcile(&prior, attempt(&cached, Fetch::Complete(&[]), &[])).unwrap();
    assert!(out.proofs.is_empty());
}

#[test]
fn partial_verdicts_keep_old_fresh_proofs_but_do_not_renew_them() {
    let a = Identity([1; 32]);
    let b = Identity([2; 32]);
    let prior = State {
        proofs: [(a, 950)].into(),
        checked_at: Some(900),
    };
    let snapshot = [a, b];
    let e = [proof(b, Verdict::Pass, 997)];
    let out = reconcile(&prior, attempt(&snapshot, Fetch::Complete(&snapshot), &e)).unwrap();
    assert_eq!(out.proofs.get(&a), Some(&950));
    assert_eq!(out.proofs.get(&b), Some(&997));
    assert_eq!(out.checked_at, Some(900));
}

#[test]
fn explicit_reject_wins_for_duplicate_identity() {
    let a = Identity([1; 32]);
    let snapshot = [a, a];
    let e = [proof(a, Verdict::Pass, 999), proof(a, Verdict::Reject, 998)];
    let out = reconcile(
        &State::default(),
        attempt(&[], Fetch::Complete(&snapshot), &e),
    )
    .unwrap();
    assert!(out.proofs.is_empty());
    assert_eq!(out.checked_at, Some(1000));
}

#[test]
fn foreign_stale_future_or_unbound_observations_cannot_admit() {
    let a = Identity([1; 32]);
    let other = Identity([2; 32]);
    let snapshot = [a];
    let wrong_nonce = Evidence {
        attempt: [8; 32],
        ..proof(a, Verdict::Pass, 999)
    };
    let e = [
        proof(other, Verdict::Pass, 999),
        proof(a, Verdict::Pass, 989),
        proof(a, Verdict::Pass, 1001),
        wrong_nonce,
    ];
    let out = reconcile(
        &State::default(),
        attempt(&[], Fetch::Complete(&snapshot), &e),
    )
    .unwrap();
    assert!(out.proofs.is_empty());
    assert_eq!(out.checked_at, None);
}

#[test]
fn revision_and_clock_conflicts_fail_before_publication() {
    let mut a = attempt(&[], Fetch::Failed, &[]);
    a.current_revision = [2; 32];
    assert!(matches!(reconcile(&State::default(), a), Err(GateError::RevisionChanged)));
    let mut a = attempt(&[], Fetch::Failed, &[]);
    a.max_age = 0;
    assert!(matches!(reconcile(&State::default(), a), Err(GateError::InvalidClock)));
}

#[test]
fn removed_and_future_dated_previous_proofs_do_not_survive() {
    let a = Identity([1; 32]);
    let b = Identity([2; 32]);
    let prior = State {
        proofs: [(a, 1001), (b, 999)].into(),
        checked_at: Some(1001),
    };
    let out = reconcile(&prior, attempt(&[a], Fetch::Complete(&[a]), &[])).unwrap();
    assert!(out.proofs.is_empty());
    assert_eq!(out.checked_at, None);
}
