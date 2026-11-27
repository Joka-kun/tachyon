# Router-local admission binding (candidate only)

The six deployment identifiers are stored in the optional `policy` object of
`provider_admission` on the router, never in the public adapter. Fields:
`source_id`, `section_id`, `group_id`, `global_auto_tag`, `managed_auto_tag`,
`managed_selector_tag`. They must be nonempty and the three graph tags distinct.

This change is a candidate, not an installer. A stock store with no admission
state remains unaffected. An existing admission state without a local policy
fails validation; it must be migrated locally before installing this candidate.
Do not publish the real router store, its policy, profile files, or credentials.

The bounded local qualification helper receives `TACHYON_ADMISSION_GLOBAL_AUTO`.
The helper and the existing admission state must be qualified together with this
new contract before any deployment. The compiled candidate is not a trusted
stable release. Run native build tests and router acceptance first.

The privacy gate scans the fork-owned commit history and candidate evidence
using generic pattern checks plus a checksum-pinned Gitleaks release. Upstream
source archives and the derived ELF are separately checked for provenance;
upstream example credentials and private-network examples are not reclassified
as local secrets. No scan is proof of absence of arbitrary secrets.

Before replacing a previously customized installation, migrate the old local admission-state field to `provider_admission`, the helper to `/usr/libexec/tachyon-provider-qualify`, and the empty-pool sentinel to `__TACHYON_NO_PROVIDER_ADMISSION__`. Validate the migrated configuration privately before starting the new binary. No compatibility alias is embedded in the public build.
