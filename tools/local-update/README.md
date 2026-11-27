# Autonomous update verification contract (candidate)

`verify-manifest.sh BUNDLE_DIR TRUSTED_PUBLIC_KEY CURRENT_SEQUENCE` is a read-only
OpenWrt verifier. It does not download, run, install, or restart anything.
Call it only on a private staging directory owned by the updater; the caller
must prevent concurrent modification throughout verification and installation.

The bundle uses fixed filenames: `manifest.txt`, `manifest.sig`, `tachyon`.
The UTF-8 manifest has exactly eight ordered ASCII lines:

```text
schema=1
channel=stable
arch=aarch64-musl
sequence=2
upstream_commit=<40 lowercase hex digits>
adapter_commit=<40 lowercase hex digits>
sha256=<64 lowercase hex digits of tachyon>
bytes=<positive decimal byte count>
```

The signature is produced by OpenWrt usign over the exact manifest bytes.
The public verification key is provisioned out of band and must not be supplied
by the downloaded bundle. Sequence is a monotonic release counter, independent
of upstream version strings. The verifier rejects equal or lower counters,
noncanonical manifests, wrong signatures, wrong length/hash and symlink files.
Payloads are bounded to 16 MiB. The architecture field is signed metadata,
not proof of the actual ELF architecture.

## Promotion is a separate gate

An Actions artifact is not a trusted stable release. The candidate builder
has no signing key and no publication permissions. A separate protected
promotion process must independently verify artifact provenance, exact source,
binary hash, actual ELF architecture, required helper/Core compatibility and
router qualification. Only that process may assign a new sequence and sign a
stable manifest. Never publish the signing secret or router configuration.

The router installer is not implemented here. It must keep the previous
binary/configuration, hold a single update lock, stage privately on disk,
verify again before atomic replacement, validate the compiled configuration
with the intended Core, check service/network health, and restore on failure.
Persist the accepted sequence only after successful activation, with crash
recovery and a separately authorized local rollback path. It must not trust a
counter supplied by the bundle as the installed counter.

Test evidence: OpenWrt synthetic fixture, 2026-11-27, one valid case and eleven
negative cases passed. Disposable keys and non-executable payloads were used.
No production key, stable release, actual binary installation, power-loss
recovery, or full compatibility acceptance is claimed.
