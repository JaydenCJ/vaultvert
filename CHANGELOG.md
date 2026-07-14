# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Format codecs: Bitwarden unencrypted JSON (read/write, including card and identity items), Bitwarden CSV (read), 1Password 1PIF (read/write, including folders, sections, designations, tags and trashed-item skipping), KeePass 2.x XML (read/write, including nested groups, protected strings, the `otp` convention, tags, KDBX 4 Base64 timestamps and Recycle Bin skipping).
- Canonical vault model with a reserved `vv:` spill mechanism: any slot a target format cannot hold natively is preserved as a custom field and lifted back by the reverse reader, making conversions lossless in both directions.
- Integrity report after every conversion: per-field mapping table (native slot vs. preserved custom field), source/target entry counts, order-independent SHA-256 vault digests, and a LOSSLESS verdict computed by re-parsing the actual output bytes — checked, not asserted. Exit code 3 on verification failure.
- `vaultvert merge`: duplicate detection on (kind, title, username, URL host), union of URLs/tags/custom fields, newest-password-wins with the superseded password preserved in a hidden custom field, timestamps widened to earliest-created/latest-modified.
- `vaultvert inspect`: format sniffing, entry/kind/folder counts, per-slot coverage and the vault digest, with `--json` output.
- CLI: `convert`, `merge`, `inspect`, `formats`; `--from`/`--to` overrides, content-based format sniffing, stdio piping via `-`, `--report` files (text or JSON), `--quiet`.
- Deliberate refusal to write CSV, with an explanation — CSV cannot carry item types, timestamps, hidden-field flags or TOTP losslessly.
- Zero-dependency infrastructure implemented in-tree against std: JSON parser/serializer, KeePass-dialect XML parser/writer with a DOCTYPE (XXE) block, RFC 4180 CSV reader, Base64, SHA-256 (NIST-vector verified), RFC 3339 time conversion.
- Fictional example exports for all four formats in `examples/`.
- Test suite: 82 unit tests, 9 CLI integration tests, and `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/vaultvert/releases/tag/v0.1.0
