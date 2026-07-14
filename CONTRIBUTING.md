# Contributing to vaultvert

Thanks for your interest in improving vaultvert. Issues, discussions and pull requests are all welcome.

## Getting started

Prerequisites: Rust 1.75 or newer (stable toolchain).

```bash
git clone https://github.com/JaydenCJ/vaultvert.git
cd vaultvert
cargo build
cargo test
bash scripts/smoke.sh
```

`scripts/smoke.sh` drives the compiled CLI end to end against the committed example exports — a conversion tour across every writable format with digest verification at each hop, a three-manager merge, report files and the failure modes. It finishes in under a minute and must print `SMOKE OK`.

## Before you open a pull request

1. `cargo fmt` — formatting is enforced.
2. `cargo clippy --all-targets -- -D warnings` — clippy must be clean.
3. `cargo test` — unit tests and the CLI integration tests must pass.
4. `bash scripts/smoke.sh` — the smoke test must print `SMOKE OK`.
5. Add tests for behavior changes. Codec, merge and infrastructure logic lives in pure modules (`bitwarden`, `keepass`, `onepassword`, `merge`, `json`, `xml`, `timefmt`) that are easy to unit-test; please keep it that way. A new format codec is only complete when its write→read round-trip test passes.

## Ground rules

- Zero dependencies is the whole point. vaultvert handles the most sensitive file a person owns; every byte of code that touches it must be auditable in this repository. PRs adding a crate dependency will be declined — including for JSON/XML/CSV/crypto, which are implemented in-tree on purpose.
- No network code, no telemetry, ever. The binary must be safe to run on an air-gapped machine.
- Never weaken the LOSSLESS verdict: the digest comparison in `report.rs` must stay a re-parse of the actual output bytes, not a claim derived from the writer.
- Code comments and doc comments are written in English.
- Never commit a real vault export — the `examples/` files are fictional by construction and new fixtures must be too (use `example.test` hosts and obviously fake secrets).

## Reporting bugs

Please include the `vaultvert --version` output, the `inspect --json` output for the input file (it contains counts and a digest, not your secrets), the integrity report, and — if you can construct one — a minimal fictional export that reproduces the issue. Do not attach a real vault export to a public issue.

## Security

If you find a security issue (a parsing flaw, a case where secret material could be dropped or leaked), please do not open a public issue. Use GitHub's private vulnerability reporting on this repository instead.
