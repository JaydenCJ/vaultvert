#!/usr/bin/env bash
# Smoke test: builds vaultvert and drives the real CLI end to end against the
# committed example exports — inspect, a full conversion tour across all three
# writable formats with digest verification at every hop, a three-manager
# merge with dedupe, report files, stdio piping and the CSV refusal.
# Self-contained: temp dirs only, no network.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }

echo "[smoke] building..."
cargo build --quiet
BIN=target/debug/vaultvert

WORK=$(mktemp -d "${TMPDIR:-/tmp}/vaultvert-smoke.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# --- 1. version/help/formats sanity ------------------------------------------
"$BIN" --version | grep -q '^vaultvert 0\.1\.0$' || fail "--version mismatch"
"$BIN" --help | grep -q 'COMMANDS:' || fail "--help missing sections"
"$BIN" formats | grep -q 'bitwarden-csv    r ' || fail "formats table wrong"

# --- 2. inspect: detection, counts, recycle-bin warning ----------------------
echo "[smoke] vaultvert inspect"
"$BIN" inspect examples/bitwarden-vault.json | tee "$WORK/inspect.out"
grep -q 'format  : bitwarden-json' "$WORK/inspect.out" || fail "format not detected"
grep -q 'entries : 4' "$WORK/inspect.out" || fail "entry count wrong"
"$BIN" inspect examples/keepass-export.xml | grep -q 'Recycle Bin' \
  || fail "recycle-bin warning missing"

digest_of() { "$BIN" inspect "$1" --json | grep '"digest"' | cut -d'"' -f4; }
START_DIGEST=$(digest_of examples/bitwarden-vault.json)

# --- 3. conversion tour: json -> xml -> 1pif -> json, verified every hop -----
echo "[smoke] conversion tour across all writable formats"
"$BIN" convert examples/bitwarden-vault.json -o "$WORK/a.xml" 2> "$WORK/rep1.txt" \
  || fail "convert to keepass-xml failed"
grep -q 'verdict: LOSSLESS' "$WORK/rep1.txt" || fail "hop 1 not LOSSLESS"
grep -q '\[match\]' "$WORK/rep1.txt" || fail "hop 1 digest line missing"
"$BIN" convert "$WORK/a.xml" -o "$WORK/b.1pif" --quiet || fail "convert to 1pif failed"
"$BIN" convert "$WORK/b.1pif" -o "$WORK/c.json" --quiet || fail "convert back to json failed"
END_DIGEST=$(digest_of "$WORK/c.json")
[ "$START_DIGEST" = "$END_DIGEST" ] || fail "digest changed over the tour"
echo "[smoke] tour digest held: $START_DIGEST"

# --- 4. merge three managers, dedupe, keep every secret ----------------------
echo "[smoke] vaultvert merge (bitwarden + keepass + 1password)"
"$BIN" merge examples/bitwarden-vault.json examples/keepass-export.xml \
  examples/onepassword-export.1pif -o "$WORK/merged.json" 2> "$WORK/merge.log" \
  || fail "merge failed"
grep -q '3 inputs, 8 entries in, 2 duplicates merged' "$WORK/merge.log" \
  || fail "merge stats wrong: $(cat "$WORK/merge.log")"
grep -q 'verdict: LOSSLESS' "$WORK/merge.log" || fail "merge output not verified"
grep -c '"Corporate Mail"' "$WORK/merged.json" | grep -qx 1 \
  || fail "duplicate entry not collapsed"

# --- 5. report file (json), including source warnings -------------------------
"$BIN" convert examples/onepassword-export.1pif -o "$WORK/op.json" \
  --report "$WORK/report.json" --json --quiet || fail "report run failed"
grep -q '"verdict": "LOSSLESS"' "$WORK/report.json" || fail "json report verdict missing"
grep -q 'skipped 1 trashed' "$WORK/report.json" || fail "trashed warning missing"

# --- 6. stdio piping ----------------------------------------------------------
"$BIN" convert - -o - --from bitwarden-json --to keepass-xml --quiet \
  < examples/bitwarden-vault.json > "$WORK/piped.xml" || fail "stdio pipe failed"
grep -q '<KeePassFile>' "$WORK/piped.xml" || fail "piped output is not KeePass XML"

# --- 7. failure modes: exit codes and messages --------------------------------
if "$BIN" convert examples/bitwarden-vault.json -o "$WORK/out.csv" --to csv 2> "$WORK/csv.err"; then
  fail "CSV output was not refused"
fi
grep -q 'refusing to write CSV' "$WORK/csv.err" || fail "CSV refusal message missing"
printf '{"encrypted": true, "items": []}' > "$WORK/enc.json"
if "$BIN" inspect "$WORK/enc.json" 2> "$WORK/enc.err"; then
  fail "encrypted export accepted"
fi
grep -q 're-export' "$WORK/enc.err" || fail "encrypted-export message unhelpful"

echo "SMOKE OK"
