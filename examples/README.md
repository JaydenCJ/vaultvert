# Examples

Small, entirely fictional exports in each supported format — safe to commit,
safe to experiment on. Every secret in here is fake by construction.

| File | Format | What it exercises |
|---|---|---|
| `bitwarden-vault.json` | bitwarden-json | folders, favorite, TOTP, custom fields (text + hidden), secure note, card item |
| `keepass-export.xml` | keepass-xml | nested groups, protected strings, `otp` convention, tags, Recycle Bin skipping |
| `onepassword-export.1pif` | 1pif | folder records, web-form designations, sections, TOTP, tags, a trashed item |
| `bitwarden-export.csv` | bitwarden-csv | quoted multi-line notes, custom-field lines, note rows |

Try them:

```bash
# What is in this export?
vaultvert inspect examples/bitwarden-vault.json

# Bitwarden -> KeePass, with the integrity report on stderr
vaultvert convert examples/bitwarden-vault.json -o /tmp/vault.xml

# Merge three vaults from three different managers into one
vaultvert merge examples/bitwarden-vault.json \
                examples/keepass-export.xml \
                examples/onepassword-export.1pif \
                -o /tmp/merged.json
```

The Bitwarden, KeePass and 1Password files intentionally share one entry
("Corporate Mail", same username and host) so the merge example demonstrates
duplicate detection and password-conflict preservation.
