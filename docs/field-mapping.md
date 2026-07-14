# Field mapping

How vaultvert maps each vendor format onto its canonical model, and how the
lossless guarantee is engineered. This is the reference for the `field
mapping` section of the integrity report.

## The canonical model

Every reader produces, and every writer consumes, the same `Entry`:

| Canonical slot | Type | Notes |
|---|---|---|
| `kind` | login / note / card / identity | Bitwarden types 1–4; 1PIF typeNames; KeePass entries are logins unless tagged |
| `title` | string | |
| `username`, `password` | optional string | |
| `urls` | list | first URL is the primary one |
| `notes` | optional string | multi-line preserved |
| `totp` | optional string | usually an `otpauth://` URI |
| `folder` | optional `/`-separated path | KeePass group nesting ⇄ flat folder names |
| `tags` | list | |
| `favorite` | bool | |
| `fields` | list of (name, value, hidden) | vendor custom fields |
| `created`, `modified` | optional Unix seconds | RFC 3339 ⇄ epoch per format |

## Native slots per format

| Canonical | bitwarden-json | 1pif | keepass-xml |
|---|---|---|---|
| title | `name` | `title` | `String[Title]` |
| username | `login.username` | field `designation=username` | `String[UserName]` |
| password | `login.password` | field `designation=password` | `String[Password]` |
| urls | `login.uris[]` | `location` + `secureContents.URLs[]` | `String[URL]` (first) |
| notes | `notes` | `secureContents.notesPlain` | `String[Notes]` |
| totp | `login.totp` | section field `TOTP_*` | `String[otp]` |
| folder | `folders[]` + `folderId` | folder records + `folderUuid` | group nesting |
| tags | — | `openContents.tags` | `Tags` |
| favorite | `favorite` | `openContents.faveIndex` | — |
| fields | `fields[]` / `card` / `identity` | section fields | extra `String` pairs |
| created/modified | `creationDate` / `revisionDate` | `createdAt` / `updatedAt` | `Times/*` |

## The spill mechanism (`vv:` fields)

When a slot has no native home in the target (a dash above, or a non-login
Bitwarden item that cannot hold `login.*`), the writer stores it as a custom
field with a reserved name — `vv:username`, `vv:password`, `vv:totp`,
`vv:url` / `vv:url.N`, `vv:favorite`, `vv:tags`, `vv:kind` — and reports it
as `custom` in the field-mapping table. Every reader runs a lift pass after
vendor parsing that moves `vv:` fields back into their canonical slots (never
overwriting a natively-present value). The result: any chain of conversions
through any of the writable formats preserves every slot.

Bitwarden card/identity sub-objects are flattened to prefixed custom fields
(`card:number`, `identity:email`, …) on read and rebuilt from those prefixes
on write, so structured items survive a detour through KeePass or 1PIF.

## The digest

`Entry::core_digest()` is SHA-256 over kind, title, username, password,
sorted URLs, notes and TOTP, joined with `\x1f` unit separators so values can
never alias across slot boundaries. The vault digest hashes the sorted list
of entry digests — order-independent, duplicate-sensitive. After writing,
the CLI re-parses its own output and compares digests; only a match earns
`verdict: LOSSLESS`. A mismatch exits with code 3 and an explicit warning to
keep the original file.

Known non-goals of the digest: it deliberately excludes ids, folder names,
timestamps and custom fields (all of which legitimately change representation
across formats — note that spilled `vv:` slots are lifted back *before*
digesting, so they stay covered). Counts and the mapping table cover the rest.
