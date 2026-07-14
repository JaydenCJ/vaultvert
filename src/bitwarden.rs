//! Bitwarden codec: unencrypted JSON export (read + write) and the
//! `login_uri`-style CSV export (read only — CSV cannot carry item types,
//! timestamps or hidden-field flags, which is exactly why vaultvert exists).
//!
//! Field references follow the export produced by Bitwarden 2024+ clients:
//! item `type` 1=login, 2=secure note, 3=card, 4=identity; custom field
//! `type` 0=text, 1=hidden, 2=boolean, 3=linked.

use crate::json::{self, Value};
use crate::model::{deterministic_uuid, Entry, EntryKind, Field, Vault};
use crate::report::{Disposition, Report};
use crate::timefmt;

const CARD_KEYS: [&str; 6] = [
    "cardholderName",
    "brand",
    "number",
    "expMonth",
    "expYear",
    "code",
];
const IDENTITY_KEYS: [&str; 18] = [
    "title",
    "firstName",
    "middleName",
    "lastName",
    "address1",
    "address2",
    "address3",
    "city",
    "state",
    "postalCode",
    "country",
    "company",
    "email",
    "phone",
    "ssn",
    "username",
    "passportNumber",
    "licenseNumber",
];

// ---------------------------------------------------------------- JSON read

pub fn read_json(text: &str) -> Result<Vault, String> {
    let doc = json::parse(text).map_err(|e| format!("bitwarden json: {e}"))?;
    if doc.get("encrypted").as_bool() == Some(true) {
        return Err(
            "this is a password-protected Bitwarden export; re-export as plain \
             .json (Tools > Export vault > File format: .json)"
                .into(),
        );
    }
    let mut folders = std::collections::BTreeMap::new();
    for f in doc.get("folders").as_array().unwrap_or(&[]) {
        if let (Some(id), Some(name)) = (f.str_of("id"), f.str_of("name")) {
            folders.insert(id, name);
        }
    }

    let items = doc
        .get("items")
        .as_array()
        .ok_or("bitwarden json: missing \"items\" array")?;
    let mut vault = Vault::default();
    for item in items {
        let kind = match item.get("type").as_i64() {
            Some(2) => EntryKind::Note,
            Some(3) => EntryKind::Card,
            Some(4) => EntryKind::Identity,
            _ => EntryKind::Login,
        };
        let mut e = Entry::new(kind, &item.str_of("name").unwrap_or_default());
        e.id = item.str_of("id").unwrap_or_default();
        e.notes = item.str_of("notes");
        e.favorite = item.get("favorite").as_bool() == Some(true);
        e.folder = item
            .str_of("folderId")
            .and_then(|id| folders.get(&id).cloned());
        e.created = item
            .str_of("creationDate")
            .and_then(|t| timefmt::parse_rfc3339(&t).ok());
        e.modified = item
            .str_of("revisionDate")
            .and_then(|t| timefmt::parse_rfc3339(&t).ok());

        let login = item.get("login");
        e.username = login.str_of("username");
        e.password = login.str_of("password");
        e.totp = login.str_of("totp");
        for uri in login.get("uris").as_array().unwrap_or(&[]) {
            if let Some(u) = uri.str_of("uri") {
                e.urls.push(u);
            }
        }

        // Structured card/identity sub-objects become prefixed fields so any
        // target format can carry them and this writer can rebuild them.
        for (obj_key, prefix, keys) in [
            ("card", "card:", &CARD_KEYS[..]),
            ("identity", "identity:", &IDENTITY_KEYS[..]),
        ] {
            let obj = item.get(obj_key);
            for key in keys {
                if let Some(v) = obj.str_of(key) {
                    let hidden = matches!(*key, "number" | "code" | "ssn" | "passportNumber");
                    e.fields
                        .push(Field::new(&format!("{prefix}{key}"), &v, hidden));
                }
            }
        }

        for f in item.get("fields").as_array().unwrap_or(&[]) {
            let value = match f.get("value") {
                Value::Bool(b) => b.to_string(),
                v => v.as_str().unwrap_or("").to_string(),
            };
            e.fields.push(Field::new(
                &f.str_of("name").unwrap_or_default(),
                &value,
                f.get("type").as_i64() == Some(1),
            ));
        }
        e.lift_spilled();
        e.ensure_id();
        vault.entries.push(e);
    }
    Ok(vault)
}

// --------------------------------------------------------------- JSON write

pub fn write_json(vault: &Vault, rep: &mut Report) -> String {
    let mut folder_ids = std::collections::BTreeMap::new();
    let mut items = Vec::new();

    for entry in &vault.entries {
        let mut e = entry.clone();
        e.ensure_id();
        let type_num = match e.kind() {
            EntryKind::Login => 1,
            EntryKind::Note => 2,
            EntryKind::Card => 3,
            EntryKind::Identity => 4,
        };
        rep.note("title", "name", Disposition::Native);
        rep.note("kind", "type", Disposition::Native);

        let mut obj = vec![
            ("id", Value::s(&e.id)),
            ("type", Value::Int(type_num)),
            ("name", Value::s(&e.title)),
            ("favorite", Value::Bool(e.favorite)),
            ("reprompt", Value::Int(0)),
            ("organizationId", Value::Null),
            ("collectionIds", Value::Null),
        ];
        if e.favorite {
            rep.note("favorite", "favorite", Disposition::Native);
        }
        match &e.notes {
            Some(n) => {
                rep.note("notes", "notes", Disposition::Native);
                obj.push(("notes", Value::s(n)));
            }
            None => obj.push(("notes", Value::Null)),
        }
        if let Some(folder) = &e.folder {
            let id = folder_ids
                .entry(folder.clone())
                .or_insert_with(|| deterministic_uuid(&format!("folder\x1f{folder}")))
                .clone();
            obj.push(("folderId", Value::s(&id)));
            rep.note("folder", "folders[] + folderId", Disposition::Native);
        } else {
            obj.push(("folderId", Value::Null));
        }
        if let Some(t) = e.created {
            obj.push(("creationDate", Value::s(&timefmt::to_rfc3339(t))));
            rep.note("created", "creationDate", Disposition::Native);
        }
        if let Some(t) = e.modified {
            obj.push(("revisionDate", Value::s(&timefmt::to_rfc3339(t))));
            rep.note("modified", "revisionDate", Disposition::Native);
        }

        // Slots with no native home on this item type are spilled to custom
        // fields; `read_json` lifts them back, keeping round-trips exact.
        match e.kind() {
            EntryKind::Login => {
                let mut login = Vec::new();
                if let Some(u) = &e.username {
                    login.push(("username", Value::s(u)));
                    rep.note("username", "login.username", Disposition::Native);
                }
                if let Some(p) = &e.password {
                    login.push(("password", Value::s(p)));
                    rep.note("password", "login.password", Disposition::Native);
                }
                if let Some(t) = &e.totp {
                    login.push(("totp", Value::s(t)));
                    rep.note("totp", "login.totp", Disposition::Native);
                }
                if !e.urls.is_empty() {
                    let uris: Vec<Value> = e
                        .urls
                        .iter()
                        .map(|u| Value::obj(vec![("match", Value::Null), ("uri", Value::s(u))]))
                        .collect();
                    login.push(("uris", Value::Array(uris)));
                    rep.note("url", "login.uris[]", Disposition::Native);
                }
                obj.push(("login", Value::obj(login)));
            }
            other => {
                spill_non_login(&mut e, rep);
                if other == EntryKind::Note {
                    obj.push(("secureNote", Value::obj(vec![("type", Value::Int(0))])));
                } else {
                    let (obj_key, prefix, keys) = if other == EntryKind::Card {
                        ("card", "card:", &CARD_KEYS[..])
                    } else {
                        ("identity", "identity:", &IDENTITY_KEYS[..])
                    };
                    let mut sub = Vec::new();
                    e.fields.retain(|f| {
                        if let Some(k) = f.name.strip_prefix(prefix) {
                            if keys.contains(&k) {
                                sub.push((k.to_string(), Value::s(&f.value)));
                                return false;
                            }
                        }
                        true
                    });
                    rep.note("fields", obj_key, Disposition::Native);
                    obj.push((obj_key, Value::Object(sub.into_iter().collect())));
                }
            }
        }

        if !e.tags.is_empty() {
            // Bitwarden has no tags concept; preserve them as a custom field.
            e.spill("tags", &entry.tags.join(","), false);
            rep.note("tags", "vv:tags custom field", Disposition::Custom);
        }
        if !e.fields.is_empty() {
            let fields: Vec<Value> = e
                .fields
                .iter()
                .map(|f| {
                    Value::obj(vec![
                        ("name", Value::s(&f.name)),
                        ("value", Value::s(&f.value)),
                        ("type", Value::Int(if f.hidden { 1 } else { 0 })),
                        ("linkedId", Value::Null),
                    ])
                })
                .collect();
            rep.note("fields", "fields[]", Disposition::Native);
            obj.push(("fields", Value::Array(fields)));
        }
        items.push(Value::obj(obj));
    }

    let folders: Vec<Value> = folder_ids
        .iter()
        .map(|(name, id)| Value::obj(vec![("id", Value::s(id)), ("name", Value::s(name))]))
        .collect();
    let doc = Value::obj(vec![
        ("encrypted", Value::Bool(false)),
        ("folders", Value::Array(folders)),
        ("items", Value::Array(items)),
    ]);
    json::to_pretty(&doc)
}

/// Move canonical slots a non-login Bitwarden item cannot hold into reserved
/// custom fields, recording each spill in the report.
fn spill_non_login(e: &mut Entry, rep: &mut Report) {
    if let Some(u) = e.username.take() {
        e.spill("username", &u, false);
        rep.note("username", "vv:username custom field", Disposition::Custom);
    }
    if let Some(p) = e.password.take() {
        e.spill("password", &p, true);
        rep.note("password", "vv:password custom field", Disposition::Custom);
    }
    if let Some(t) = e.totp.take() {
        e.spill("totp", &t, true);
        rep.note("totp", "vv:totp custom field", Disposition::Custom);
    }
    for (i, u) in e.urls.drain(..).collect::<Vec<_>>().iter().enumerate() {
        let slot = if i == 0 {
            "url".to_string()
        } else {
            format!("url.{}", i + 1)
        };
        e.fields.push(Field::new(&format!("vv:{slot}"), u, false));
        rep.note("url", "vv:url custom field", Disposition::Custom);
    }
}

// ----------------------------------------------------------------- CSV read

pub fn read_csv(text: &str) -> Result<Vault, String> {
    let rows = crate::csv::parse(text).map_err(|e| format!("bitwarden csv: {e}"))?;
    let header = rows.first().ok_or("bitwarden csv: empty file")?;
    let col = |name: &str| header.iter().position(|h| h == name);
    let name_col = col("name").ok_or("bitwarden csv: no \"name\" column in header")?;
    let get = |row: &[String], idx: Option<usize>| -> Option<String> {
        idx.and_then(|i| row.get(i))
            .filter(|v| !v.is_empty())
            .cloned()
    };
    let (c_folder, c_fav, c_type, c_notes, c_fields) = (
        col("folder"),
        col("favorite"),
        col("type"),
        col("notes"),
        col("fields"),
    );
    let (c_uri, c_user, c_pass, c_totp) = (
        col("login_uri"),
        col("login_username"),
        col("login_password"),
        col("login_totp"),
    );

    let mut vault = Vault::default();
    for (n, row) in rows.iter().enumerate().skip(1) {
        if row.iter().all(|f| f.is_empty()) {
            continue;
        }
        if row.len() != header.len() {
            return Err(format!(
                "bitwarden csv: row {} has {} columns, header has {}",
                n + 1,
                row.len(),
                header.len()
            ));
        }
        let kind = match get(row, c_type).as_deref() {
            Some("note") => EntryKind::Note,
            _ => EntryKind::Login,
        };
        let mut e = Entry::new(kind, get(row, Some(name_col)).unwrap_or_default().as_str());
        e.folder = get(row, c_folder);
        e.favorite = matches!(get(row, c_fav).as_deref(), Some("1") | Some("true"));
        e.notes = get(row, c_notes);
        e.username = get(row, c_user);
        e.password = get(row, c_pass);
        e.totp = get(row, c_totp);
        if let Some(uris) = get(row, c_uri) {
            e.urls = uris.split(',').map(|u| u.trim().to_string()).collect();
        }
        if let Some(fields) = get(row, c_fields) {
            // Bitwarden encodes custom fields one per line as "name: value".
            for line in fields.lines() {
                let (k, v) = line.split_once(": ").unwrap_or((line, ""));
                e.fields.push(Field::new(k, v, false));
            }
        }
        e.lift_spilled();
        e.ensure_id();
        vault.entries.push(e);
    }
    Ok(vault)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> &'static str {
        r#"{
          "encrypted": false,
          "folders": [{"id": "f-1", "name": "Work"}],
          "items": [
            {
              "id": "11111111-2222-3333-4444-555555555555",
              "type": 1, "name": "Mail", "favorite": true, "folderId": "f-1",
              "notes": "line1\nline2",
              "login": {
                "username": "kim@example.test", "password": "pw&<>\"'",
                "totp": "otpauth://totp/x?secret=JBSWY3DP",
                "uris": [{"match": null, "uri": "https://mail.example.test"}]
              },
              "fields": [{"name": "recovery", "value": "seed words", "type": 1, "linkedId": null}],
              "creationDate": "2026-05-01T08:00:00.000Z",
              "revisionDate": "2026-06-02T09:30:00.000Z"
            },
            {"id": "aaaa", "type": 2, "name": "Wifi", "notes": "psk here", "secureNote": {"type": 0}},
            {"id": "bbbb", "type": 3, "name": "Visa",
             "card": {"cardholderName": "K KIM", "brand": "Visa", "number": "4111111111111111",
                      "expMonth": "12", "expYear": "2030", "code": "123"}}
          ]
        }"#
    }

    #[test]
    fn reads_login_with_all_slots() {
        let v = read_json(sample_json()).unwrap();
        let e = &v.entries[0];
        assert_eq!(e.title, "Mail");
        assert_eq!(e.username.as_deref(), Some("kim@example.test"));
        assert_eq!(e.password.as_deref(), Some("pw&<>\"'"));
        assert_eq!(e.totp.as_deref(), Some("otpauth://totp/x?secret=JBSWY3DP"));
        assert_eq!(e.urls, vec!["https://mail.example.test"]);
        assert_eq!(e.folder.as_deref(), Some("Work"));
        assert!(e.favorite);
        assert_eq!(e.fields[0].name, "recovery");
        assert!(e.fields[0].hidden);
        assert_eq!(
            e.created,
            Some(crate::timefmt::parse_rfc3339("2026-05-01T08:00:00Z").unwrap())
        );
    }

    #[test]
    fn reads_card_into_prefixed_fields() {
        let v = read_json(sample_json()).unwrap();
        let card = &v.entries[2];
        assert_eq!(card.kind(), EntryKind::Card);
        let number = card
            .fields
            .iter()
            .find(|f| f.name == "card:number")
            .unwrap();
        assert_eq!(number.value, "4111111111111111");
        assert!(number.hidden);
    }

    #[test]
    fn rejects_encrypted_export_with_actionable_message() {
        let err = read_json(r#"{"encrypted": true, "items": []}"#).unwrap_err();
        assert!(err.contains("re-export"), "unhelpful message: {err}");
    }

    #[test]
    fn json_round_trip_is_digest_identical_and_deterministic() {
        let v = read_json(sample_json()).unwrap();
        let mut rep = Report::default();
        let out = write_json(&v, &mut rep);
        let back = read_json(&out).unwrap();
        assert_eq!(back.digest(), v.digest());
        // Structured card fields must be rebuilt, not dumped as customs.
        assert!(out.contains("\"cardholderName\": \"K KIM\""));
        assert_eq!(out, write_json(&v, &mut Report::default()));
    }

    #[test]
    fn tags_survive_via_spill_field() {
        let mut e = Entry::new(EntryKind::Login, "tagged");
        e.tags = vec!["personal".into(), "email".into()];
        let v = Vault { entries: vec![e] };
        let out = write_json(&v, &mut Report::default());
        let back = read_json(&out).unwrap();
        assert_eq!(back.entries[0].tags, vec!["personal", "email"]);
    }

    #[test]
    fn note_with_password_round_trips_through_spill() {
        // A KeePass entry filed as a note can still carry a password;
        // Bitwarden type-2 items have no login object, so it must spill.
        let mut e = Entry::new(EntryKind::Note, "server");
        e.password = Some("root-pw".into());
        e.urls = vec![
            "ssh://10.0.0.1".into(),
            "https://console.example.test".into(),
        ];
        let v = Vault { entries: vec![e] };
        let out = write_json(&v, &mut Report::default());
        let back = read_json(&out).unwrap();
        assert_eq!(back.entries[0].password.as_deref(), Some("root-pw"));
        assert_eq!(back.entries[0].urls.len(), 2);
        assert_eq!(back.digest(), v.digest());
    }

    #[test]
    fn reads_csv_export() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   Work,1,login,Mail,\"note line1\nline2\",\"pin: 1234\",0,https://mail.example.test,kim,pw123,\n\
                   ,,note,Wifi,psk here,,,,,,\n";
        let v = read_csv(csv).unwrap();
        assert_eq!(v.entries.len(), 2);
        assert_eq!(v.entries[0].folder.as_deref(), Some("Work"));
        assert!(v.entries[0].favorite);
        assert_eq!(v.entries[0].fields[0].value, "1234");
        assert_eq!(v.entries[1].kind(), EntryKind::Note);
    }

    #[test]
    fn csv_with_misaligned_row_is_rejected() {
        let csv = "folder,favorite,type,name\nWork,1,login\n";
        assert!(read_csv(csv).unwrap_err().contains("columns"));
    }
}
