//! Minimal JSON parser and serializer (RFC 8259), std only.
//!
//! Powers the Bitwarden JSON and 1Password 1PIF codecs. Strict where it
//! matters for credentials (full string-escape handling, surrogate pairs,
//! trailing-garbage rejection), pragmatic elsewhere (numbers are kept as
//! f64/i64, which covers every value the supported exports produce).

use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    // BTreeMap keeps serialization deterministic (sorted keys) — important
    // for reproducible output files and stable tests.
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            Value::Float(f) if f.fract() == 0.0 => Some(*f as i64),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }
    /// `obj["key"]` convenience: returns Null for missing keys / non-objects.
    pub fn get(&self, key: &str) -> &Value {
        static NULL: Value = Value::Null;
        self.as_object().and_then(|o| o.get(key)).unwrap_or(&NULL)
    }
    pub fn str_of(&self, key: &str) -> Option<String> {
        self.get(key).as_str().map(|s| s.to_string())
    }

    pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
        Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
    pub fn s(text: &str) -> Value {
        Value::Str(text.to_string())
    }
}

pub fn parse(input: &str) -> Result<Value, String> {
    let bytes = input.as_bytes();
    let mut p = Parser { b: bytes, i: 0 };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.i != bytes.len() {
        return Err(format!("trailing data at byte {}", p.i));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn expect(&mut self, c: u8) -> Result<(), String> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at byte {}", c as char, self.i))
        }
    }

    fn value(&mut self) -> Result<Value, String> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(format!("unexpected input at byte {}", self.i)),
        }
    }

    fn literal(&mut self, word: &str, v: Value) -> Result<Value, String> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(format!("invalid literal at byte {}", self.i))
        }
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let mut is_float = false;
        while let Some(c) = self.peek() {
            match c {
                b'0'..=b'9' => self.i += 1,
                b'.' | b'e' | b'E' | b'+' | b'-' => {
                    is_float = true;
                    self.i += 1;
                }
                _ => break,
            }
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).unwrap();
        if is_float {
            text.parse::<f64>()
                .map(Value::Float)
                .map_err(|_| format!("bad number '{text}'"))
        } else {
            text.parse::<i64>()
                .map(Value::Int)
                .map_err(|_| format!("bad number '{text}'"))
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("unterminated string".into()),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    match self.peek() {
                        Some(b'"') => out.push('"'),
                        Some(b'\\') => out.push('\\'),
                        Some(b'/') => out.push('/'),
                        Some(b'b') => out.push('\u{0008}'),
                        Some(b'f') => out.push('\u{000c}'),
                        Some(b'n') => out.push('\n'),
                        Some(b'r') => out.push('\r'),
                        Some(b't') => out.push('\t'),
                        Some(b'u') => {
                            self.i += 1;
                            let hi = self.hex4()?;
                            let ch = if (0xd800..0xdc00).contains(&hi) {
                                // Surrogate pair: \uD8xx must be followed by \uDCxx.
                                if self.b[self.i..].starts_with(b"\\u") {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    let code =
                                        0x10000 + ((hi - 0xd800) << 10) + (lo.wrapping_sub(0xdc00));
                                    char::from_u32(code).ok_or("bad surrogate pair")?
                                } else {
                                    return Err("lone high surrogate".into());
                                }
                            } else {
                                char::from_u32(hi).ok_or("bad \\u escape")?
                            };
                            out.push(ch);
                            continue; // hex4 already advanced past the digits
                        }
                        _ => return Err(format!("bad escape at byte {}", self.i)),
                    }
                    self.i += 1;
                }
                Some(c) if c < 0x20 => return Err(format!("raw control byte 0x{c:02x} in string")),
                Some(_) => {
                    // Copy one full UTF-8 scalar.
                    let rest = std::str::from_utf8(&self.b[self.i..])
                        .map_err(|_| "invalid UTF-8".to_string())?;
                    let ch = rest.chars().next().unwrap();
                    out.push(ch);
                    self.i += ch.len_utf8();
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.b.len() {
            return Err("truncated \\u escape".into());
        }
        let text = std::str::from_utf8(&self.b[self.i..self.i + 4])
            .map_err(|_| "bad \\u escape".to_string())?;
        let v = u32::from_str_radix(text, 16).map_err(|_| "bad \\u escape".to_string())?;
        self.i += 4;
        Ok(v)
    }

    fn array(&mut self) -> Result<Value, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.i)),
            }
        }
    }

    fn object(&mut self) -> Result<Value, String> {
        self.expect(b'{')?;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let val = self.value()?;
            map.insert(key, val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(map));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.i)),
            }
        }
    }
}

/// Serialize with two-space indentation and sorted object keys.
pub fn to_pretty(v: &Value) -> String {
    let mut out = String::new();
    write_value(v, 0, &mut out);
    out.push('\n');
    out
}

fn write_value(v: &Value, depth: usize, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(n) => {
            let _ = write!(out, "{n}");
        }
        Value::Float(f) => {
            let _ = write!(out, "{f}");
        }
        Value::Str(s) => write_string(s, out),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                indent(depth + 1, out);
                write_value(item, depth + 1, out);
            }
            out.push('\n');
            indent(depth, out);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, val)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                indent(depth + 1, out);
                write_string(k, out);
                out.push_str(": ");
                write_value(val, depth + 1, out);
            }
            out.push('\n');
            indent(depth, out);
            out.push('}');
        }
    }
}

fn indent(depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_document() {
        let v = parse(r#"{"a": [1, 2.5, true, null], "b": {"c": "d"}}"#).unwrap();
        assert_eq!(v.get("a").as_array().unwrap().len(), 4);
        assert_eq!(v.get("b").str_of("c").as_deref(), Some("d"));
    }

    #[test]
    fn parses_all_escape_sequences_and_surrogate_pairs() {
        let v = parse(r#""a\"b\\c\/d\n\t\r\b\fé""#).unwrap();
        assert_eq!(v.as_str().unwrap(), "a\"b\\c/d\n\t\r\u{8}\u{c}é");
        // Passwords legitimately contain emoji; 🔐 is U+1F510 (🔐).
        assert_eq!(parse(r#""🔐""#).unwrap().as_str().unwrap(), "\u{1F510}");
        assert!(
            parse(r#""\uD83D""#).is_err(),
            "lone high surrogate accepted"
        );
    }

    #[test]
    fn rejects_malformed_documents() {
        // A truncation or concatenation bug in an export must not be
        // silently half-parsed.
        assert!(parse(r#"{"a": 1} extra"#).is_err());
        assert!(parse("\"a\u{01}b\"").is_err(), "raw control byte accepted");
        assert!(parse(r#"{"a": }"#).is_err());
        assert!(parse(r#"["unterminated"#).is_err());
    }

    #[test]
    fn negative_and_float_numbers() {
        assert_eq!(parse("-42").unwrap().as_i64(), Some(-42));
        assert_eq!(parse("3.0").unwrap().as_i64(), Some(3));
        assert!(matches!(parse("1.5e2").unwrap(), Value::Float(f) if f == 150.0));
    }

    #[test]
    fn round_trip_preserves_special_characters() {
        let original = Value::obj(vec![
            ("pw", Value::s("a\"b\\c\nd\té\u{1F510}")),
            ("empty", Value::Array(vec![])),
        ]);
        let text = to_pretty(&original);
        assert_eq!(parse(&text).unwrap(), original);
    }

    #[test]
    fn serializer_output_is_deterministic_and_sorted() {
        let v = Value::obj(vec![("zebra", Value::Int(1)), ("apple", Value::Int(2))]);
        let text = to_pretty(&v);
        assert!(text.find("apple").unwrap() < text.find("zebra").unwrap());
        assert_eq!(text, to_pretty(&parse(&text).unwrap()));
    }

    #[test]
    fn get_on_missing_key_returns_null_not_panic() {
        // Codec code chains .get() freely; missing keys must be benign.
        let v = parse("{}").unwrap();
        assert_eq!(v.get("nope").get("deeper"), &Value::Null);
    }
}
