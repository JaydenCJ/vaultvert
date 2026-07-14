//! Minimal XML tree parser and writer for the KeePass 2.x export dialect.
//!
//! This is deliberately not a general XML implementation: it supports exactly
//! what KeePass XML files contain — elements, attributes, character data, the
//! five predefined entities plus numeric character references, comments, and
//! an optional `<?xml ...?>` declaration. DTDs and processing instructions
//! are rejected, which doubles as a hard block on XXE-style tricks.

use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub struct Element {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Element>,
    pub text: String,
}

impl Element {
    pub fn new(name: &str) -> Element {
        Element {
            name: name.to_string(),
            attrs: Vec::new(),
            children: Vec::new(),
            text: String::new(),
        }
    }

    pub fn with_text(name: &str, text: &str) -> Element {
        let mut e = Element::new(name);
        e.text = text.to_string();
        e
    }

    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter(move |c| c.name == name)
    }

    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.as_str())
    }
}

pub fn parse(input: &str) -> Result<Element, String> {
    let mut p = Parser {
        b: input.as_bytes(),
        i: 0,
    };
    p.skip_ws();
    p.skip_prolog()?;
    p.skip_ws();
    let root = p.element()?;
    p.skip_ws();
    if p.i != p.b.len() {
        return Err(format!("trailing data after root element at byte {}", p.i));
    }
    Ok(root)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn starts(&self, s: &str) -> bool {
        self.b[self.i..].starts_with(s.as_bytes())
    }

    fn skip_prolog(&mut self) -> Result<(), String> {
        if self.starts("<?xml") {
            match self.b[self.i..].windows(2).position(|w| w == b"?>") {
                Some(off) => self.i += off + 2,
                None => return Err("unterminated XML declaration".into()),
            }
        }
        self.skip_ws();
        while self.starts("<!--") {
            self.skip_comment()?;
            self.skip_ws();
        }
        if self.starts("<!DOCTYPE") {
            return Err("DOCTYPE declarations are not accepted".into());
        }
        Ok(())
    }

    fn skip_comment(&mut self) -> Result<(), String> {
        match self.b[self.i..].windows(3).position(|w| w == b"-->") {
            Some(off) => {
                self.i += off + 3;
                Ok(())
            }
            None => Err("unterminated comment".into()),
        }
    }

    fn name(&mut self) -> Result<String, String> {
        let start = self.i;
        while self.i < self.b.len()
            && matches!(self.b[self.i], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' | b':' | b'.')
        {
            self.i += 1;
        }
        if self.i == start {
            return Err(format!("expected a name at byte {}", self.i));
        }
        Ok(String::from_utf8_lossy(&self.b[start..self.i]).into_owned())
    }

    fn element(&mut self) -> Result<Element, String> {
        if !self.starts("<") {
            return Err(format!("expected '<' at byte {}", self.i));
        }
        self.i += 1;
        let mut el = Element::new(&self.name()?);

        // Attributes.
        loop {
            self.skip_ws();
            match self.b.get(self.i) {
                Some(b'/') if self.starts("/>") => {
                    self.i += 2;
                    return Ok(el);
                }
                Some(b'>') => {
                    self.i += 1;
                    break;
                }
                Some(_) => {
                    let key = self.name()?;
                    self.skip_ws();
                    if self.b.get(self.i) != Some(&b'=') {
                        return Err(format!("expected '=' after attribute at byte {}", self.i));
                    }
                    self.i += 1;
                    self.skip_ws();
                    let quote = *self.b.get(self.i).ok_or("truncated attribute")?;
                    if quote != b'"' && quote != b'\'' {
                        return Err("attribute value must be quoted".into());
                    }
                    self.i += 1;
                    let start = self.i;
                    while self.i < self.b.len() && self.b[self.i] != quote {
                        self.i += 1;
                    }
                    if self.i == self.b.len() {
                        return Err("unterminated attribute value".into());
                    }
                    let raw = std::str::from_utf8(&self.b[start..self.i])
                        .map_err(|_| "invalid UTF-8".to_string())?;
                    el.attrs.push((key, decode_entities(raw)?));
                    self.i += 1;
                }
                None => return Err("truncated element".into()),
            }
        }

        // Content: text and child elements until the matching close tag.
        loop {
            if self.starts("<!--") {
                self.skip_comment()?;
            } else if self.starts("</") {
                self.i += 2;
                let close = self.name()?;
                if close != el.name {
                    return Err(format!("mismatched close tag </{close}> for <{}>", el.name));
                }
                self.skip_ws();
                if self.b.get(self.i) != Some(&b'>') {
                    return Err("malformed close tag".into());
                }
                self.i += 1;
                // Indentation between child elements is not content.
                if !el.children.is_empty() && el.text.trim().is_empty() {
                    el.text.clear();
                }
                return Ok(el);
            } else if self.starts("<?") || self.starts("<!") {
                return Err(format!("unsupported markup at byte {}", self.i));
            } else if self.starts("<") {
                el.children.push(self.element()?);
            } else if self.i >= self.b.len() {
                return Err(format!("unexpected end of input inside <{}>", el.name));
            } else {
                let start = self.i;
                while self.i < self.b.len() && self.b[self.i] != b'<' {
                    self.i += 1;
                }
                let raw = std::str::from_utf8(&self.b[start..self.i])
                    .map_err(|_| "invalid UTF-8".to_string())?;
                el.text.push_str(&decode_entities(raw)?);
            }
        }
    }
}

fn decode_entities(raw: &str) -> Result<String, String> {
    if !raw.contains('&') {
        return Ok(raw.to_string());
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        rest = &rest[pos + 1..];
        let semi = rest.find(';').ok_or("unterminated entity")?;
        let ent = &rest[..semi];
        match ent {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                let code = u32::from_str_radix(&ent[2..], 16)
                    .map_err(|_| format!("bad character reference &{ent};"))?;
                out.push(char::from_u32(code).ok_or("invalid character reference")?);
            }
            _ if ent.starts_with('#') => {
                let code = ent[1..]
                    .parse::<u32>()
                    .map_err(|_| format!("bad character reference &{ent};"))?;
                out.push(char::from_u32(code).ok_or("invalid character reference")?);
            }
            _ => return Err(format!("unknown entity &{ent};")),
        }
        rest = &rest[semi + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c if (c as u32) < 0x20 && c != '\n' && c != '\t' && c != '\r' => {
                // XML 1.0 forbids most C0 controls entirely; strip them
                // rather than emit an unparseable document.
            }
            c => out.push(c),
        }
    }
    out
}

/// Serialize an element tree with two-space indentation.
pub fn to_string(root: &Element) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    write_element(root, 0, &mut out);
    out
}

fn write_element(el: &Element, depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push('\t');
    }
    let _ = write!(out, "<{}", el.name);
    for (k, v) in &el.attrs {
        let _ = write!(out, " {}=\"{}\"", k, escape_text(v));
    }
    if el.children.is_empty() && el.text.is_empty() {
        out.push_str(" />\n");
        return;
    }
    out.push('>');
    if el.children.is_empty() {
        let _ = writeln!(out, "{}</{}>", escape_text(&el.text), el.name);
        return;
    }
    out.push('\n');
    for child in &el.children {
        write_element(child, depth + 1, out);
    }
    for _ in 0..depth {
        out.push('\t');
    }
    let _ = writeln!(out, "</{}>", el.name);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_elements_attributes_and_text() {
        let doc = r#"<?xml version="1.0"?>
<Root a="1">
  <Child b="two">hello</Child>
  <Child>world</Child>
</Root>"#;
        let root = parse(doc).unwrap();
        assert_eq!(root.name, "Root");
        assert_eq!(root.attr("a"), Some("1"));
        assert_eq!(root.children_named("Child").count(), 2);
        assert_eq!(root.child("Child").unwrap().text, "hello");
    }

    #[test]
    fn decodes_all_predefined_and_numeric_entities() {
        let root = parse("<V>&amp;&lt;&gt;&quot;&apos;&#65;&#x1F510;</V>").unwrap();
        assert_eq!(root.text, "&<>\"'A\u{1F510}");
    }

    #[test]
    fn rejects_doctype_declarations() {
        // XXE guard: a vault file has no business declaring a DTD.
        let doc = "<!DOCTYPE foo [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><V>&x;</V>";
        assert!(parse(doc).unwrap_err().contains("DOCTYPE"));
    }

    #[test]
    fn rejects_structurally_broken_documents() {
        assert!(parse("<A><B></A></B>").is_err(), "mismatched close tags");
        assert!(parse("<A/><B/>").is_err(), "trailing content after root");
        assert!(parse("<A><B></A>").is_err(), "unclosed child");
    }

    #[test]
    fn escape_round_trips_hostile_password_text() {
        let hostile = "pw&<>\"'\n\ttext ]]> &amp;";
        let doc = format!("<V>{}</V>", escape_text(hostile));
        // Control characters aside, everything must survive exactly.
        assert_eq!(parse(&doc).unwrap().text, hostile);
    }

    #[test]
    fn serializer_output_reparses_identically() {
        let mut root = Element::new("Root");
        root.attrs.push(("Version".into(), "2".into()));
        root.children.push(Element::with_text("Name", "a & b <c>"));
        root.children.push(Element::new("Empty"));
        let text = to_string(&root);
        assert_eq!(parse(&text).unwrap(), root);
    }

    #[test]
    fn comments_inside_content_are_ignored() {
        let root = parse("<A><!-- note --><B>x</B></A>").unwrap();
        assert_eq!(root.child("B").unwrap().text, "x");
    }
}
