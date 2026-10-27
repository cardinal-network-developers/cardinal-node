//! The canonical text rendering (`encoding.md#text-rendering`).
//!
//! `Display` on [`Value`] and [`Record`] produces it. Text values are
//! rendered as JSON strings with the minimal escaping of RFC 8259: `"` and
//! `\` are escaped, control characters below U+0020 use the short forms
//! `\b \t \n \f \r` where they exist and `\u00xx` (lowercase) otherwise, and
//! every other character, including non-ASCII, is written as itself.

use std::fmt::{self, Write};

use crate::value::{Record, Value};

const HEX: &[u8; 16] = b"0123456789abcdef";

fn write_json_string(s: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_char('"')?;
    for c in s.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\u{08}' => f.write_str("\\b")?,
            '\t' => f.write_str("\\t")?,
            '\n' => f.write_str("\\n")?,
            '\u{0c}' => f.write_str("\\f")?,
            '\r' => f.write_str("\\r")?,
            c if (c as u32) < 0x20 => {
                let b = c as u8;
                f.write_str("\\u00")?;
                f.write_char(HEX[(b >> 4) as usize] as char)?;
                f.write_char(HEX[(b & 15) as usize] as char)?;
            }
            c => f.write_char(c)?,
        }
    }
    f.write_char('"')
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Int(i) => write!(f, "{i}"),
            Value::Bytes(b) => {
                f.write_str("h'")?;
                for byte in b {
                    f.write_char(HEX[(byte >> 4) as usize] as char)?;
                    f.write_char(HEX[(byte & 15) as usize] as char)?;
                }
                f.write_char('\'')
            }
            Value::Text(t) => write_json_string(t, f),
            Value::List(items) => {
                f.write_char('[')?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    fmt::Display::fmt(item, f)?;
                }
                f.write_char(']')
            }
            Value::Record(r) => fmt::Display::fmt(r, f),
        }
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('{')?;
        for (i, (k, v)) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{k}: ")?;
            fmt::Display::fmt(v, f)?;
        }
        f.write_char('}')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders() {
        let v = Value::list([
            Value::from(42u32),
            Value::from(-5i32),
            Value::from(vec![0x00, 0xff]),
            Value::from("hi\n\"q\"\\ \u{01} \u{7f} é"),
            Value::List(vec![]),
            Value::Record(Record::new()),
            Value::Record(Record::new().with(0, 3u32).with(1, "x")),
        ]);
        assert_eq!(
            v.to_string(),
            "[42, -5, h'00ff', \"hi\\n\\\"q\\\"\\\\ \\u0001 \u{7f} é\", [], {}, {0: 3, 1: \"x\"}]"
        );
    }

    #[test]
    fn json_compatible_strings() {
        // Every rendered text value parses as the same JSON string.
        for s in [
            "",
            "plain",
            "\u{0}\u{1f}\u{8}\u{c}",
            "tab\there",
            "ünïcødé 🐦",
            "\\\"",
        ] {
            let rendered = Value::from(s).to_string();
            let parsed: String = serde_json::from_str(&rendered).unwrap();
            assert_eq!(parsed, s);
            assert_eq!(rendered, serde_json::to_string(s).unwrap());
        }
    }
}
