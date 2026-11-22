//! The canonical text rendering (`encoding.md#text-rendering`).
//!
//! `Display` on [`Value`] and [`Record`] produces it. Text is written in
//! double quotes, with `\"` for a quote, `\\` for a backslash, `\n` for a
//! line feed, and `\u{hex}` (lowercase, no leading zeros) for every other
//! control character (Unicode category Cc: U+0000 to U+001F and U+007F to
//! U+009F). Every other character is written as itself.

use std::fmt::{self, Write};

use crate::value::{Record, Value};

const HEX: &[u8; 16] = b"0123456789abcdef";

fn write_text(s: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_char('"')?;
    for c in s.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            c if c.is_control() => write!(f, "\\u{{{:x}}}", c as u32)?,
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
            Value::Text(t) => write_text(t, f),
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
            "[42, -5, h'00ff', \"hi\\n\\\"q\\\"\\\\ \\u{1} \\u{7f} é\", [], {}, {0: 3, 1: \"x\"}]"
        );
    }

    #[test]
    fn text_escapes() {
        for (s, shown) in [
            ("", r#""""#),
            ("plain", r#""plain""#),
            ("line\nfeed", r#""line\nfeed""#),
            ("tab\there", r#""tab\u{9}here""#),
            ("\r\n", r#""\u{d}\n""#),
            ("\u{0}\u{1f}", r#""\u{0}\u{1f}""#),
            (
                "\u{7f}\u{80}\u{9f}\u{a0}",
                "\"\\u{7f}\\u{80}\\u{9f}\u{a0}\"",
            ),
            ("\\\"", r#""\\\"""#),
            ("ünïcødé 🐦 \u{2028}", "\"ünïcødé 🐦 \u{2028}\""),
        ] {
            assert_eq!(Value::from(s).to_string(), shown, "{s:?}");
        }
    }
}
