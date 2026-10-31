//! Hand-rolled canonical JSON line writer for `ruster-run-sim/v1`.
//!
//! Fields are written in call order, so every event has a fixed field order.
//! Nothing here reads a clock or iterates a map. Strings are escaped per
//! RFC 8259 §7: `"` and `\` are backslash-escaped, control characters below
//! U+0020 use `\n`, `\r`, `\t`, or `\u00XX`, and everything else is emitted as
//! UTF-8.

use std::fmt::Write as _;

use ruster_core::{FieldValue, FieldVisitor, MacAddress, ObservableFields};

/// One JSON object under construction, terminated by `\n` on [`Line::finish`].
pub(crate) struct Line {
    buf: String,
    /// Whether the innermost open container already holds an element.
    filled: Vec<bool>,
}

impl Line {
    pub(crate) fn event(name: &str) -> Self {
        let mut line = Self {
            buf: String::with_capacity(256),
            filled: vec![false],
        };
        line.buf.push('{');
        line.str("event", name);
        line
    }

    fn separator(&mut self) {
        if let Some(filled) = self.filled.last_mut() {
            if *filled {
                self.buf.push(',');
            }
            *filled = true;
        }
    }

    fn key(&mut self, key: &str) {
        self.separator();
        escape_into(&mut self.buf, key);
        self.buf.push(':');
    }

    pub(crate) fn str(&mut self, key: &str, value: &str) {
        self.key(key);
        escape_into(&mut self.buf, value);
    }

    pub(crate) fn u64(&mut self, key: &str, value: u64) {
        self.key(key);
        let _ = write!(self.buf, "{value}");
    }

    pub(crate) fn usize(&mut self, key: &str, value: usize) {
        self.u64(key, u64::try_from(value).unwrap_or(u64::MAX));
    }

    pub(crate) fn opt_u64(&mut self, key: &str, value: Option<u64>) {
        match value {
            Some(value) => self.u64(key, value),
            None => self.null(key),
        }
    }

    pub(crate) fn opt_str(&mut self, key: &str, value: Option<&str>) {
        match value {
            Some(value) => self.str(key, value),
            None => self.null(key),
        }
    }

    pub(crate) fn bool(&mut self, key: &str, value: bool) {
        self.key(key);
        self.buf.push_str(if value { "true" } else { "false" });
    }

    pub(crate) fn null(&mut self, key: &str) {
        self.key(key);
        self.buf.push_str("null");
    }

    pub(crate) fn hex(&mut self, key: &str, bytes: &[u8]) {
        self.key(key);
        self.buf.push('"');
        push_hex(&mut self.buf, bytes);
        self.buf.push('"');
    }

    pub(crate) fn mac(&mut self, key: &str, mac: MacAddress) {
        self.key(key);
        self.buf.push('"');
        for (index, octet) in mac.0.iter().enumerate() {
            if index != 0 {
                self.buf.push(':');
            }
            let _ = write!(self.buf, "{octet:02x}");
        }
        self.buf.push('"');
    }

    pub(crate) fn open(&mut self, key: &str) {
        self.key(key);
        self.buf.push('{');
        self.filled.push(false);
    }

    pub(crate) fn open_array(&mut self, key: &str) {
        self.key(key);
        self.buf.push('[');
        self.filled.push(false);
    }

    /// Opens an object as the next array element.
    pub(crate) fn open_element(&mut self) {
        self.separator();
        self.buf.push('{');
        self.filled.push(false);
    }

    pub(crate) fn close(&mut self) {
        self.filled.pop();
        self.buf.push('}');
    }

    pub(crate) fn close_array(&mut self) {
        self.filled.pop();
        self.buf.push(']');
    }

    /// Writes every `(section, key, value)` triple as a flat
    /// `"section.key": value` member of a new object named `key`.
    pub(crate) fn fields<T: ObservableFields>(&mut self, key: &str, value: &T) {
        self.open(key);
        value.visit_fields(&mut FieldsVisitor { line: self });
        self.close();
    }

    pub(crate) fn finish(mut self) -> String {
        while self.filled.len() > 1 {
            self.close();
        }
        self.buf.push('}');
        self.buf.push('\n');
        self.buf
    }
}

struct FieldsVisitor<'a> {
    line: &'a mut Line,
}

impl FieldVisitor for FieldsVisitor<'_> {
    fn field(&mut self, section: &'static str, key: &'static str, value: FieldValue) {
        let mut name = String::with_capacity(section.len() + key.len() + 1);
        name.push_str(section);
        name.push('.');
        name.push_str(key);
        let line = &mut *self.line;
        match value {
            FieldValue::Count(count) => line.u64(&name, count),
            FieldValue::Flag(flag) => line.bool(&name, flag),
            FieldValue::Millis(millis) => line.opt_u64(&name, millis.map(|millis| millis.0)),
            FieldValue::Generation(generation) => {
                line.opt_u64(&name, generation.map(std::num::NonZeroU64::get));
            }
            FieldValue::Label(label) => line.str(&name, label),
        }
    }
}

fn escape_into(buf: &mut String, value: &str) {
    buf.push('"');
    for character in value.chars() {
        match character {
            '"' => buf.push_str("\\\""),
            '\\' => buf.push_str("\\\\"),
            '\n' => buf.push_str("\\n"),
            '\r' => buf.push_str("\\r"),
            '\t' => buf.push_str("\\t"),
            control if u32::from(control) < 0x20 => {
                let _ = write!(buf, "\\u{:04x}", u32::from(control));
            }
            other => buf.push(other),
        }
    }
    buf.push('"');
}

pub(crate) fn push_hex(buf: &mut String, bytes: &[u8]) {
    for byte in bytes {
        let _ = write!(buf, "{byte:02x}");
    }
}

pub(crate) fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    push_hex(&mut out, bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::Line;

    #[test]
    fn json_strings_are_escaped_and_fields_keep_call_order() {
        let mut line = Line::event("x");
        line.str("s", "a\"b\\c\nd\u{1}é");
        line.open_array("list");
        line.open_element();
        line.u64("n", 1);
        line.close();
        line.open_element();
        line.null("n");
        line.close();
        line.close_array();
        line.open("o");
        line.bool("b", true);
        assert_eq!(
            line.finish(),
            "{\"event\":\"x\",\"s\":\"a\\\"b\\\\c\\nd\\u0001é\",\"list\":[{\"n\":1},{\"n\":null}],\"o\":{\"b\":true}}\n"
        );
    }
}
