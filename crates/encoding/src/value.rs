//! The value model: integers, bytes, text, lists, and records.

use std::collections::btree_map;
use std::collections::BTreeMap;
use std::fmt;

use crate::varint::VARINT_MAX;
use crate::{Kind, SchemaError};

/// An integer in the range the encoding can carry: `-2^60 ..= 2^60 - 1`.
///
/// Values outside the range are unrepresentable, so every `Value` encodes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Int(i64);

impl Int {
    /// The smallest integer: `-2^60`.
    pub const MIN: Int = Int(-(1 << 60));
    /// The largest integer: `2^60 - 1`.
    pub const MAX: Int = Int((1 << 60) - 1);

    /// Returns the integer if it is in range.
    pub const fn new(v: i64) -> Option<Int> {
        if v >= Self::MIN.0 && v <= Self::MAX.0 {
            Some(Int(v))
        } else {
            None
        }
    }

    /// Returns the unsigned integer if it is in range.
    pub const fn from_u64(v: u64) -> Option<Int> {
        if v <= Self::MAX.0 as u64 {
            Some(Int(v as i64))
        } else {
            None
        }
    }

    /// The value as `i64`.
    pub const fn get(self) -> i64 {
        self.0
    }

    /// The value as `u64`, if it is not negative.
    pub const fn as_u64(self) -> Option<u64> {
        if self.0 >= 0 {
            Some(self.0 as u64)
        } else {
            None
        }
    }
}

impl fmt::Display for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

macro_rules! int_from_small {
    ($($t:ty),*) => {$(
        impl From<$t> for Int {
            fn from(v: $t) -> Int {
                Int(i64::from(v))
            }
        }
    )*};
}
int_from_small!(u8, u16, u32, i8, i16, i32, bool);

impl TryFrom<u64> for Int {
    type Error = SchemaError;
    fn try_from(v: u64) -> Result<Int, SchemaError> {
        Int::from_u64(v).ok_or(SchemaError::IntegerOutOfRange)
    }
}

impl TryFrom<i64> for Int {
    type Error = SchemaError;
    fn try_from(v: i64) -> Result<Int, SchemaError> {
        Int::new(v).ok_or(SchemaError::IntegerOutOfRange)
    }
}

impl TryFrom<usize> for Int {
    type Error = SchemaError;
    fn try_from(v: usize) -> Result<Int, SchemaError> {
        Int::try_from(v as u64)
    }
}

/// A decoded or constructed value.
///
/// Equality is structural, and because the encoding is canonical, two values
/// are equal exactly when their encodings are equal.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Value {
    /// An integer (encoding types 0 and 1). Booleans are `0` and `1`.
    Int(Int),
    /// A byte string (type 2).
    Bytes(Vec<u8>),
    /// A UTF-8 text string (type 3), not normalized.
    Text(String),
    /// A list of values (type 4).
    List(Vec<Value>),
    /// A record (type 5).
    Record(Record),
}

impl Value {
    /// The integer, if this is one.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(i.get()),
            _ => None,
        }
    }

    /// The unsigned integer, if this is a non-negative integer.
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Value::Int(i) => i.as_u64(),
            _ => None,
        }
    }

    /// The boolean, if this is the integer `0` or `1`.
    pub fn as_bool(&self) -> Option<bool> {
        match self.as_int() {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => None,
        }
    }

    /// The bytes, if this is a byte string.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The text, if this is a text string.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The items, if this is a list.
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    /// The record, if this is one.
    pub fn as_record(&self) -> Option<&Record> {
        match self {
            Value::Record(r) => Some(r),
            _ => None,
        }
    }

    /// A short name of this value's type, for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Int(i) if i.get() >= 0 => "uint",
            Value::Int(_) => "neg",
            Value::Bytes(_) => "bytes",
            Value::Text(_) => "text",
            Value::List(_) => "list",
            Value::Record(_) => "record",
        }
    }

    /// The nesting depth: 0 for a scalar, and one more than the deepest
    /// item for a list or record. Decoders reject depths over
    /// [`MAX_DEPTH`](crate::MAX_DEPTH).
    pub fn depth(&self) -> usize {
        match self {
            Value::List(items) => 1 + items.iter().map(Value::depth).max().unwrap_or(0),
            Value::Record(r) => 1 + r.values().map(Value::depth).max().unwrap_or(0),
            _ => 0,
        }
    }

    /// Builds a list value from anything convertible to values.
    pub fn list<I, V>(items: I) -> Value
    where
        I: IntoIterator<Item = V>,
        V: Into<Value>,
    {
        Value::List(items.into_iter().map(Into::into).collect())
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The canonical text rendering is the most useful debug form.
        fmt::Display::fmt(self, f)
    }
}

impl From<Int> for Value {
    fn from(v: Int) -> Value {
        Value::Int(v)
    }
}

macro_rules! value_from_small {
    ($($t:ty),*) => {$(
        impl From<$t> for Value {
            fn from(v: $t) -> Value {
                Value::Int(Int::from(v))
            }
        }
    )*};
}
value_from_small!(u8, u16, u32, i8, i16, i32, bool);

/// Converts an unsigned integer.
///
/// # Panics
///
/// Panics if `v >= 2^60`, which the encoding cannot carry. Use
/// [`Int::try_from`] where such values can arise.
impl From<u64> for Value {
    fn from(v: u64) -> Value {
        Value::Int(Int::from_u64(v).expect("integer exceeds 2^60 - 1"))
    }
}

/// Converts a signed integer.
///
/// # Panics
///
/// Panics if `v` is outside `-2^60 ..= 2^60 - 1`. Use [`Int::try_from`]
/// where such values can arise.
impl From<i64> for Value {
    fn from(v: i64) -> Value {
        Value::Int(Int::new(v).expect("integer outside -2^60 ..= 2^60 - 1"))
    }
}

/// Converts a length or index.
///
/// # Panics
///
/// Panics if `v >= 2^60`.
impl From<usize> for Value {
    fn from(v: usize) -> Value {
        Value::from(v as u64)
    }
}

impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Value {
        Value::Bytes(v)
    }
}

impl From<&[u8]> for Value {
    fn from(v: &[u8]) -> Value {
        Value::Bytes(v.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for Value {
    fn from(v: [u8; N]) -> Value {
        Value::Bytes(v.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for Value {
    fn from(v: &[u8; N]) -> Value {
        Value::Bytes(v.to_vec())
    }
}

impl From<String> for Value {
    fn from(v: String) -> Value {
        Value::Text(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Value {
        Value::Text(v.to_owned())
    }
}

impl From<Vec<Value>> for Value {
    fn from(v: Vec<Value>) -> Value {
        Value::List(v)
    }
}

impl From<Record> for Value {
    fn from(v: Record) -> Value {
        Value::Record(v)
    }
}

impl From<Kind> for Value {
    fn from(k: Kind) -> Value {
        match k {
            Kind::Core(n) => Value::from(n),
            Kind::Named(name) => Value::Bytes(name.to_vec()),
        }
    }
}

/// A record: fields keyed by unsigned integers, kept sorted and unique.
///
/// A record holds every field it was decoded with, known or not, so a
/// decoded record re-encodes to exactly its original bytes.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct Record {
    fields: BTreeMap<u64, Value>,
}

impl Record {
    /// An empty record.
    pub fn new() -> Record {
        Record::default()
    }

    /// Sets field `key`, returning the previous value if there was one.
    ///
    /// # Panics
    ///
    /// Panics if `key >= 2^63`, which a varint cannot carry.
    pub fn insert(&mut self, key: u64, value: impl Into<Value>) -> Option<Value> {
        assert!(key <= VARINT_MAX, "record key {key} exceeds 2^63 - 1");
        self.fields.insert(key, value.into())
    }

    /// Builder form of [`insert`](Record::insert).
    #[must_use]
    pub fn with(mut self, key: u64, value: impl Into<Value>) -> Record {
        self.insert(key, value);
        self
    }

    /// Builder form that sets the field only when `value` is `Some`.
    #[must_use]
    pub fn with_opt<V: Into<Value>>(mut self, key: u64, value: Option<V>) -> Record {
        if let Some(v) = value {
            self.insert(key, v);
        }
        self
    }

    /// Removes field `key`.
    pub fn remove(&mut self, key: u64) -> Option<Value> {
        self.fields.remove(&key)
    }

    /// The value of field `key`, if present.
    pub fn get(&self, key: u64) -> Option<&Value> {
        self.fields.get(&key)
    }

    /// A mutable reference to the value of field `key`, if present.
    pub fn get_mut(&mut self, key: u64) -> Option<&mut Value> {
        self.fields.get_mut(&key)
    }

    /// Whether field `key` is present.
    pub fn contains(&self, key: u64) -> bool {
        self.fields.contains_key(&key)
    }

    /// The number of fields.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether the record has no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// The fields in key order.
    pub fn iter(&self) -> btree_map::Iter<'_, u64, Value> {
        self.fields.iter()
    }

    /// The keys in order.
    pub fn keys(&self) -> impl Iterator<Item = u64> + '_ {
        self.fields.keys().copied()
    }

    /// The values in key order.
    pub fn values(&self) -> btree_map::Values<'_, u64, Value> {
        self.fields.values()
    }

    /// The fields whose keys are not in `known`, in key order. Useful for
    /// carrying unknown fields through a typed view.
    pub fn unknown_fields<'a>(
        &'a self,
        known: &'a [u64],
    ) -> impl Iterator<Item = (u64, &'a Value)> + 'a {
        self.fields
            .iter()
            .filter(move |(k, _)| !known.contains(k))
            .map(|(k, v)| (*k, v))
    }

    /// A copy of this record keeping only the fields whose keys are not in
    /// `known`.
    pub fn without(&self, known: &[u64]) -> Record {
        Record {
            fields: self
                .fields
                .iter()
                .filter(|(k, _)| !known.contains(k))
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
        }
    }

    // ---- typed getters --------------------------------------------------

    fn required(&self, key: u64) -> Result<&Value, SchemaError> {
        self.get(key).ok_or(SchemaError::Missing { key })
    }

    fn wrong(key: u64, expected: &'static str, v: &Value) -> SchemaError {
        SchemaError::WrongType {
            key,
            expected,
            found: v.type_name(),
        }
    }

    /// The kind in field `0`: a small integer or a 32-byte name.
    pub fn kind(&self) -> Result<Kind, SchemaError> {
        let v = self.required(0)?;
        Kind::from_value(v).ok_or_else(|| Self::wrong(0, "kind (uint or bytes(32))", v))
    }

    /// Required unsigned integer.
    pub fn uint(&self, key: u64) -> Result<u64, SchemaError> {
        let v = self.required(key)?;
        v.as_uint().ok_or_else(|| Self::wrong(key, "uint", v))
    }

    /// Optional unsigned integer.
    pub fn opt_uint(&self, key: u64) -> Result<Option<u64>, SchemaError> {
        self.get(key)
            .map(|v| v.as_uint().ok_or_else(|| Self::wrong(key, "uint", v)))
            .transpose()
    }

    /// Required integer of either sign.
    pub fn int(&self, key: u64) -> Result<i64, SchemaError> {
        let v = self.required(key)?;
        v.as_int().ok_or_else(|| Self::wrong(key, "int", v))
    }

    /// Optional integer of either sign.
    pub fn opt_int(&self, key: u64) -> Result<Option<i64>, SchemaError> {
        self.get(key)
            .map(|v| v.as_int().ok_or_else(|| Self::wrong(key, "int", v)))
            .transpose()
    }

    /// Required boolean (`0` or `1`).
    pub fn bool(&self, key: u64) -> Result<bool, SchemaError> {
        let v = self.required(key)?;
        v.as_bool().ok_or_else(|| Self::wrong(key, "bool", v))
    }

    /// Optional boolean; absent reads as `None`.
    pub fn opt_bool(&self, key: u64) -> Result<Option<bool>, SchemaError> {
        self.get(key)
            .map(|v| v.as_bool().ok_or_else(|| Self::wrong(key, "bool", v)))
            .transpose()
    }

    /// Required byte string.
    pub fn bytes(&self, key: u64) -> Result<&[u8], SchemaError> {
        let v = self.required(key)?;
        v.as_bytes().ok_or_else(|| Self::wrong(key, "bytes", v))
    }

    /// Optional byte string.
    pub fn opt_bytes(&self, key: u64) -> Result<Option<&[u8]>, SchemaError> {
        self.get(key)
            .map(|v| v.as_bytes().ok_or_else(|| Self::wrong(key, "bytes", v)))
            .transpose()
    }

    /// Required byte string of exactly `N` bytes.
    pub fn bytes_n<const N: usize>(&self, key: u64) -> Result<[u8; N], SchemaError> {
        let b = self.bytes(key)?;
        b.try_into().map_err(|_| SchemaError::WrongLength {
            key,
            expected: N,
            found: b.len(),
        })
    }

    /// Optional byte string of exactly `N` bytes.
    pub fn opt_bytes_n<const N: usize>(&self, key: u64) -> Result<Option<[u8; N]>, SchemaError> {
        if self.contains(key) {
            self.bytes_n(key).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Required text.
    pub fn text(&self, key: u64) -> Result<&str, SchemaError> {
        let v = self.required(key)?;
        v.as_text().ok_or_else(|| Self::wrong(key, "text", v))
    }

    /// Optional text.
    pub fn opt_text(&self, key: u64) -> Result<Option<&str>, SchemaError> {
        self.get(key)
            .map(|v| v.as_text().ok_or_else(|| Self::wrong(key, "text", v)))
            .transpose()
    }

    /// Required list.
    pub fn list(&self, key: u64) -> Result<&[Value], SchemaError> {
        let v = self.required(key)?;
        v.as_list().ok_or_else(|| Self::wrong(key, "list", v))
    }

    /// Optional list; absent reads as `None`.
    pub fn opt_list(&self, key: u64) -> Result<Option<&[Value]>, SchemaError> {
        self.get(key)
            .map(|v| v.as_list().ok_or_else(|| Self::wrong(key, "list", v)))
            .transpose()
    }

    /// Required list, every item of which is a record.
    pub fn record_list(&self, key: u64) -> Result<Vec<&Record>, SchemaError> {
        self.list(key)?
            .iter()
            .map(|v| {
                v.as_record()
                    .ok_or_else(|| Self::wrong(key, "list of records", v))
            })
            .collect()
    }

    /// Required record.
    pub fn record(&self, key: u64) -> Result<&Record, SchemaError> {
        let v = self.required(key)?;
        v.as_record().ok_or_else(|| Self::wrong(key, "record", v))
    }

    /// Optional record.
    pub fn opt_record(&self, key: u64) -> Result<Option<&Record>, SchemaError> {
        self.get(key)
            .map(|v| v.as_record().ok_or_else(|| Self::wrong(key, "record", v)))
            .transpose()
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<'a> IntoIterator for &'a Record {
    type Item = (&'a u64, &'a Value);
    type IntoIter = btree_map::Iter<'a, u64, Value>;
    fn into_iter(self) -> Self::IntoIter {
        self.fields.iter()
    }
}

impl IntoIterator for Record {
    type Item = (u64, Value);
    type IntoIter = btree_map::IntoIter<u64, Value>;
    fn into_iter(self) -> Self::IntoIter {
        self.fields.into_iter()
    }
}

impl<V: Into<Value>> FromIterator<(u64, V)> for Record {
    /// Collects fields; a later duplicate key replaces an earlier one.
    fn from_iter<I: IntoIterator<Item = (u64, V)>>(iter: I) -> Record {
        let mut r = Record::new();
        for (k, v) in iter {
            r.insert(k, v);
        }
        r
    }
}
