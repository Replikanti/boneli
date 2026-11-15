//! The value type. Objects keep their members in insertion order and never
//! hold a key twice (ADR-008, D4).

use std::cmp::Ordering;
use std::fmt;

use crate::limits::MAX_DEPTH;
use crate::number::Number;

/// A JSON value.
///
/// `Clone`, `PartialEq` and `Drop` recurse. Values from `parse` nest at
/// most `MAX_DEPTH` deep, which keeps them inside the stack (ADR-008, D6);
/// a value built by hand much deeper than that can overflow the stack in
/// these operations, and `to_vec` refuses it with `TooDeep`.
///
/// `Debug` is compact and the same with or without `#`, for example
/// `Object {"a": Array [Number(1), String("x"), Null]}`, so its cost is
/// linear in the value's size. A non-empty container inside `MAX_DEPTH`
/// others prints `..` instead of its contents, so `Debug` recurses no
/// deeper on a built value than on a parsed one (ADR-008, D6 and D9).
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, as its lexeme.
    Number(Number),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object.
    Object(Object),
}

impl Value {
    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The boolean, if this is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The number, if this is one.
    pub fn as_number(&self) -> Option<&Number> {
        match self {
            Value::Number(n) => Some(n),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The object, if this is one.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Whether this is `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// The member `key`, if this is an object that has it.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object().and_then(|o| o.get(key))
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_value(self, f, 0)
    }
}

/// Writes `value`, a value nested `depth` deep, straight to `f`: no
/// `debug_list` or `debug_map`, whose `{:#?}` form passes every byte
/// through one indentation adapter per level (ADR-008, D9).
fn debug_value(value: &Value, f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
    match value {
        Value::Null => f.write_str("Null"),
        Value::Bool(true) => f.write_str("Bool(true)"),
        Value::Bool(false) => f.write_str("Bool(false)"),
        Value::Number(n) => fmt::Debug::fmt(n, f),
        Value::String(s) => {
            f.write_str("String(")?;
            fmt::Debug::fmt(s.as_str(), f)?;
            f.write_str(")")
        }
        Value::Array(items) => {
            f.write_str("Array [")?;
            if depth >= MAX_DEPTH && !items.is_empty() {
                f.write_str("..")?;
            } else {
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    debug_value(item, f, depth + 1)?;
                }
            }
            f.write_str("]")
        }
        Value::Object(o) => {
            f.write_str("Object ")?;
            debug_object(o, f, depth)
        }
    }
}

/// `{"key": value, ...}` for an object nested `depth` deep.
fn debug_object(object: &Object, f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
    f.write_str("{")?;
    if depth >= MAX_DEPTH && !object.is_empty() {
        f.write_str("..")?;
    } else {
        for (i, (key, item)) in object.members.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            fmt::Debug::fmt(key.as_str(), f)?;
            f.write_str(": ")?;
            debug_value(item, f, depth + 1)?;
        }
    }
    f.write_str("}")
}

impl From<bool> for Value {
    fn from(b: bool) -> Value {
        Value::Bool(b)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Value {
        Value::String(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Value {
        Value::String(s)
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Value {
        Value::Number(Number::from(n))
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Value {
        Value::Number(Number::from(n))
    }
}

impl From<Number> for Value {
    fn from(n: Number) -> Value {
        Value::Number(n)
    }
}

impl From<Vec<Value>> for Value {
    fn from(items: Vec<Value>) -> Value {
        Value::Array(items)
    }
}

impl From<Object> for Value {
    fn from(o: Object) -> Value {
        Value::Object(o)
    }
}

/// A JSON object: members in insertion order, each key at most once.
///
/// Lookups scan the members, which is fast for the small objects APIs
/// send. Building an object of m members with `insert` costs O(m²) key
/// comparisons; `collect` costs O(m log m). `Debug` prints
/// `{"key": value, ...}` in the compact form of [`Value`].
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Object {
    members: Vec<(String, Value)>,
}

impl fmt::Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_object(self, f, 0)
    }
}

impl Object {
    /// An empty object.
    pub fn new() -> Object {
        Object::default()
    }

    /// An empty object with room for `capacity` members.
    pub fn with_capacity(capacity: usize) -> Object {
        Object {
            members: Vec::with_capacity(capacity),
        }
    }

    /// Members whose keys the caller has checked to be distinct.
    pub(crate) fn from_distinct(members: Vec<(String, Value)>) -> Object {
        Object { members }
    }

    /// The number of members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the object has no members.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The value of `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.members.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The value of `key`, mutably.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.members
            .iter_mut()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// Whether the object has `key`.
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Sets `key` to `value`. An existing key keeps its position and its
    /// old value is returned; a new key goes last.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) -> Option<Value> {
        let key = key.into();
        let value = value.into();
        match self.get_mut(&key) {
            Some(slot) => Some(std::mem::replace(slot, value)),
            None => {
                self.members.push((key, value));
                None
            }
        }
    }

    /// Removes `key` and returns its value; the other members keep their
    /// order.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let at = self.members.iter().position(|(k, _)| k == key)?;
        Some(self.members.remove(at).1)
    }

    /// The members in order.
    pub fn iter(&self) -> Iter<'_> {
        Iter(self.members.iter())
    }

    /// The keys in order.
    pub fn keys(&self) -> impl Iterator<Item = &str> + '_ {
        self.members.iter().map(|(k, _)| k.as_str())
    }
}

/// The members of an object, borrowed, in order.
#[derive(Clone, Debug)]
pub struct Iter<'a>(std::slice::Iter<'a, (String, Value)>);

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a str, &'a Value);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(k, v)| (k.as_str(), v))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl<'a> IntoIterator for &'a Object {
    type Item = (&'a str, &'a Value);
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

/// The members of an object, owned, in order.
#[derive(Debug)]
pub struct IntoIter(std::vec::IntoIter<(String, Value)>);

impl Iterator for IntoIter {
    type Item = (String, Value);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl IntoIterator for Object {
    type Item = (String, Value);
    type IntoIter = IntoIter;

    fn into_iter(self) -> IntoIter {
        IntoIter(self.members.into_iter())
    }
}

impl FromIterator<(String, Value)> for Object {
    /// Collects members with the semantics of `insert`: a repeated key keeps
    /// the position of its first occurrence and the value of its last.
    /// O(m log m) for m members.
    fn from_iter<I: IntoIterator<Item = (String, Value)>>(iter: I) -> Object {
        let mut members: Vec<(String, Value)> = iter.into_iter().collect();
        let mut order: Vec<usize> = (0..members.len()).collect();
        order.sort_unstable_by(|&a, &b| by_key_then_index(&members, a, b));
        let mut keep = vec![true; members.len()];
        let mut run = 0;
        while run < order.len() {
            let mut end = run + 1;
            while end < order.len() && members[order[end]].0 == members[order[run]].0 {
                end += 1;
            }
            if end - run > 1 {
                let first = order[run];
                let last = order[end - 1];
                let value = std::mem::replace(&mut members[last].1, Value::Null);
                members[first].1 = value;
                for &later in &order[run + 1..end] {
                    keep[later] = false;
                }
            }
            run = end;
        }
        let mut flags = keep.into_iter();
        members.retain(|_| flags.next().unwrap_or(false));
        Object { members }
    }
}

/// Orders member indices by key, then by position.
pub(crate) fn by_key_then_index(members: &[(String, Value)], a: usize, b: usize) -> Ordering {
    members[a].0.cmp(&members[b].0).then(a.cmp(&b))
}

#[cfg(test)]
mod tests {
    use super::{Object, Value};
    use crate::{Limits, parse};

    /// Every container of `value` holds exactly its elements, so no spare
    /// slot counts toward the memory per value (ADR-008, D5).
    fn assert_exact(value: &Value) {
        let mut stack = vec![value];
        while let Some(v) = stack.pop() {
            match v {
                Value::Array(items) => {
                    assert_eq!(items.capacity(), items.len(), "array {v:?}");
                    stack.extend(items.iter());
                }
                Value::Object(Object { members }) => {
                    assert_eq!(members.capacity(), members.len(), "object {v:?}");
                    stack.extend(members.iter().map(|(_, item)| item));
                }
                _ => {}
            }
        }
    }

    #[test]
    fn parsed_containers_have_exact_capacity() {
        let lim = Limits::new(1 << 16, 512, 1 << 16).expect("limits");
        let mut wide = String::from("[");
        for i in 0..1000 {
            if i > 0 {
                wide.push(',');
            }
            wide.push_str(&format!("{{\"k{i}\":[{i}]}}"));
        }
        wide.push(']');
        let chains = format!(
            "[{}0{},{}0{}]",
            "{\"a\":".repeat(64),
            "}".repeat(64),
            "[".repeat(64),
            "]".repeat(64)
        );
        for input in [
            "[0]",
            "{\"a\":0}",
            "[{\"a\":0},{\"\":0}]",
            "[[0],[0],[0]]",
            "[0,0,0]",
            "{\"a\":0,\"b\":0,\"c\":0}",
            "[0,0,0,0,0]",
            chains.as_str(),
            wide.as_str(),
        ] {
            let v = parse(input.as_bytes(), &lim).expect("parses");
            assert_exact(&v);
        }
    }
}
