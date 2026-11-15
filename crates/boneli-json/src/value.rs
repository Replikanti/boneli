//! The value type. Objects keep their members in insertion order and never
//! hold a key twice (ADR-008, D4).

use std::cmp::Ordering;

use crate::number::Number;

/// A JSON value.
///
/// `Clone`, `PartialEq`, `Debug` and `Drop` recurse. Values from `parse`
/// nest at most `MAX_DEPTH` deep, which keeps them inside the stack
/// (ADR-008, D6); a value built by hand much deeper than that can overflow
/// the stack in these operations, and `to_vec` refuses it with `TooDeep`.
#[derive(Clone, Debug, PartialEq, Eq)]
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
/// comparisons; `collect` costs O(m log m).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Object {
    members: Vec<(String, Value)>,
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
