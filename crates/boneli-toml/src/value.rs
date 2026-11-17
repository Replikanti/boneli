//! The value type. Tables keep their members in the order they were first
//! created and never hold a key twice (ADR-011, D4).

use std::cmp::Ordering;
use std::fmt;

use crate::limits::MAX_DEPTH;

/// A TOML value of the subset (ADR-011, D1).
///
/// `Clone`, `PartialEq` and `Drop` recurse. Values from `parse` nest at
/// most `MAX_DEPTH` deep, which keeps them inside the stack (ADR-011, D6);
/// a value built by hand much deeper than that can overflow the stack in
/// these operations.
///
/// `Debug` is compact and the same with or without `#`, for example
/// `Table {"a": Array [Integer(1), String("x"), Boolean(true)]}`, so its
/// cost is linear in the value's size. A non-empty container inside
/// `MAX_DEPTH` others prints `..` instead of its contents, so `Debug`
/// recurses no deeper on a built value than on a parsed one.
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    /// A string, from any of the four string forms.
    String(String),
    /// A decimal integer.
    Integer(i64),
    /// `true` or `false`.
    Boolean(bool),
    /// An array, static or of tables.
    Array(Vec<Value>),
    /// A table, from a header, dotted keys or an inline table.
    Table(Table),
}

impl Value {
    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The integer, if this is one.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// The boolean, if this is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
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

    /// The table, if this is one.
    pub fn as_table(&self) -> Option<&Table> {
        match self {
            Value::Table(t) => Some(t),
            _ => None,
        }
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_value(self, f, 0)
    }
}

/// Writes `value`, nested `depth` deep, straight to `f`: no `debug_list`
/// or `debug_map`, whose `{:#?}` form passes every byte through one
/// indentation adapter per level (the cubic cost of ADR-008, D9).
fn debug_value(value: &Value, f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
    match value {
        Value::String(s) => {
            f.write_str("String(")?;
            fmt::Debug::fmt(s.as_str(), f)?;
            f.write_str(")")
        }
        Value::Integer(i) => write!(f, "Integer({i})"),
        Value::Boolean(true) => f.write_str("Boolean(true)"),
        Value::Boolean(false) => f.write_str("Boolean(false)"),
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
        Value::Table(t) => {
            f.write_str("Table ")?;
            debug_table(t, f, depth)
        }
    }
}

/// `{"key": value, ...}` for a table nested `depth` deep.
fn debug_table(table: &Table, f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
    f.write_str("{")?;
    if depth >= MAX_DEPTH && !table.is_empty() {
        f.write_str("..")?;
    } else {
        for (i, (key, item)) in table.members.iter().enumerate() {
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

/// A table: members in the order they were first created, each key at
/// most once.
///
/// Equality is order-sensitive: two tables with the same members in a
/// different order differ, as for `boneli_json::Object`. Lookups scan the
/// members, which is fast for the small tables configuration has; the
/// parser keeps its own index while it builds a table (ADR-011, D11).
/// Building a table of m members with `insert` costs O(m²) key
/// comparisons; `collect` costs O(m log m). `Debug` prints
/// `{"key": value, ...}` in the compact form of [`Value`].
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Table {
    members: Vec<(String, Value)>,
}

impl fmt::Debug for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_table(self, f, 0)
    }
}

impl Table {
    /// An empty table.
    pub fn new() -> Table {
        Table::default()
    }

    /// Members whose keys the caller has checked to be distinct.
    pub(crate) fn from_distinct(members: Vec<(String, Value)>) -> Table {
        Table { members }
    }

    /// The number of members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the table has no members.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The value of `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.members.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Sets `key` to `value`. An existing key keeps its position and its
    /// old value is returned; a new key goes last.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) -> Option<Value> {
        let key = key.into();
        match self.members.iter_mut().find(|(k, _)| *k == key) {
            Some((_, slot)) => Some(std::mem::replace(slot, value)),
            None => {
                self.members.push((key, value));
                None
            }
        }
    }

    /// The members in order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &Value)> + '_ {
        self.members.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// The keys in order.
    pub fn keys(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        self.members.iter().map(|(k, _)| k.as_str())
    }
}

impl<'a> IntoIterator for &'a Table {
    type Item = (&'a str, &'a Value);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, (String, Value)>,
        fn(&'a (String, Value)) -> (&'a str, &'a Value),
    >;

    fn into_iter(self) -> Self::IntoIter {
        fn pair(member: &(String, Value)) -> (&str, &Value) {
            (member.0.as_str(), &member.1)
        }
        self.members.iter().map(pair)
    }
}

impl FromIterator<(String, Value)> for Table {
    /// Collects members with the semantics of `insert`: a repeated key keeps
    /// the position of its first occurrence and the value of its last.
    /// O(m log m) for m members.
    fn from_iter<I: IntoIterator<Item = (String, Value)>>(iter: I) -> Table {
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
                let value = std::mem::replace(&mut members[last].1, Value::Boolean(false));
                members[first].1 = value;
                for &later in &order[run + 1..end] {
                    keep[later] = false;
                }
            }
            run = end;
        }
        let mut flags = keep.into_iter();
        members.retain(|_| flags.next().unwrap_or(false));
        Table { members }
    }
}

/// Orders member indices by key, then by position.
fn by_key_then_index(members: &[(String, Value)], a: usize, b: usize) -> Ordering {
    members[a].0.cmp(&members[b].0).then(a.cmp(&b))
}

#[cfg(test)]
mod tests {
    use super::{Table, Value};
    use crate::{Limits, MAX_DEPTH, parse};

    /// The per-value costs of ADR-011, D5 start from these sizes.
    #[test]
    fn value_sizes_pinned() {
        assert_eq!(size_of::<Value>(), 32);
        assert_eq!(size_of::<(String, Value)>(), 56);
    }

    /// Every container of `table` holds exactly its elements, so no spare
    /// slot counts toward the memory per value (ADR-011, D5).
    fn assert_exact(table: &Table) {
        let mut tables = vec![table];
        let mut arrays: Vec<&Vec<Value>> = Vec::new();
        while !tables.is_empty() || !arrays.is_empty() {
            let children: Vec<&Value> = if let Some(t) = tables.pop() {
                assert_eq!(t.members.capacity(), t.members.len(), "table {t:?}");
                t.members.iter().map(|(_, v)| v).collect()
            } else if let Some(items) = arrays.pop() {
                assert_eq!(items.capacity(), items.len(), "array {items:?}");
                items.iter().collect()
            } else {
                Vec::new()
            };
            for v in children {
                match v {
                    Value::Table(t) => tables.push(t),
                    Value::Array(items) => arrays.push(items),
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn parsed_containers_have_exact_capacity() {
        let lim = Limits::new(1 << 16, MAX_DEPTH).expect("limits");
        let wide: String = (0..1000).map(|i| format!("k{i} = [{i}]\n")).collect();
        for input in [
            "a = [0]",
            "a = [0, 0, 0, 0, 0]",
            "a = {b = 0}",
            "a = [{b = 0}, {c = [1, 2, 3]}]",
            "[a.b]\nc = 1\n[a]\nd.e = [[1], [2]]",
            "[[a]]\nb = 1\n[[a]]\n[[a]]\nc = [1, 2]",
            "a.b.c.d = 1\na.b.e = 2",
            wide.as_str(),
        ] {
            assert_exact(&parse(input.as_bytes(), &lim).expect("parses"));
        }
    }
}
