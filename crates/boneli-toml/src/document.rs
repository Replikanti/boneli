//! The table definition state of a document while it is parsed (ADR-011,
//! D4): which tables a header, a dotted key or an inline value created, and
//! which of them may still be extended. The finished tree moves into a
//! `Table` and the state is dropped.

use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::error::ErrorKind;
use crate::value::{Table, Value};

/// An error kind and the byte offset it applies to.
pub(crate) type Fail = (ErrorKind, usize);

/// A key segment and the offset of its first byte. Keys without escapes
/// borrow the input until the tree is finished (ADR-011, D5).
pub(crate) type Segment<'a> = (Cow<'a, str>, usize);

/// Members a table holds before it gets an index: a scan over at most
/// this many keys costs no more than the key that is looked up, and a
/// table that stays this small needs no B-tree node (ADR-011, D5 and D11).
const SMALL: usize = 8;

/// How a table came to exist.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Created by a header for a table below it; one header may still
    /// define it, and dotted keys may define it instead.
    Implicit,
    /// Defined by a `[header]` or as an element of `[[header]]`; headers
    /// for tables below it may follow, dotted keys from outside may not.
    Header,
    /// Created by a dotted key; more dotted keys from the same table and
    /// headers for tables below it may extend it, a header for it may not.
    Dotted,
}

/// A member of a table under construction.
pub(crate) enum Node<'a> {
    /// A scalar, an inline table or a static array: closed for good.
    Frozen(Value),
    /// A table that headers or dotted keys may still extend.
    Table(Box<Builder<'a>>),
    /// An array of tables; headers extend its last element.
    Tables(Vec<Builder<'a>>),
}

/// A table under construction: members in creation order, and, once it
/// has more than `SMALL` members, an index from key to member for
/// O(log m) lookups (ADR-011, D11).
pub(crate) struct Builder<'a> {
    origin: Origin,
    nodes: Vec<(Cow<'a, str>, Node<'a>)>,
    index: BTreeMap<Cow<'a, str>, usize>,
}

impl<'a> Builder<'a> {
    pub(crate) fn new(origin: Origin) -> Builder<'a> {
        Builder {
            origin,
            nodes: Vec::new(),
            index: BTreeMap::new(),
        }
    }

    /// The slot of `key`.
    fn find(&self, key: &str) -> Option<usize> {
        if self.index.is_empty() {
            self.nodes.iter().position(|(k, _)| k == key)
        } else {
            self.index.get(key).copied()
        }
    }

    /// Adds a member and returns its slot. The first member gets a buffer
    /// of exactly one, because most tables of a hostile chain hold one; the
    /// buffer grows as usual after that.
    fn push(&mut self, key: Cow<'a, str>, node: Node<'a>) -> usize {
        let slot = self.nodes.len();
        if slot == SMALL {
            for (i, (k, _)) in self.nodes.iter().enumerate() {
                self.index.insert(k.clone(), i);
            }
        }
        if slot >= SMALL {
            self.index.insert(key.clone(), slot);
        }
        if self.nodes.capacity() == 0 {
            self.nodes.reserve_exact(1);
        }
        self.nodes.push((key, node));
        slot
    }

    /// Adds `k1. ... .kn = value`. The middle segments pass through or
    /// create dotted tables; a table only a header created implicitly
    /// becomes dotted, so a later header for it is `DuplicateTable`.
    /// Anything else in the way is `NotExtensible`, and an existing final
    /// key is `DuplicateKey`. The caller has checked the depth.
    pub(crate) fn insert_dotted(
        &mut self,
        keys: Vec<Segment<'a>>,
        value: Value,
    ) -> Result<(), Fail> {
        let mut t = self;
        let mut keys = keys.into_iter().peekable();
        while let Some((key, at)) = keys.next() {
            let existing = t.find(&key);
            if keys.peek().is_none() {
                if existing.is_some() {
                    return Err((ErrorKind::DuplicateKey, at));
                }
                t.push(key, Node::Frozen(value));
                return Ok(());
            }
            let slot = match existing {
                Some(slot) => slot,
                None => t.push(key, Node::Table(Box::new(Builder::new(Origin::Dotted)))),
            };
            t = match t.nodes.get_mut(slot) {
                Some((_, Node::Table(b))) if b.origin != Origin::Header => {
                    b.origin = Origin::Dotted;
                    b
                }
                _ => return Err((ErrorKind::NotExtensible, at)),
            };
        }
        // `key` never yields an empty path.
        Err((ErrorKind::UnexpectedEnd, 0))
    }

    /// The finished table: every key is copied out of the input or moved,
    /// and the members keep their order. It recurses through
    /// `Node::finish` once per level, with a plain loop so that a level
    /// costs two frames (ADR-011, D6).
    pub(crate) fn finish(self) -> Table {
        let Builder { nodes, index, .. } = self;
        drop(index);
        let mut members = Vec::with_capacity(nodes.len());
        for (key, node) in nodes {
            members.push((key.into_owned(), node.finish()));
        }
        Table::from_distinct(members)
    }
}

impl Node<'_> {
    fn finish(self) -> Value {
        match self {
            Node::Frozen(v) => v,
            Node::Table(b) => Value::Table(b.finish()),
            Node::Tables(tables) => {
                let mut items = Vec::with_capacity(tables.len());
                for b in tables {
                    items.push(Value::Table(b.finish()));
                }
                Value::Array(items)
            }
        }
    }
}

/// A document: the root table and the table the last header selected.
pub(crate) struct Document<'a> {
    root: Builder<'a>,
    /// The member slots from the root to the current table; a slot that
    /// holds an array of tables stands for its last element.
    current: Vec<usize>,
    /// The depth of the current table, the root being 1 (ADR-011, D6).
    current_depth: usize,
}

impl<'a> Document<'a> {
    pub(crate) fn new() -> Document<'a> {
        Document {
            root: Builder::new(Origin::Header),
            current: Vec::new(),
            current_depth: 1,
        }
    }

    pub(crate) fn current_depth(&self) -> usize {
        self.current_depth
    }

    /// The table that key-value pairs go to.
    pub(crate) fn current_table(&mut self) -> Result<&mut Builder<'a>, Fail> {
        let mut t = &mut self.root;
        for &slot in &self.current {
            t = match t.nodes.get_mut(slot) {
                Some((_, Node::Table(b))) => b,
                Some((_, Node::Tables(items))) => match items.last_mut() {
                    Some(b) => b,
                    None => return Err((ErrorKind::NotExtensible, 0)),
                },
                _ => return Err((ErrorKind::NotExtensible, 0)),
            };
        }
        Ok(t)
    }

    /// `[k1. ... .kn]`, or `[[k1. ... .kn]]` if `array`: walks from the
    /// root through tables and the last elements of arrays of tables,
    /// creating implicit tables, and makes the final table current. Every
    /// table or array it creates counts toward `max_depth`.
    pub(crate) fn header(
        &mut self,
        keys: Vec<Segment<'a>>,
        array: bool,
        max_depth: usize,
    ) -> Result<(), Fail> {
        let mut path = Vec::with_capacity(keys.len());
        let mut depth = 1;
        let mut t = &mut self.root;
        let mut keys = keys.into_iter().peekable();
        while let Some((key, at)) = keys.next() {
            let last = keys.peek().is_none();
            let slot = match t.find(&key) {
                None => {
                    let node = if last && array {
                        if depth + 2 > max_depth {
                            return Err((ErrorKind::TooDeep, at));
                        }
                        Node::Tables(vec![Builder::new(Origin::Header)])
                    } else {
                        if depth + 1 > max_depth {
                            return Err((ErrorKind::TooDeep, at));
                        }
                        let origin = if last {
                            Origin::Header
                        } else {
                            Origin::Implicit
                        };
                        Node::Table(Box::new(Builder::new(origin)))
                    };
                    t.push(key, node)
                }
                Some(slot) => {
                    match (t.nodes.get_mut(slot).map(|(_, node)| node), last) {
                        (Some(Node::Table(_) | Node::Tables(_)), false) => {}
                        (Some(Node::Table(b)), true) if !array && b.origin == Origin::Implicit => {
                            b.origin = Origin::Header;
                        }
                        (Some(Node::Tables(items)), true) if array => {
                            items.push(Builder::new(Origin::Header));
                        }
                        (_, false) => return Err((ErrorKind::NotExtensible, at)),
                        (_, true) => return Err((ErrorKind::DuplicateTable, at)),
                    }
                    slot
                }
            };
            path.push(slot);
            t = match t.nodes.get_mut(slot) {
                Some((_, Node::Table(b))) => {
                    depth += 1;
                    b
                }
                Some((_, Node::Tables(items))) => {
                    depth += 2;
                    match items.last_mut() {
                        Some(b) => b,
                        None => return Err((ErrorKind::NotExtensible, at)),
                    }
                }
                _ => return Err((ErrorKind::NotExtensible, at)),
            };
        }
        self.current = path;
        self.current_depth = depth;
        Ok(())
    }

    pub(crate) fn finish(self) -> Table {
        self.root.finish()
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{Builder, Node};

    /// The per-table costs of ADR-011, D5 start from these sizes.
    #[test]
    fn builder_sizes_pinned() {
        assert_eq!(size_of::<Builder<'_>>(), 56);
        assert_eq!(size_of::<Node<'_>>(), 32);
        assert_eq!(size_of::<(Cow<'_, str>, Node<'_>)>(), 56);
    }
}
