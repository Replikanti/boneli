//! Table definition rules: which header, dotted key or inline value may
//! create, define or extend which table, and the error each violation is
//! (ADR-011, D3 and D4). The expected outcomes agree with tomllib.

mod common;

use boneli_toml::{ErrorKind, Value};
use common::{err, kind_at, lookup, ok};

fn keys_at(input: &str, path: &[&str]) -> Vec<String> {
    let t = ok(input);
    let table = if path.is_empty() {
        &t
    } else {
        lookup(&t, path).and_then(Value::as_table).expect("a table")
    };
    table.keys().map(str::to_owned).collect()
}

#[test]
fn key_spellings_are_one_key() {
    for second in ["a", "\"a\"", "'a'", "\"\\u0061\"", "\"\\U00000061\""] {
        let e = err(&format!("a = 1\n{second} = 2"));
        assert_eq!(
            (e.kind(), e.offset()),
            (ErrorKind::DuplicateKey, 6),
            "{second}"
        );
        assert_eq!((e.line(), e.column()), (2, 1), "{second}");
    }
    assert_eq!(
        kind_at("a = {b = 1, 'b' = 2}"),
        (ErrorKind::DuplicateKey, 12)
    );
    assert_eq!(
        kind_at("x.a = 1\nx.\"a\" = 2"),
        (ErrorKind::DuplicateKey, 10)
    );
}

#[test]
fn header_spellings_are_one_table() {
    for (second, at) in [
        ("[ a ]", 6),
        ("[\"a\"]", 5),
        ("['a']", 5),
        ("[\t\"\\u0061\"\t]", 6),
    ] {
        assert_eq!(
            kind_at(&format!("[a]\n{second}")),
            (ErrorKind::DuplicateTable, at),
            "{second}"
        );
    }
    assert_eq!(
        kind_at("[a . b]\n['a'.\"b\"]"),
        (ErrorKind::DuplicateTable, 13)
    );
}

#[test]
fn keys_compare_bytewise() {
    let t =
        ok("\"\\u00e9\" = 1\n\"e\\u0301\" = 2\n\"lints\" = 3\n\"lints\\u200B\" = 4\nA = 5\na = 6");
    assert_eq!(t.len(), 6);
    assert_eq!(t.get("\u{e9}"), Some(&Value::Integer(1)));
    assert_eq!(t.get("e\u{301}"), Some(&Value::Integer(2)));
    assert_eq!(t.get("lints\u{200b}"), Some(&Value::Integer(4)));
    assert_eq!(t.get("A"), Some(&Value::Integer(5)));
}

#[test]
fn table_order_is_first_creation() {
    assert_eq!(keys_at("[a.b]\n[a]\nx = 1", &["a"]), ["b", "x"]);
    assert_eq!(
        keys_at("z = 1\n[y]\n[x]\n[w.v]\n[y.u]", &[]),
        ["z", "y", "x", "w"]
    );
    assert_eq!(keys_at("b.y = 1\na = 2\nb.x = 3", &["b"]), ["y", "x"]);
}

#[test]
fn super_table_after_sub_table() {
    let t = ok("[a.b]\nc = 1\n[a]\nd = 2");
    assert_eq!(lookup(&t, &["a", "b", "c"]), Some(&Value::Integer(1)));
    assert_eq!(lookup(&t, &["a", "d"]), Some(&Value::Integer(2)));
    assert_eq!(kind_at("[a]\n[a]"), (ErrorKind::DuplicateTable, 5));
    assert_eq!(kind_at("[a.b]\n[a]\n[a]"), (ErrorKind::DuplicateTable, 11));
    assert_eq!(kind_at("[a.b]\n[a.b]"), (ErrorKind::DuplicateTable, 9));
}

#[test]
fn dotted_tables_take_sub_headers_only() {
    assert_eq!(kind_at("a.b = 1\n[a]"), (ErrorKind::DuplicateTable, 9));
    assert_eq!(
        kind_at("[a]\nb.c = 1\n[a.b]"),
        (ErrorKind::DuplicateTable, 15)
    );
    let t = ok("[a]\nb.c = 1\n[a.b.d]\ne = 2");
    assert_eq!(lookup(&t, &["a", "b", "c"]), Some(&Value::Integer(1)));
    assert_eq!(lookup(&t, &["a", "b", "d", "e"]), Some(&Value::Integer(2)));
    // A later dotted key in the same table extends it.
    let t = ok("[a]\nb.c = 1\nb.d = 2");
    assert_eq!(keys_at("[a]\nb.c = 1\nb.d = 2", &["a", "b"]), ["c", "d"]);
    assert_eq!(t.len(), 1);
}

#[test]
fn dotted_key_through_implicit_table_defines_it() {
    let t = ok("[a.b.c]\n[a]\nb.d = 1");
    assert_eq!(keys_at("[a.b.c]\n[a]\nb.d = 1", &["a", "b"]), ["c", "d"]);
    assert_eq!(lookup(&t, &["a", "b", "d"]), Some(&Value::Integer(1)));
    assert_eq!(
        kind_at("[a.b.c]\n[a]\nb.d = 1\n[a.b]"),
        (ErrorKind::DuplicateTable, 23)
    );
}

#[test]
fn dotted_keys_cannot_extend_headers_or_arrays() {
    assert_eq!(
        kind_at("[a.b.c]\n[a]\nb.c.t = 1"),
        (ErrorKind::NotExtensible, 14)
    );
    assert_eq!(
        kind_at("[[a.b]]\n[a]\nb.y = 2"),
        (ErrorKind::NotExtensible, 12)
    );
}

#[test]
fn inline_tables_are_frozen() {
    assert_eq!(
        kind_at("a = {b = 1}\na.c = 2"),
        (ErrorKind::NotExtensible, 12)
    );
    assert_eq!(
        kind_at("a = {b = 1}\n[a.c]"),
        (ErrorKind::NotExtensible, 13)
    );
    assert_eq!(kind_at("a = {b = 1}\n[a]"), (ErrorKind::DuplicateTable, 13));
    assert_eq!(
        kind_at("a = {b = 1}\n[[a]]"),
        (ErrorKind::DuplicateTable, 14)
    );
    assert_eq!(
        kind_at("a = {b = {}}\n[a.b.d]"),
        (ErrorKind::NotExtensible, 14)
    );
    assert_eq!(
        kind_at("a = {b = 1, b.c = 2}"),
        (ErrorKind::NotExtensible, 12)
    );
    assert_eq!(
        kind_at("a = {b.c = 1, b = 2}"),
        (ErrorKind::DuplicateKey, 14)
    );
    let t = ok("a = {b.c = 1, b.d = 2}");
    assert_eq!(keys_at("a = {b.c = 1, b.d = 2}", &["a", "b"]), ["c", "d"]);
    assert_eq!(t.len(), 1);
}

#[test]
fn static_arrays_are_frozen() {
    assert_eq!(kind_at("a = []\n[[a]]"), (ErrorKind::DuplicateTable, 9));
    assert_eq!(
        kind_at("a = [{b = 1}]\n[a.c]"),
        (ErrorKind::NotExtensible, 15)
    );
    assert_eq!(
        kind_at("a = [{b = 1}]\n[a]"),
        (ErrorKind::DuplicateTable, 15)
    );
    assert_eq!(
        kind_at("a = [{b = 1}]\na.c = 1"),
        (ErrorKind::NotExtensible, 14)
    );
}

#[test]
fn array_of_tables_rules() {
    assert_eq!(kind_at("[[x]]\n[x]"), (ErrorKind::DuplicateTable, 7));
    assert_eq!(kind_at("[x]\n[[x]]"), (ErrorKind::DuplicateTable, 6));
    assert_eq!(kind_at("[[a.b]]\n[[a]]"), (ErrorKind::DuplicateTable, 10));
    let t = ok("[[a.b]]\n[a]\nc = 1");
    assert_eq!(lookup(&t, &["a", "c"]), Some(&Value::Integer(1)));
    let t = ok("[[x]]\n[x.y]\nz=1\n[[x]]\n[x.y]\nz=2");
    let items = t.get("x").and_then(Value::as_array).expect("array");
    assert_eq!(items.len(), 2);
    for (item, z) in items.iter().zip([1, 2]) {
        let y = item
            .as_table()
            .and_then(|t| t.get("y"))
            .and_then(Value::as_table);
        assert_eq!(y.and_then(|y| y.get("z")), Some(&Value::Integer(z)));
    }
    // Dotted keys inside an element, and nested arrays of tables.
    let t = ok("[[a]]\nb.c = 1\n[[a.d]]\ne = 1\n[[a.d]]\n[[a]]\nb.c = 2");
    let items = t.get("a").and_then(Value::as_array).expect("array");
    assert_eq!(items.len(), 2);
    let first = items[0].as_table().expect("table");
    assert_eq!(
        first.get("d").and_then(Value::as_array).map(<[Value]>::len),
        Some(2)
    );
    assert_eq!(
        kind_at("[[a]]\nb = 1\n[[a]]\nb = 1\nb = 2"),
        (ErrorKind::DuplicateKey, 24)
    );
}

#[test]
fn scalar_and_table_overwrites() {
    assert_eq!(kind_at("a = 1\na.b = 2"), (ErrorKind::NotExtensible, 6));
    assert_eq!(kind_at("a.b = 1\na = {}"), (ErrorKind::DuplicateKey, 8));
    assert_eq!(kind_at("a = 1\n[a]"), (ErrorKind::DuplicateTable, 7));
    assert_eq!(kind_at("a = 1\n[a.b]"), (ErrorKind::NotExtensible, 7));
    assert_eq!(
        kind_at("[a]\n[b]\n[a.c]\nd = 1\n[a]"),
        (ErrorKind::DuplicateTable, 21)
    );
    assert_eq!(
        kind_at("[a]\nb = 1\n[a.b]"),
        (ErrorKind::DuplicateTable, 13)
    );
}

#[test]
fn keys_after_header_belong_to_it() {
    let t = ok("[a]\nb = 1");
    assert_eq!(t.keys().collect::<Vec<_>>(), ["a"]);
    assert_eq!(lookup(&t, &["a", "b"]), Some(&Value::Integer(1)));
    let t = ok("x = 0\n[a.b]\nc = 1\n[d]\ne = 2");
    assert_eq!(t.keys().collect::<Vec<_>>(), ["x", "a", "d"]);
    assert_eq!(lookup(&t, &["a", "b", "c"]), Some(&Value::Integer(1)));
    assert_eq!(lookup(&t, &["d", "e"]), Some(&Value::Integer(2)));
}
