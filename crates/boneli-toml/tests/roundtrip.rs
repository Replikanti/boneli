//! Generated values survive every syntactic form of the test writer:
//! headers, `[[ ]]`, dotted keys and inline values, every string form,
//! quoted and bare keys, integer spellings and CRLF (ADR-011, D10).

mod common;

use boneli_toml::{MAX_DEPTH, Table, Value};
use common::{Rng, SPECIAL_INTEGERS, assert_round_trips, deepest_tables, depth, gen_table, styles};

#[test]
fn generated_values_round_trip() {
    let mut rng = Rng::new(0x746f_6d6c);
    let mut deepest = 0;
    for i in 0..10_000 {
        let t = gen_table(&mut rng, 3);
        deepest = deepest.max(depth(&t));
        assert_round_trips(&t, &format!("value {i}"));
    }
    assert!(deepest >= 4, "deepest {deepest}");
    assert_eq!(styles().len(), 15);
}

#[test]
fn deepest_values_round_trip() {
    for (i, t) in deepest_tables().iter().enumerate() {
        assert_eq!(depth(t), MAX_DEPTH, "chain {i}");
        assert_round_trips(t, &format!("chain {i}"));
    }
}

#[test]
fn edge_scalars_round_trip() {
    let mut t = Table::new();
    for (i, n) in SPECIAL_INTEGERS.iter().enumerate() {
        t.insert(format!("i{i}"), Value::Integer(*n));
    }
    let every_control: String = (0u8..0x20).map(char::from).chain(['\u{7f}']).collect();
    for (i, s) in [
        "",
        "\"",
        "\"\"",
        "\"\"\"",
        "\"\"\"\"\"\"\"",
        "'",
        "''",
        "'''",
        "''''''",
        "\r\n",
        "\n",
        "\r",
        "\\",
        "\\\n",
        "a\\",
        every_control.as_str(),
        "\u{feff}\u{200b}\u{10ffff}",
    ]
    .iter()
    .enumerate()
    {
        t.insert(format!("s{i}"), Value::String((*s).to_owned()));
        t.insert((*s).to_owned(), Value::Boolean(i.is_multiple_of(2)));
    }
    assert_round_trips(&t, "edge scalars");
}
