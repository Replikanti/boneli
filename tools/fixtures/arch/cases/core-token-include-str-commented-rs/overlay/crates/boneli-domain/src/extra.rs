/// Address as text.
pub fn f(x: &u8, w: &mut dyn core::fmt::Write) -> core::fmt::Result {
    write!(w, include_str!("fmt.rs"), x)
}
