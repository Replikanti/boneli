/// The Pointer trait, never named.
pub mod g {
    use core::fmt::*;
    trait Marker {}
    impl Marker for u8 {}
    /// Shows its value.
    pub struct Show<'a>(pub &'a u8);
    impl Display for Show<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            let r: &dyn Marker = self.0;
            r.fmt(f)
        }
    }
}
