macro_rules! redirect {
    ($($a:tt)*) => {
        #[$($a)*]
        pub mod clock;
    };
}
redirect!(path = "clock.rs");
