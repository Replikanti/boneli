macro_rules! call {
    ($m:ident) => {
        $m!("clock.rs");
    };
}
call!(include);
