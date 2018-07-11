extern crate lalrpop;

// Rerun if any of these files change:
#[allow(dead_code)]
const SOURCE: &'static str
    = include_str!("src/message/grammar.lalrpop");

fn main() {
    lalrpop::process_root().unwrap();
}
