extern crate lalrpop;

// Rerun if any of these files change:
#[allow(dead_code)]
const SOURCE: [ &'static str; 1 ]
    = [ include_str!("src/grammar.lalrpop"),
      ];

fn main() {
    lalrpop::process_root().unwrap();
}
