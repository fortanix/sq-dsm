extern crate lalrpop;

// Rerun if any of these files change:
#[allow(dead_code)]
const SOURCE: [ &'static str; 2 ]
    = [ include_str!("src/message/grammar.lalrpop"),
        include_str!("src/tpk/grammar.lalrpop"),
      ];

fn main() {
    lalrpop::process_root().unwrap();
}
