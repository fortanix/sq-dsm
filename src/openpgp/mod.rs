// Hack so that the file doesn't have to be named mod.rs.
// Unfortunately, it seems that putting 'pub mod xxx' declarations in
// an included file confuses rust (it looks for the module in the
// wrong place).  Hence, that here as well.

pub mod armor;
pub mod parse;
pub mod tpk;
pub mod types;

include!("openpgp.rs");
