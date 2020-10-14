//! The revocation status.

use libc::c_int;

use sequoia_openpgp as openpgp;

use crate::RefRaw;

/// The revocation status.
#[crate::ffi_wrapper_type(prefix = "pgp_", derive = "Debug")]
pub struct RevocationStatus<'a>(openpgp::types::RevocationStatus<'a>);

fn revocation_status_to_int(rs: &openpgp::types::RevocationStatus) -> c_int {
    use self::openpgp::types::RevocationStatus::*;
    match rs {
        Revoked(_) => 0,
        CouldBe(_) => 1,
        NotAsFarAsWeKnow => 2,
    }
}

/// Returns the Cert's revocation status variant.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_revocation_status_variant(
    rs: *const RevocationStatus)
    -> c_int
{
    revocation_status_to_int(rs.ref_raw())
}

