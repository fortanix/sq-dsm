//! The revocation status.

use libc::c_int;

extern crate sequoia_openpgp as openpgp;

use RefRaw;

/// The revocation status.
#[::ffi_wrapper_type(prefix = "pgp_", derive = "Debug")]
pub struct RevocationStatus<'a>(openpgp::RevocationStatus<'a>);

fn revocation_status_to_int(rs: &openpgp::RevocationStatus) -> c_int {
    use self::openpgp::RevocationStatus::*;
    match rs {
        Revoked(_) => 0,
        CouldBe(_) => 1,
        NotAsFarAsWeKnow => 2,
    }
}

/// Returns the TPK's revocation status variant.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_revocation_status_variant(
    rs: *const RevocationStatus)
    -> c_int
{
    revocation_status_to_int(rs.ref_raw())
}

