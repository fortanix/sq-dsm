//! Maps various errors to status codes.

use failure;
use std::io;

extern crate sequoia_openpgp as openpgp;

/// Complex errors.
///
/// This wraps [`failure::Error`]s.
///
/// [`failure::Error`]: https://docs.rs/failure/0.1.5/failure/struct.Error.html
#[::ffi_wrapper_type(prefix = "pgp_", derive = "Display")]
pub struct Error(failure::Error);

/// Returns the error status code.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_error_status(error: *const Error)
                                       -> Status {
    error.ref_raw().into()
}

/// XXX: Reorder and name-space before release.
#[derive(PartialEq, Debug)]
#[repr(C)]
pub enum Status {
    /// The operation was successful.
    Success = 0,

    /// An unknown error occurred.
    UnknownError = -1,

    /// The network policy was violated by the given action.
    NetworkPolicyViolation = -2,

    /// An IO error occurred.
    IoError = -3,

    /// A given argument is invalid.
    InvalidArgument = -15,

    /// The requested operation is invalid.
    InvalidOperation = -4,

    /// The packet is malformed.
    MalformedPacket = -5,

    /// Unsupported hash algorithm.
    UnsupportedHashAlgorithm = -9,

    /// Unsupported public key algorithm.
    UnsupportedPublicKeyAlgorithm = -18,

    /// Unsupported elliptic curve.
    UnsupportedEllipticCurve = -21,

    /// Unsupported symmetric algorithm.
    UnsupportedSymmetricAlgorithm = -10,

    /// Unsupported AEAD algorithm.
    UnsupportedAEADAlgorithm = -26,

    /// Unsupport signature type.
    UnsupportedSignatureType = -20,

    /// Invalid password.
    InvalidPassword = -11,

    /// Invalid session key.
    InvalidSessionKey = -12,

    /// Missing session key.
    MissingSessionKey = -27,

    /// Malformed TPK.
    MalformedTPK = -13,

    // XXX: -14 was UserIDNotFound.

    // XXX: Skipping InvalidArgument = -15.

    /// Malformed MPI.
    MalformedMPI = -16,

    // XXX: Skipping UnknownPublicKeyAlgorithm = -17.
    // XXX: Skipping UnsupportedPublicKeyAlgorithm = -18

    /// Bad signature.
    BadSignature = -19,

    /// Message has been manipulated.
    ManipulatedMessage = -25,

    // XXX: Skipping UnsupportedSignatureType = -20
    // XXX: Skipping UnsupportedEllipticCurve = -21

    /// Malformed message.
    MalformedMessage = -22,

    /// Index out of range.
    IndexOutOfRange = -23,

    /// TPK not supported.
    UnsupportedTPK = -24,

    // XXX: Skipping ManipulatedMessage = -25
    // XXX: Skipping UnsupportedAEADAlgorithm = -26
    // XXX: Skipping MissingSessionKey = -27
}

impl<'a> From<&'a failure::Error> for Status {
    fn from(e: &'a failure::Error) -> Self {
        if let Some(e) = e.downcast_ref::<openpgp::Error>() {
            return match e {
                &openpgp::Error::InvalidArgument(_) =>
                    Status::InvalidArgument,
                &openpgp::Error::InvalidOperation(_) =>
                    Status::InvalidOperation,
                &openpgp::Error::MalformedPacket(_) =>
                    Status::MalformedPacket,
                &openpgp::Error::UnsupportedHashAlgorithm(_) =>
                    Status::UnsupportedHashAlgorithm,
                &openpgp::Error::UnsupportedPublicKeyAlgorithm(_) =>
                    Status::UnsupportedPublicKeyAlgorithm,
                &openpgp::Error::UnsupportedEllipticCurve(_) =>
                    Status::UnsupportedEllipticCurve,
                &openpgp::Error::UnsupportedSymmetricAlgorithm(_) =>
                    Status::UnsupportedSymmetricAlgorithm,
                &openpgp::Error::UnsupportedAEADAlgorithm(_) =>
                    Status::UnsupportedAEADAlgorithm,
                &openpgp::Error::UnsupportedSignatureType(_) =>
                    Status::UnsupportedSignatureType,
                &openpgp::Error::InvalidPassword =>
                    Status::InvalidPassword,
                &openpgp::Error::InvalidSessionKey(_) =>
                    Status::InvalidSessionKey,
                &openpgp::Error::MissingSessionKey(_) =>
                    Status::MissingSessionKey,
                &openpgp::Error::MalformedMPI(_) =>
                    Status::MalformedMPI,
                &openpgp::Error::BadSignature(_) =>
                    Status::BadSignature,
                &openpgp::Error::ManipulatedMessage =>
                    Status::ManipulatedMessage,
                &openpgp::Error::MalformedMessage(_) =>
                    Status::MalformedMessage,
                &openpgp::Error::MalformedTPK(_) =>
                    Status::MalformedTPK,
                &openpgp::Error::IndexOutOfRange =>
                    Status::IndexOutOfRange,
                &openpgp::Error::UnsupportedTPK(_) =>
                    Status::UnsupportedTPK,
            }
        }

        if let Some(_) = e.downcast_ref::<io::Error>() {
            return Status::IoError;
        }

        eprintln!("ffi: Error not converted: {}", e);
        Status::UnknownError
    }
}
