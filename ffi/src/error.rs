/// Maps various errors to status codes.

use failure;
use std::io;
use std::ffi::CString;
use libc::c_char;

extern crate openpgp;
use sequoia_core as core;

/// Frees an error.
#[no_mangle]
pub extern "system" fn sq_error_free(error: *mut failure::Error) {
    if ! error.is_null() {
        unsafe { drop(Box::from_raw(error)) }
    }
}

/// Returns the error message.
///
/// The returned value must be freed with `sq_string_free`.
#[no_mangle]
pub extern "system" fn sq_error_string(error: Option<&failure::Error>)
                                       -> *mut c_char {
    let error = error.expect("Error is NULL");
    CString::new(format!("{}", error))
        .map(|s| s.into_raw())
        .unwrap_or(CString::new("Failed to convert error into string")
                   .unwrap().into_raw())
}

/// Returns the error status code.
#[no_mangle]
pub extern "system" fn sq_error_status(error: Option<&failure::Error>)
                                       -> Status {
    let error = error.expect("Error is NULL");
    error.into()
}

/// XXX: Reorder and name-space before release.
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

    /// Unknown packet type.
    UnknownPacketTag = -6,

    /// Unknown hash algorithm.
    UnknownHashAlgorithm = -7,

    /// Unknown public key algorithm.
    UnknownPublicKeyAlgorithm = -17,

    /// Unknown symmetric algorithm.
    UnknownSymmetricAlgorithm = -8,

    /// Unsupported hash algorithm.
    UnsupportedHashAlgorithm = -9,

    /// Unsupported public key algorithm.
    UnsupportedPublicKeyAlgorithm = -18,

    /// Unsupported elliptic curve.
    UnsupportedEllipticCurve = -21,

    /// Unsupported symmetric algorithm.
    UnsupportedSymmetricAlgorithm = -10,

    /// Unsupport signature type.
    UnsupportedSignatureType = -20,

    /// Invalid password.
    InvalidPassword = -11,

    /// Invalid session key.
    InvalidSessionKey = -12,

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

    // XXX: Skipping UnsupportedSignatureType = -20
    // XXX: Skipping UnsupportedEllipticCurve = -21

    MalformedMessage = -22,

    IndexOutOfRange = -23,
}

impl<'a> From<&'a failure::Error> for Status {
    fn from(e: &'a failure::Error) -> Self {
        if let Some(e) = e.downcast_ref::<core::Error>() {
            return match e {
                &core::Error::NetworkPolicyViolation(_) =>
                    Status::NetworkPolicyViolation,
                &core::Error::IoError(_) =>
                    Status::IoError,
            }
        }

        if let Some(e) = e.downcast_ref::<openpgp::Error>() {
            return match e {
                &openpgp::Error::InvalidArgument(_) =>
                    Status::InvalidArgument,
                &openpgp::Error::InvalidOperation(_) =>
                    Status::InvalidOperation,
                &openpgp::Error::MalformedPacket(_) =>
                    Status::MalformedPacket,
                &openpgp::Error::UnknownPacketTag(_) =>
                    Status::UnknownPacketTag,
                &openpgp::Error::UnknownHashAlgorithm(_) =>
                    Status::UnknownHashAlgorithm,
                &openpgp::Error::UnknownPublicKeyAlgorithm(_) =>
                    Status::UnknownPublicKeyAlgorithm,
                &openpgp::Error::UnknownSymmetricAlgorithm(_) =>
                    Status::UnknownSymmetricAlgorithm,
                &openpgp::Error::UnsupportedHashAlgorithm(_) =>
                    Status::UnsupportedHashAlgorithm,
                &openpgp::Error::UnsupportedPublicKeyAlgorithm(_) =>
                    Status::UnsupportedPublicKeyAlgorithm,
                &openpgp::Error::UnsupportedEllipticCurve(_) =>
                    Status::UnsupportedEllipticCurve,
                &openpgp::Error::UnsupportedSymmetricAlgorithm(_) =>
                    Status::UnsupportedSymmetricAlgorithm,
                &openpgp::Error::UnsupportedSignatureType(_) =>
                    Status::UnsupportedSignatureType,
                &openpgp::Error::InvalidPassword =>
                    Status::InvalidPassword,
                &openpgp::Error::InvalidSessionKey(_) =>
                    Status::InvalidSessionKey,
                &openpgp::Error::MalformedMPI(_) =>
                    Status::MalformedMPI,
                &openpgp::Error::BadSignature(_) =>
                    Status::BadSignature,
                &openpgp::Error::MalformedMessage(_) =>
                    Status::MalformedMessage,
                &openpgp::Error::MalformedTPK(_) =>
                    Status::MalformedTPK,
                &openpgp::Error::IndexOutOfRange =>
                    Status::IndexOutOfRange,
            }
        }

        if let Some(_) = e.downcast_ref::<io::Error>() {
            return Status::IoError;
        }

        eprintln!("ffi: Error not converted: {}", e);
        Status::UnknownError
    }
}
