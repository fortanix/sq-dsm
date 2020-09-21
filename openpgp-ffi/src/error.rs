//! Maps various errors to status codes.

use std::io;
use libc::c_char;

use sequoia_openpgp as openpgp;

use crate::MoveIntoRaw;
use crate::RefRaw;

/// Complex errors.
///
/// This wraps [`anyhow::Error`]s.
///
/// [`anyhow::Error`]: https://docs.rs/failure/0.1.5/failure/struct.Error.html
#[crate::ffi_wrapper_type(prefix = "pgp_", derive = "Display")]
pub struct Error(anyhow::Error);

impl<T> From<anyhow::Result<T>> for Status {
    fn from(f: anyhow::Result<T>) -> crate::error::Status {
        match f {
            Ok(_) =>  crate::error::Status::Success,
            Err(e) => crate::error::Status::from(&e),
        }
    }
}

impl crate::MoveResultIntoRaw<crate::error::Status> for ::anyhow::Result<()>
{
    fn move_into_raw(self, errp: Option<&mut *mut crate::error::Error>)
                     -> crate::error::Status {
        match self {
            Ok(_) => crate::error::Status::Success,
            Err(e) => {
                let status = crate::error::Status::from(&e);
                if let Some(errp) = errp {
                    *errp = e.move_into_raw();
                }
                status
            },
        }
    }
}

/// Returns the error status code.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_error_status(error: *const Error)
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

    /// Packet size exceeds the configured limit.
    PacketTooLarge = -29,

    /// Unsupported packet type.
    UnsupportedPacketType = -14,

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

    /// Unsupported Compression algorithm.
    UnsupportedCompressionAlgorithm = -28,

    /// Unsupported signature type.
    UnsupportedSignatureType = -20,

    /// Invalid password.
    InvalidPassword = -11,

    /// Invalid session key.
    InvalidSessionKey = -12,

    /// Missing session key.
    MissingSessionKey = -27,

    /// Malformed Cert.
    MalformedCert = -13,

    // XXX: Skipping UnsupportedPacketType = -14.

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

    /// Cert not supported.
    UnsupportedCert = -24,

    // XXX: Skipping ManipulatedMessage = -25
    // XXX: Skipping UnsupportedAEADAlgorithm = -26
    // XXX: Skipping MissingSessionKey = -27
    // XXX: Skipping UnsupportedCompressionAlgorithm = -28
    // XXX: Skipping PacketTooLarge = -29

    /// Expired.
    Expired = -30,

    /// Not yet live.
    NotYetLive = -31,

    /// No binding signature.
    NoBindingSignature = -32,

    /// Invalid key.
    InvalidKey = -33,

    /// Policy violation.
    PolicyViolation = -34,
}

/// Returns the error message.
///
/// The returned value must *not* be freed.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_status_to_string(status: Status) -> *const c_char {
    use crate::error::Status::*;

    match status {
        Success => "Success\x00",
        UnknownError => "An unknown error occurred\x00",
        NetworkPolicyViolation =>
            "The network policy was violated by the given action\x00",
        IoError => "An IO error occurred\x00",
        InvalidArgument => "A given argument is invalid\x00",
        InvalidOperation => "The requested operation is invalid\x00",
        MalformedPacket => "The packet is malformed\x00",
        PacketTooLarge => "Packet size exceeds the configured limit\x00",
        UnsupportedPacketType => "Unsupported packet type\x00",
        UnsupportedHashAlgorithm => "Unsupported hash algorithm\x00",
        UnsupportedPublicKeyAlgorithm =>
            "Unsupported public key algorithm\x00",
        UnsupportedEllipticCurve => "Unsupported elliptic curve\x00",
        UnsupportedSymmetricAlgorithm =>
            "Unsupported symmetric algorithm\x00",
        UnsupportedAEADAlgorithm => "Unsupported AEAD algorithm\x00",
        UnsupportedCompressionAlgorithm =>
            "Unsupported compression algorithm\x00",
        UnsupportedSignatureType => "Unsupported signature type\x00",
        InvalidPassword => "Invalid password\x00",
        InvalidSessionKey => "Invalid session key\x00",
        MissingSessionKey => "Missing session key\x00",
        MalformedCert => "Malformed Cert\x00",
        MalformedMPI => "Malformed MPI\x00",
        BadSignature => "Bad signature\x00",
        ManipulatedMessage => "Message has been manipulated\x00",
        MalformedMessage => "Malformed message\x00",
        IndexOutOfRange => "Index out of range\x00",
        UnsupportedCert => "Cert not supported\x00",
        Expired => "Expired\x00",
        NotYetLive => "Not yet live\x00",
        NoBindingSignature => "No binding signature\x00",
        InvalidKey => "Invalid key\x00",
        PolicyViolation => "Policy violation\x00",
    }.as_bytes().as_ptr() as *const c_char
}

impl<'a> From<&'a anyhow::Error> for Status {
    fn from(e: &'a anyhow::Error) -> Self {
        if let Some(e) = e.downcast_ref::<openpgp::Error>() {
            return match e {
                &openpgp::Error::InvalidArgument(_) =>
                    Status::InvalidArgument,
                &openpgp::Error::InvalidOperation(_) =>
                    Status::InvalidOperation,
                &openpgp::Error::MalformedPacket(_) =>
                    Status::MalformedPacket,
                &openpgp::Error::PacketTooLarge(_, _, _) =>
                    Status::PacketTooLarge,
                &openpgp::Error::UnsupportedPacketType(_) =>
                    Status::UnsupportedPacketType,
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
                &openpgp::Error::UnsupportedCompressionAlgorithm(_) =>
                    Status::UnsupportedCompressionAlgorithm,
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
                &openpgp::Error::MalformedCert(_) =>
                    Status::MalformedCert,
                &openpgp::Error::IndexOutOfRange =>
                    Status::IndexOutOfRange,
                &openpgp::Error::UnsupportedCert(_) =>
                    Status::UnsupportedCert,
                &openpgp::Error::Expired(_) =>
                    Status::Expired,
                &openpgp::Error::NotYetLive(_) =>
                    Status::NotYetLive,
                &openpgp::Error::NoBindingSignature(_) =>
                    Status::NoBindingSignature,
                &openpgp::Error::InvalidKey(_) =>
                    Status::InvalidKey,
                &openpgp::Error::PolicyViolation(_, _) =>
                    Status::PolicyViolation,
                &_ => unreachable!(), // openpgp::Error is non-exhaustive.
            }
        }

        if let Some(_) = e.downcast_ref::<io::Error>() {
            return Status::IoError;
        }

        eprintln!("ffi: Error not converted: {}", e);
        Status::UnknownError
    }
}
