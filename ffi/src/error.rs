//! Maps various errors to status codes.

use std::io;

use sequoia_openpgp as openpgp;
use sequoia_net as net;
pub use crate::openpgp::error::Status;

pub(crate) use crate::openpgp::error::Error;

trait FromSequoiaError<'a> {
    fn from_sequoia_error(_: &'a anyhow::Error) -> Status;
}

impl<'a> FromSequoiaError<'a> for Status {
    fn from_sequoia_error(e: &'a anyhow::Error) -> Self {
        if let Some(e) = e.downcast_ref::<net::Error>() {
            return match e {
                net::Error::PolicyViolation(_) =>
                    Status::NetworkPolicyViolation,
                e => {
                    // XXX
                    eprintln!("ffi: net error not converted: {}", e);
                    Status::UnknownError
                },
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
                // openpgp::Error is non_exhaustive, match on &_ to handle
                // future additions.
                &_ => Status::UnknownError
            }
        }

        if let Some(_) = e.downcast_ref::<io::Error>() {
            return Status::IoError;
        }

        eprintln!("ffi: Error not converted: {}", e);
        Status::UnknownError
    }
}
