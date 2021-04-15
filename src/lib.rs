use std::marker::PhantomData;

use sdkms::{
    api_model::{SobjectDescriptor},
    SdkmsClient,
    Error as SdkmsError,
};

use mbedtls::{
    Error as MbedtlsError,
    pk::Pk,
};

use sequoia_openpgp::{
    packet::{
        key::{Key4, PublicParts, UnspecifiedRole},
        Key,
    },
};

use anyhow::Error as SequoiaError;

#[derive(Debug)]
pub enum Error {
    Sdkms(SdkmsError),
    Sequoia(SequoiaError),
    Mbedtls(MbedtlsError),
    SdkmsBadResponse,
}

type Result<T> = core::result::Result<T, Error>;

pub mod signer;

pub mod decryptor;

trait Operation {}

/// The Agent can access a single private key, and can perform a single
/// operation. It either signs or decrypts. Using the same key for signature and
/// decryption is disallowed here; see e.g.
/// https://security.stackexchange.com/questions/101036
struct Agent<O: Operation> {
    key_name: &'static str,
    public_key: Key<PublicParts, UnspecifiedRole>,
    http_client: SdkmsClient,
    phantom: PhantomData<O>,
}

impl<O: Operation> Agent<O> {
    const DEFAULT_API_ENDPOINT: &'static str = "https://sdkms.test.fortanix.com";

    pub(crate) fn new(
        api_endpoint: Option<String>,
        api_key: String,
        key_name: &'static str,
    ) -> Result<Self> {
        let endpoint = match api_endpoint {
            Some(s) => s,
            None => Self::DEFAULT_API_ENDPOINT.to_string(),
        };

        let http_client = SdkmsClient::builder()
            .with_api_endpoint(&endpoint)
            .with_api_key(&api_key)
            .build()?;
        let public_key = {
            let req = SobjectDescriptor::Name(key_name.to_string());
            let resp = http_client.get_sobject(None, &req)?;
            // TODO: Set creation time!
            let raw_pk = resp.pub_key.ok_or(Error::SdkmsBadResponse)?;
            let deserialized_pk = Pk::from_public_key(&raw_pk)?;
            let e = deserialized_pk.rsa_public_exponent()?.to_be_bytes();
            let n = deserialized_pk.rsa_public_modulus()?.to_binary()?;
            Key::V4(Key4::import_public_rsa(&e, &n, None)?)
        };

        Ok(Agent::<O> {
            key_name,
            http_client,
            public_key,
            phantom: PhantomData,
        })
    }
}

// Error conversions
macro_rules! define_from {
    ($error:ident, $variant:ident) => {
        impl From<$error> for Error {
            fn from(other: $error) -> Self {
                Error::$variant(other)
            }
        }
    }
}

define_from!(SdkmsError, Sdkms);
define_from!(MbedtlsError, Mbedtls);
define_from!(SequoiaError, Sequoia);

#[cfg(test)]
mod tests;
