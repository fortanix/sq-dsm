//! Private Key Store communication.
//!
//! Functions in this module can be used to sign and decrypt using
//! remote keys using the [Private Key Store][PKS] protocol.
//!
//! [PKS]: https://gitlab.com/wiktor/pks
//! # Examples
//! ```
//! use sequoia_net::pks;
//! # let p: sequoia_openpgp::crypto::Password = vec![1, 2, 3].into();
//! # let key = sequoia_openpgp::cert::CertBuilder::general_purpose(None, Some("alice@example.org"))
//! #     .generate().unwrap().0.keys().next().unwrap().key().clone();
//!
//! match pks::unlock_signer("http://localhost:3000/", key, &p) {
//!     Ok(signer) => { /* use signer for signing */ },
//!     Err(e) => { eprintln!("Could not unlock signer: {:?}", e); }
//! }
//! ```

use sequoia_openpgp as openpgp;

use openpgp::packet::Key;
use openpgp::packet::key::{PublicParts, UnspecifiedRole};
use openpgp::crypto::{Password, Decryptor, Signer, mpi, SessionKey, ecdh};

use hyper::{Body, Client, Uri, client::HttpConnector, Request};
use hyper_tls::HttpsConnector;

use super::Result;
use url::Url;

/// Returns a capability URL for given key's capability.
///
/// Unlocks a key using given password and on success returns a capability
/// URL that can be used for signing or decryption.
fn create_uri(store_uri: &str, key: &Key<PublicParts, UnspecifiedRole>,
                      p: &Password, capability: &str) -> Result<Uri> {
    let mut url = Url::parse(&store_uri)?;
    let auth = if !url.username().is_empty() {
        let credentials = format!("{}:{}", url.username(), url.password().unwrap_or_default());
        Some(format!("Basic {}", base64::encode(credentials)))
    } else {
        None
    };

    let client = Client::builder().build(HttpsConnector::new());

    url.query_pairs_mut().append_pair("capability", capability);

    let uri: hyper::Uri = url.join(&key.fingerprint().to_hex())?.as_str().parse()?;
    let mut request = Request::builder()
        .method("POST")
        .uri(uri);

    if let Some(auth) = auth {
        request = request.header(hyper::header::AUTHORIZATION, auth);
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    let request = request.body(Body::from(p.map(|p|p.as_ref().to_vec())))?;
    let response = rt.block_on(client.request(request))?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!("PKS Key unlock failed."));
    }

    if let Some(location) = response.headers().get("Location") {
        Ok(location.to_str()?.parse()?)
    } else {
        Err(anyhow::anyhow!("Key unlock did not return a Location header."))
    }
}

/// Unlock a remote key for signing.
///
/// Look up a private key corresponding to the public key passed as a
/// parameter and return a [`Signer`] trait object that will utilize
/// that private key for signing.
///
/// # Errors
///
/// This function fails if the key cannot be found on the remote store
/// or if the password is not correct.
///
/// # Examples
/// ```
/// use sequoia_net::pks;
/// # let p: sequoia_openpgp::crypto::Password = vec![1, 2, 3].into();
/// # let key = sequoia_openpgp::cert::CertBuilder::general_purpose(None, Some("alice@example.org"))
/// #     .generate().unwrap().0.keys().next().unwrap().key().clone();
///
/// match pks::unlock_signer("http://localhost:3000/", key, &p) {
///     Ok(signer) => { /* use signer for signing */ },
///     Err(e) => { eprintln!("Could not unlock signer: {:?}", e); }
/// }
/// ```
pub fn unlock_signer(store_uri: impl AsRef<str>, key: Key<PublicParts, UnspecifiedRole>,
                     p: &Password) -> Result<Box<dyn Signer + Send + Sync>> {
    let capability = create_uri(store_uri.as_ref(), &key, p, "sign")?;
    Ok(Box::new(PksClient::new(key, capability)?))
}

/// Unlock a remote key for decryption.
///
/// Look up a private key corresponding to the public key passed as a
/// parameter and return a [`Decryptor`] trait object that will utilize
/// that private key for decryption.
///
/// # Errors
///
/// This function fails if the key cannot be found on the remote store
/// or if the password is not correct.
///
/// # Examples
/// ```
/// use sequoia_net::pks;
/// # let p: sequoia_openpgp::crypto::Password = vec![1, 2, 3].into();
/// # let key = sequoia_openpgp::cert::CertBuilder::general_purpose(None, Some("alice@example.org"))
/// #     .generate().unwrap().0.keys().next().unwrap().key().clone();
///
/// match pks::unlock_decryptor("http://localhost:3000/", key, &p) {
///     Ok(decryptor) => { /* use decryptor for decryption */ },
///     Err(e) => { eprintln!("Could not unlock decryptor: {:?}", e); }
/// }
/// ```
pub fn unlock_decryptor(store_uri: impl AsRef<str>, key: Key<PublicParts, UnspecifiedRole>,
                     p: &Password) -> Result<Box<dyn Decryptor + Send + Sync>> {
    let capability = create_uri(store_uri.as_ref(), &key, p, "decrypt")?;
    Ok(Box::new(PksClient::new(key, capability)?))
}

struct PksClient {
    location: Uri,
    public: Key<PublicParts, UnspecifiedRole>,
    client: hyper::client::Client<HttpsConnector<HttpConnector>>,
    rt: tokio::runtime::Runtime,
}

impl PksClient {
    fn new(
           public: Key<PublicParts, UnspecifiedRole>,
           location: Uri,
    ) -> Result<Self> {
        let client = Client::builder().build(HttpsConnector::new());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;

        Ok(Self { location, public, client, rt })
    }

    fn make_request<T>(&mut self, body: Vec<u8>, hash: T) -> Result<Vec<u8>>
    where T: Into<Option<String>> {
        let hash = hash.into();
        let location = if let Some(hash) = hash {
            format!("{}?hash={}", self.location, hash).parse::<Uri>()?
        } else {
            self.location.clone()
        };

        let request = Request::builder()
            .method("POST")
            .uri(location)
            .body(Body::from(body))?;
        let response = self.rt.block_on(self.client.request(request))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("PKS Decryption failed."));
        }

        let response = self.rt.block_on(hyper::body::to_bytes(response))?.to_vec();
        Ok(response)
    }
}

impl Decryptor for PksClient {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> openpgp::Result<SessionKey> {
        match (ciphertext, self.public.mpis()) {
            (mpi::Ciphertext::RSA { c }, mpi::PublicKey::RSA { .. }) =>
                Ok(self.make_request(c.value().to_vec(), None)?.into())
            ,
            (mpi::Ciphertext::ECDH { e, .. }, mpi::PublicKey::ECDH { .. }) => {
                #[allow(non_snake_case)]
                let S = self.make_request(e.value().to_vec(), None)?.into();
                Ok(ecdh::decrypt_unwrap(&self.public, &S, ciphertext)?)
            },
            (ciphertext, public) => Err(anyhow::anyhow!(
                "Unsupported combination of ciphertext {:?} \
                     and public key {:?} ",
                ciphertext,
                public
            )),
        }
    }
}

impl Signer for PksClient {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public
    }

    fn sign(
        &mut self,
        hash_algo: openpgp::types::HashAlgorithm,
        digest: &[u8],
    ) -> openpgp::Result<openpgp::crypto::mpi::Signature> {
        use openpgp::types::PublicKeyAlgorithm;

        let sig = self.make_request(digest.into(), hash_algo.to_string())?;

        match (self.public.pk_algo(), self.public.mpis()) {
            #[allow(deprecated)]
            (PublicKeyAlgorithm::RSASign, mpi::PublicKey::RSA { .. })
            | (
                PublicKeyAlgorithm::RSAEncryptSign,
                mpi::PublicKey::RSA { .. },
            ) =>
                Ok(mpi::Signature::RSA { s: mpi::MPI::new(&sig) }),
            (PublicKeyAlgorithm::EdDSA, mpi::PublicKey::EdDSA { .. }) => {
                let r = mpi::MPI::new(&sig[..32]);
                let s = mpi::MPI::new(&sig[32..]);

                Ok(mpi::Signature::EdDSA { r, s })
            }
            (
                PublicKeyAlgorithm::ECDSA,
                mpi::PublicKey::ECDSA { .. },
            ) => {
                let len_2 = sig.len() / 2;
                let r = mpi::MPI::new(&sig[..len_2]);
                let s = mpi::MPI::new(&sig[len_2..]);

                Ok(mpi::Signature::ECDSA { r, s })
            }

            (pk_algo, _) => Err(anyhow::anyhow!(
                "Unsupported combination of algorithm {:?} and pubkey {:?}",
                pk_algo,
                self.public
            )),
        }
    }
}
