//! *S-Expressions* for communicating cryptographic primitives.
//!
//! *S-Expressions* as described in the internet draft [S-Expressions],
//! are a way to communicate cryptographic primitives like keys,
//! signatures, and ciphertexts between agents or implementations.
//!
//! [S-Expressions]: https://people.csail.mit.edu/rivest/Sexp.txt

use std::convert::TryFrom;
use std::fmt;
use std::ops::Deref;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use sequoia_openpgp as openpgp;
use openpgp::crypto::{mpi, SessionKey};
use openpgp::crypto::mem::Protected;

use openpgp::Error;
use openpgp::Result;

mod parse;

/// An *S-Expression*.
///
/// An *S-Expression* is either a string, or a list of *S-Expressions*.
#[derive(Clone, PartialEq, Eq)]
pub enum Sexp {
    /// Just a string.
    String(String_),
    /// A list of *S-Expressions*.
    List(Vec<Sexp>),
}

impl fmt::Debug for Sexp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Sexp::String(ref s) => s.fmt(f),
            Sexp::List(ref l) => l.fmt(f),
        }
    }
}

impl Sexp {
    fn summarize(&self) -> String {
        fn inner(sexp: &Sexp, start_of_list: bool, output: &mut String) {
            match sexp {
                Sexp::List(l) => {
                    output.push('(');
                    for (i, sexp) in l.iter().enumerate() {
                        if i > 0 {
                            output.push(' ');
                        }
                        inner(sexp, i == 0, output);
                    }
                    output.push(')');
                }
                Sexp::String(s) => {
                    let mut shown = false;
                    if (start_of_list || s.len() <= 16)
                        && s.is_ascii() && s.iter().all(|c| {
                            c.is_ascii_alphanumeric()
                                || c.is_ascii_punctuation()
                                || c.is_ascii_whitespace()
                        })
                    {
                        if let Ok(s) = String::from_utf8(s.as_ref().to_vec()) {
                            shown = true;
                            output.push_str(&s);
                        }
                    }

                    if ! shown {
                        output.push_str(&format!("{} bytes", s.len()));
                    }
                }
            }
        }

        let mut output = String::new();
        inner(self, true, &mut output);
        output
    }
}

impl Sexp {
    /// Completes the decryption of this S-Expression representing a
    /// wrapped session key.
    ///
    /// Such an expression is returned from gpg-agent's `PKDECRYPT`
    /// command.  `padding` must be set according to the status
    /// messages sent.
    pub fn finish_decryption<R>(&self,
                                recipient: &openpgp::packet::Key<
                                        openpgp::packet::key::PublicParts, R>,
                                ciphertext: &mpi::Ciphertext,
                                plaintext_len: Option<usize>,
                                padding: bool)
        -> Result<SessionKey>
        where R: openpgp::packet::key::KeyRole
    {
        use openpgp::crypto::mpi::PublicKey;
        let not_a_session_key = || -> anyhow::Error {
            Error::MalformedMPI(
                format!("Not a session key: {:?}", self)).into()
        };

        let value = self.get(b"value")?.ok_or_else(not_a_session_key)?
            .into_iter().next().ok_or_else(not_a_session_key)?;

        match value {
            Sexp::String(s) => match recipient.mpis() {
                PublicKey::RSA { .. } | PublicKey::ElGamal { .. } => if padding
                {
                    // The session key is padded.  The format is
                    // described in g10/pubkey-enc.c (note that we,
                    // like GnuPG 2.2, only support the new encoding):
                    //
                    //   * Later versions encode the DEK like this:
                    //   *
                    //   *     0  2  RND(n bytes)  [...]
                    //   *
                    //   * (mpi_get_buffer already removed the leading zero).
                    //   *
                    //   * RND are non-zero random bytes.
                    let s_ = s.to_protected();
                    let mut s = &s_[..];

                    // The leading 0 may or may not be swallowed along
                    // the way due to MPI encoding.
                    if s[0] == 0 {
                        s = &s[1..];
                    }

                    // Version.
                    if s[0] != 2 {
                        return Err(Error::MalformedMPI(
                            format!("DEK encoding version {} not understood",
                                    s[0])).into());
                    }

                    // Skip non-zero bytes.
                    while !s.is_empty() && s[0] > 0 {
                        s = &s[1..];
                    }

                    if s.is_empty() {
                        return Err(Error::MalformedMPI(
                            "Invalid DEK encoding, no zero found".into())
                                   .into());
                    }

                    // Skip zero.
                    s = &s[1..];

                    Ok(s.to_vec().into())
                } else {
                    // The session key is not padded.  Currently, this
                    // happens if the session key is decrypted using
                    // scdaemon.
                    Ok(s.to_protected().into())
                },

                PublicKey::ECDH { curve, .. } => {
                    // The shared point has been computed by the
                    // remote agent.  The shared point is not padded.
                    let s_: mpi::ProtectedMPI = s.to_protected().into();
                    #[allow(non_snake_case)]
                    let S: Protected = s_.decode_point(curve)?.0.into();

                    // Now finish the decryption.
                    openpgp::crypto::ecdh::decrypt_unwrap(
                        recipient.role_as_unspecified(), &S, ciphertext,
                        plaintext_len)
                },

                _ => {
                    let _ = s.to_protected();
                    Err(Error::InvalidArgument(
                        format!("Don't know how to handle key {:?}", recipient))
                        .into())
                },
            }
            Sexp::List(..) => Err(not_a_session_key()),
        }
    }

    /// Parses this s-expression to a signature.
    ///
    /// Such an expression is returned from gpg-agent's `PKSIGN`
    /// command.
    pub fn to_signature(&self) -> Result<mpi::Signature> {
        let not_a_signature = || -> anyhow::Error {
            Error::MalformedMPI(
                format!("Not a signature: {:?}", self)).into()
        };

        let sig = self.get(b"sig-val")?.ok_or_else(not_a_signature)?
            .into_iter().next().ok_or_else(not_a_signature)?;

        if let Some(param) = sig.get(b"eddsa")? {
            let r = param.iter().find_map(|p| {
                p.get(b"r").ok().unwrap_or_default()
                    .and_then(|l| l.get(0).and_then(Sexp::string).cloned())
            }).ok_or_else(not_a_signature)?;
            let s = param.iter().find_map(|p| {
                p.get(b"s").ok().unwrap_or_default()
                    .and_then(|l| l.get(0).and_then(Sexp::string).cloned())
            }).ok_or_else(not_a_signature)?;
            Ok(mpi::Signature::EdDSA {
                r: mpi::MPI::new(&r),
                s: mpi::MPI::new(&s),
            })
        } else if let Some(param) = sig.get(b"ecdsa")? {
            let r = param.iter().find_map(|p| {
                p.get(b"r").ok().unwrap_or_default()
                    .and_then(|l| l.get(0).and_then(Sexp::string).cloned())
            }).ok_or_else(not_a_signature)?;
            let s = param.iter().find_map(|p| {
                p.get(b"s").ok().unwrap_or_default()
                    .and_then(|l| l.get(0).and_then(Sexp::string).cloned())
            }).ok_or_else(not_a_signature)?;
            Ok(mpi::Signature::ECDSA {
                r: mpi::MPI::new(&r),
                s: mpi::MPI::new(&s),
            })
        } else if let Some(param) = sig.get(b"rsa")? {
            let s = param.iter().find_map(|p| {
                p.get(b"s").ok().unwrap_or_default()
                    .and_then(|l| l.get(0).and_then(Sexp::string).cloned())
            }).ok_or_else(not_a_signature)?;
            Ok(mpi::Signature::RSA {
                s: mpi::MPI::new(&s),
            })
        } else if let Some(param) = sig.get(b"dsa")? {
            let r = param.iter().find_map(|p| {
                p.get(b"r").ok().unwrap_or_default()
                    .and_then(|l| l.get(0).and_then(Sexp::string).cloned())
            }).ok_or_else(not_a_signature)?;
            let s = param.iter().find_map(|p| {
                p.get(b"s").ok().unwrap_or_default()
                    .and_then(|l| l.get(0).and_then(Sexp::string).cloned())
            }).ok_or_else(not_a_signature)?;
            Ok(mpi::Signature::DSA {
                r: mpi::MPI::new(&r),
                s: mpi::MPI::new(&s),
            })
        } else {
            Err(Error::MalformedMPI(
                format!("Unknown signature sexp: {:?}", self)).into())
        }
    }

    /// Parses this s-expression to a private key.
    ///
    /// Such an expression is returned from gpg-agent's `EXPORT_KEY`
    /// command.
    ///
    /// When exporting NIST and brainpool curves, gpg doesn't indicate
    /// whether the curve is an ECDSA curve (for signing) or an ECDH
    /// curve (for encryption).  As [`mpi::SecretKeyMaterial`] needs
    /// this information, it is necessary for the caller to provide
    /// it.  This information can be extract from the public key.  If
    /// `None` is provided and the `sexp` is unambiguous (e.g., it's
    /// an RSA key), then the secret key material is returned in the
    /// expected form.  If the `sexp` is ambiguous and `pk` is `None`,
    /// then [`mpi::SecretKeyMaterial::Unknown`] is returned.
    pub fn to_secret_key(&self, pk: Option<&mpi::PublicKey>)
        -> Result<mpi::SecretKeyMaterial>
    {
        let not_a_key = |msg: &str| -> anyhow::Error {
            let base = "s-exp does not contain a key";

            if msg.is_empty() {
                Error::MalformedMPI(
                    format!("{}, s-exp: {}",
                            base, self.summarize())).into()
            } else {
                Error::MalformedMPI(
                    format!("{}: {}, s-exp: {}",
                            base, msg, self.summarize())).into()
            }
        };

        let disambiguate_ecc = |public, private|
            -> Result<mpi::SecretKeyMaterial>
        {
            let public = mpi::MPI::new(public);

            if let Some(pk) = pk {
                match pk {
                    mpi::PublicKey::ECDSA { q, .. } => {
                        if q != &public {
                            return Err(Error::MalformedMPI(
                                "Secret key does not correspond to \
                                 public key".into()).into());
                        }

                        return Ok(mpi::SecretKeyMaterial::ECDSA {
                            scalar: private,
                        });
                    }
                    mpi::PublicKey::ECDH { q, .. } => {
                        if q != &public {
                            return Err(Error::MalformedMPI(
                                "Secret key does not correspond to \
                                 public key".into()).into());
                        }

                        return Ok(mpi::SecretKeyMaterial::ECDH {
                            scalar: private,
                        });
                    }
                    _ => (),
                }
            }

            Ok(mpi::SecretKeyMaterial::Unknown {
                mpis: vec![ private ].into_boxed_slice(),
                rest: vec![].into_boxed_slice().into(),
            })
        };

        let _private_key = self.lookup(&[b"private-key"])?;

        if let Some(rsa) = self.lookup(&[b"private-key", b"rsa"])
            .map_err(|_| not_a_key(""))?
        {
            let d: &[u8] = rsa.lookup_value(&[b"rsa", b"d"])
                .unwrap_or(None)
                .ok_or_else(|| not_a_key("rsa key is missing n parameter"))?;
            let p: &[u8] = rsa.lookup_value(&[b"rsa", b"p"])
                .unwrap_or(None)
                .ok_or_else(|| not_a_key("rsa key is missing p parameter"))?;
            let q: &[u8] = rsa.lookup_value(&[b"rsa", b"q"])
                .unwrap_or(None)
                .ok_or_else(|| not_a_key("rsa key is missing q parameter"))?;
            let u: &[u8] = rsa.lookup_value(&[b"rsa", b"u"])
                .unwrap_or(None)
                .ok_or_else(|| not_a_key("rsa key is missing u parameter"))?;

            return Ok(mpi::SecretKeyMaterial::RSA {
                d: d.into(),
                p: p.into(),
                q: q.into(),
                u: u.into(),
            });
        } else if let Some(rsa) = self.lookup(&[b"private-key", b"dsa"])
            .map_err(|_| not_a_key(""))?
        {
            let x: &[u8] = rsa.lookup_value(&[b"dsa", b"x"])
                .unwrap_or(None)
                .ok_or_else(|| not_a_key("dsa key is missing x parameter"))?;

            return Ok(mpi::SecretKeyMaterial::DSA {
                x: x.into(),
            });
        } else if let Some(rsa) = self.lookup(&[b"private-key", b"elg"])
            .map_err(|_| not_a_key(""))?
        {
            let x: &[u8] = rsa.lookup_value(&[b"elg", b"x"])
                .unwrap_or(None)
                .ok_or_else(|| not_a_key("elgamal key is missing x parameter"))?;

            return Ok(mpi::SecretKeyMaterial::ElGamal {
                x: x.into(),
            });
        } else if let Some(ecc) = self.lookup(&[b"private-key", b"ecc"])
            .map_err(|_| not_a_key(""))?
        {
            let curve: Option<&[u8]> = ecc.lookup_value(&[b"ecc", b"curve"])
                .map_err(|_| not_a_key(""))?
                .map(|s| s.to_bytes());
            let flags: Option<&[u8]> = ecc.lookup_value(&[b"ecc", b"flags"])
                .map_err(|_| not_a_key(""))?
                .map(|s| s.to_bytes());
            let q: Option<&[u8]> = ecc.lookup_value(&[b"ecc", b"q"])
                .map_err(|_| not_a_key(""))?
                .map(|s| s.to_bytes());
            let d: Option<&[u8]> = ecc.lookup_value(&[b"ecc", b"d"])
                .map_err(|_| not_a_key(""))?
                .map(|s| s.to_bytes());

            if curve == Some(b"Curve25519") && flags == Some(b"djb-tweak") {
                if let Some(d) = d {
                    return Ok(mpi::SecretKeyMaterial::ECDH {
                        scalar: d.into(),
                    });
                }
            } else if curve == Some(b"Ed25519") && flags == Some(b"eddsa") {
                if let Some(d) = d {
                    return Ok(mpi::SecretKeyMaterial::EdDSA {
                        scalar: d.into(),
                    });
                }
            } else if curve == Some(b"brainpoolP256r1")
                || curve == Some(b"brainpoolP384r1")
                || curve == Some(b"brainpoolP512r1")
                || curve == Some(b"NIST P-256")
                || curve == Some(b"NIST P-384")
                || curve == Some(b"NIST P-521")
            {
                if let (Some(q), Some(d)) = (q, d) {
                    return disambiguate_ecc(q, d.into());
                }
            }
        }

        Err(Error::MalformedMPI(
            format!("Unsupported secret key, s-exp: {}",
                    self.summarize())).into())
    }

    /// Casts this to a string.
    pub fn string(&self) -> Option<&String_> {
        match self {
            Sexp::String(ref s) => Some(s),
            _ => None,
        }
    }

    /// Casts this to a list.
    pub fn list(&self) -> Option<&[Sexp]> {
        match self {
            Sexp::List(ref s) => Some(s.as_slice()),
            _ => None,
        }
    }

    /// Writes a serialized version of the object to `o`.
    pub fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        match self {
            Sexp::String(ref s) => s.serialize(o),
            Sexp::List(ref l) => {
                write!(o, "(")?;
                for sexp in l {
                    sexp.serialize(o)?;
                }
                write!(o, ")")?;
                Ok(())
            },
        }
    }

    /// Given an alist, returns the key, i.e., the value of the first
    /// element.
    ///
    /// Returns an error if the `Sexp` is not an alist, or the first
    /// element of the alist is not a string.
    fn key(&self) -> Result<&[u8]> {
        if let Sexp::List(alist) = self {
            if let Some(Sexp::String(key)) = alist.get(0) {
                return Ok(key);
            }
        }

        Err(Error::InvalidArgument(
            format!("Malformed alist: {:?}", self)).into())
    }

    /// Given an alist, ignores the key (the first element) and
    /// returns the rest.
    ///
    /// Returns an error if the `Sexp` is not an alist, or the first
    /// element of the alist is not a string.
    fn value(&self) -> Result<&[Sexp]> {
        if let Sexp::List(alist) = self {
            if let Some(Sexp::String(_key)) = alist.get(0) {
                return Ok(&alist[1..]);
            }
        }

        Err(Error::InvalidArgument(
            format!("Malformed alist: {:?}", self)).into())
    }

    /// Given an alist, checks that the key is equal to `key` and, if
    /// so, returns the rest.
    ///
    /// Returns `Ok(None)` if the key does not equal `key`.
    ///
    /// Returns an error if the `Sexp` is not an alist.
    fn get(&self, key: &[u8]) -> Result<Option<&[Sexp]>> {
        if self.key()? == key {
            self.value().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Given a Sexp, looks up the specified path.
    ///
    /// Returns an error if the `Sexp` is not an alist.
    ///
    /// # Example
    ///
    /// Given the sexp:
    ///
    /// ```text
    /// (private-key (ecc (curve Curve25519) (q #...#) (d #...#)))
    /// ```
    ///
    /// ```text
    /// sexp.lookup(&[b"private-key", b"ecc"])
    /// // => `(ecc (curve Curve25519) (q #...#) (d #...#))`
    ///
    /// sexp.lookup(&[b"foo"])
    /// // => `None`.
    ///
    /// sexp.lookup(&[b"private-key", "foo", "bar"])
    /// // => `None`.
    ///
    /// sexp.lookup(&[b"ecc"])
    /// // => `None`.
    /// ```
    fn lookup(&self, path: &[&[u8]]) -> Result<Option<&Sexp>> {
        assert!(! path.is_empty());

        let mut sexp = self;
        let mut values = if let Some(values) = self.get(path[0])? {
            values
        } else {
            return Ok(None);
        };

        'find: for key in path.iter().skip(1) {
            for value in values.iter() {
                if let Ok(Some(yes)) = value.get(key) {
                    values = yes;
                    sexp = value;
                    continue 'find;
                }
            }

            return Ok(None);
        }

        Ok(Some(sexp))
    }

    /// Like `Sexp::lookup`, but returns the value.
    ///
    /// Whereas `Sexp::lookup` returns the `Sexp` at the given path,
    /// this returns the value.  Further, it only returns the value if
    /// `path` names an alist with two elements where the first
    /// element is the key, and the second element is a String.
    fn lookup_value(&self, path: &[&[u8]]) -> Result<Option<&String_>> {
        let sexp = self.lookup(path)?;
        if let Some(Sexp::List(l)) = sexp {
            if l.len() == 2 {
                if let Sexp::String(ref s) = l[1] {
                    return Ok(Some(s));
                }
            }
        }
        Ok(None)
    }
}

impl TryFrom<&mpi::Ciphertext> for Sexp {
    type Error = anyhow::Error;

    /// Constructs an S-Expression representing `ciphertext`.
    ///
    /// The resulting expression is suitable for gpg-agent's `INQUIRE
    /// CIPHERTEXT` inquiry.
    fn try_from(ciphertext: &mpi::Ciphertext) -> Result<Self> {
        use openpgp::crypto::mpi::Ciphertext::*;
        match ciphertext {
            RSA { ref c } =>
                Ok(Sexp::List(vec![
                    Sexp::String("enc-val".into()),
                    Sexp::List(vec![
                        Sexp::String("rsa".into()),
                        Sexp::List(vec![
                            Sexp::String("a".into()),
                            Sexp::String(c.value().into())])])])),

            &ElGamal { ref e, ref c } =>
                Ok(Sexp::List(vec![
                    Sexp::String("enc-val".into()),
                    Sexp::List(vec![
                        Sexp::String("elg".into()),
                        Sexp::List(vec![
                            Sexp::String("a".into()),
                            Sexp::String(e.value().into())]),
                        Sexp::List(vec![
                            Sexp::String("b".into()),
                            Sexp::String(c.value().into())])])])),

            &ECDH { ref e, ref key } =>
                Ok(Sexp::List(vec![
                    Sexp::String("enc-val".into()),
                    Sexp::List(vec![
                        Sexp::String("ecdh".into()),
                        Sexp::List(vec![
                            Sexp::String("s".into()),
                            Sexp::String(key.as_ref().into())]),
                        Sexp::List(vec![
                            Sexp::String("e".into()),
                            Sexp::String(e.value().into())])])])),

            // crypto::mpi::Ciphertext is non_exhaustive, match on &_ to handle
            // future additions.
            &Unknown { .. } | &_ =>
                Err(Error::InvalidArgument(
                    format!("Don't know how to convert {:?}", ciphertext))
                    .into()),
        }
    }
}

#[cfg(test)]
impl Arbitrary for Sexp {
    fn arbitrary(g: &mut Gen) -> Self {
        if f32::arbitrary(g) < 0.7 {
            Sexp::String(String_::arbitrary(g))
        } else {
            let mut v = Vec::new();
            for _ in 0..usize::arbitrary(g) % 3 {
                v.push(Sexp::arbitrary(g));
            }
            Sexp::List(v)
        }
    }
}

/// A string.
///
/// A string can optionally have a display hint.
#[derive(Clone, PartialEq, Eq)]
pub struct String_(Box<[u8]>, Option<Box<[u8]>>);

impl fmt::Debug for String_ {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fn bstring(f: &mut fmt::Formatter, buf: &[u8]) -> fmt::Result {
            write!(f, "b\"")?;
            for &b in buf {
                match b {
                    0..=31 | 128..=255 =>
                        write!(f, "\\x{:02x}", b)?,
                    0x22 => // "
                        write!(f, "\\\"")?,
                    0x5c => // \
                        write!(f, "\\\\")?,
                    _ =>
                        write!(f, "{}", b as char)?,
                }
            }
            write!(f, "\"")
        }

        if let Some(hint) = self.display_hint() {
            write!(f, "[")?;
            bstring(f, hint)?;
            write!(f, "]")?;
        }
        bstring(f, &self.0)
    }
}

impl String_ {
    /// Constructs a new *Simple String*.
    pub fn new<S>(s: S) -> Self
        where S: Into<Box<[u8]>>
    {
        Self(s.into(), None)
    }

    /// Constructs a new *String*.
    pub fn with_display_hint<S, T>(s: S, display_hint: T) -> Self
        where S: Into<Box<[u8]>>, T: Into<Box<[u8]>>
    {
        Self(s.into(), Some(display_hint.into()))
    }

    /// Gets a reference to this *String*'s display hint, if any.
    pub fn display_hint(&self) -> Option<&[u8]> {
        self.1.as_ref().map(|b| b.as_ref())
    }

    /// Writes a serialized version of the object to `o`.
    pub fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        if let Some(display) = self.display_hint() {
            write!(o, "[{}:", display.len())?;
            o.write_all(display)?;
            write!(o, "]")?;
        }
        write!(o, "{}:", self.len())?;
        o.write_all(self)?;
        Ok(())
    }

    /// Returns the bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Creates a Protected memory region from this String.
    ///
    /// Securely erases the contents of the original String.
    pub fn to_protected(&self) -> Protected {
        Protected::from(&self.0[..])
    }

    /// Creates a Protected memory region from this String.
    ///
    /// Securely erases the contents of the original String.
    pub fn into_protected(self) -> Protected {
        let r = Protected::from(&self.0[..]);
        drop(self); // Securely erases this string.
        r
    }
}

impl Drop for String_ {
    fn drop(&mut self) {
        unsafe {
            memsec::memzero(self.0.as_mut_ptr(), self.0.len());
            if let Some(p) = self.1.as_mut() {
                memsec::memzero(p.as_mut_ptr(), p.len());
            }
        }
    }
}

impl From<std::string::String> for String_ {
    fn from(b: std::string::String) -> Self {
        Self::new(b.into_bytes())
    }
}

impl From<&str> for String_ {
    fn from(b: &str) -> Self {
        Self::new(b.as_bytes().to_vec())
    }
}

impl From<Vec<u8>> for String_ {
    fn from(b: Vec<u8>) -> Self {
        Self::new(b.into_boxed_slice())
    }
}

impl From<&[u8]> for String_ {
    fn from(b: &[u8]) -> Self {
        Self::new(b.to_vec())
    }
}

impl Deref for String_ {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String_> for Sexp {
    fn from(v: String_) -> Sexp {
        Sexp::String(v)
    }
}

impl From<Vec<Sexp>> for Sexp {
    fn from(v: Vec<Sexp>) -> Sexp {
        Sexp::List(v)
    }
}

#[cfg(test)]
impl Arbitrary for String_ {
    fn arbitrary(g: &mut Gen) -> Self {
        if bool::arbitrary(g) {
            Self::new(Vec::arbitrary(g).into_boxed_slice())
        } else {
            Self::with_display_hint(Vec::arbitrary(g).into_boxed_slice(),
                                    Vec::arbitrary(g).into_boxed_slice())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use openpgp::Cert;
    use openpgp::parse::Parse;
    use openpgp::packet::key;

    use crate::Keygrip;

    quickcheck::quickcheck! {
        fn roundtrip(s: Sexp) -> bool {
            let mut buf = Vec::new();
            s.serialize(&mut buf).unwrap();
            let t = Sexp::from_bytes(&buf).unwrap();
            assert_eq!(s, t);
            true
        }
    }

    #[test]
    fn to_signature() {
        use openpgp::crypto::mpi::Signature::*;
        assert!(matches!(
            Sexp::from_bytes(
                crate::tests::file("sexp/dsa-signature.sexp")).unwrap()
                    .to_signature().unwrap(),
                DSA { .. }
        ));
        assert!(matches!(
            Sexp::from_bytes(
                crate::tests::file("sexp/ecdsa-signature.sexp")).unwrap()
                    .to_signature().unwrap(),
                ECDSA { .. }
        ));
        assert!(matches!(
            Sexp::from_bytes(
                crate::tests::file("sexp/eddsa-signature.sexp")).unwrap()
                    .to_signature().unwrap(),
                EdDSA { .. }
        ));
        assert!(matches!(
            Sexp::from_bytes(
                crate::tests::file("sexp/rsa-signature.sexp")).unwrap()
                    .to_signature().unwrap(),
                RSA { .. }
        ));
    }

    #[test]
    fn sexp_lookup() {
        let s = b"(3:foo(3:bar1:x)(5:xyzzy(3:baz1:y1:z)))";
        let sexp = Sexp::from_bytes(s).expect("valid sexp");

        assert_eq!(
            sexp.lookup(&[&b"foo"[..]]).expect("valid sexp").expect("valid path"),
            &sexp);
    }

    #[test]
    fn to_secret_key() {
        let compare = |allow_unknown: bool,
        expected: &key::SecretKeyMaterial,
        got: &mpi::SecretKeyMaterial|
        {
            match expected {
                key::SecretKeyMaterial::Unencrypted(expected) => {
                    expected.map(|expected| {
                        match got {
                            mpi::SecretKeyMaterial::Unknown { mpis, rest } => {
                                if ! allow_unknown {
                                    panic!("Got unknown, but unknowns \
                                            are not allowed");
                                }
                                match expected {
                                    mpi::SecretKeyMaterial::ECDSA { scalar }
                                    | mpi::SecretKeyMaterial::ECDH { scalar } => {
                                        assert_eq!(mpis.len(), 1);
                                        assert_eq!(scalar, &mpis[0]);
                                        assert_eq!(rest.len(), 0);
                                    }
                                    _ => {
                                        assert_eq!(expected, got);
                                    }
                                }
                            }
                            _ => {
                                assert_eq!(expected, got);
                            }
                        }
                    });
                },
                key::SecretKeyMaterial::Encrypted(_) => {
                    panic!("Secret key material is encrypted");
                }
            };
        };

        for test in &[
            "rsa3072",
            "rsa3075",
            "dsa2048+elg2048",
            "ed25519+cv25519",
            "brainpoolP256r1",
            "brainpoolP384r1",
            "brainpoolP512r1",
            "nistp256+ecdsa+nistp256+ecdh",
            "nistp384+ecdsa+nistp384+ecdh",
            "nistp521+ecdsa+nistp521+ecdh",
        ]
        {
            let base = "sexp/keys";

            let cert = Cert::from_bytes(
                crate::tests::file(&format!("{}/{}.pgp", base, test)))
                .expect("valid cert");

            for key in cert.keys().secret().map(|ka| ka.key()) {
                let keygrip = Keygrip::of(key.mpis()).expect("has a keygrip");
                eprintln!("Checking {}-{}", test, keygrip);

                if let key::SecretKeyMaterial::Unencrypted(k) = key.secret() {
                    k.map(|k| eprintln!("key: {:?}", k));
                }

                let sexp = crate::tests::file(
                    &format!("{}/{}-{}.sexp", base, test, keygrip.to_string()));
                let sexp = Sexp::from_bytes(sexp).expect("valid sexp");

                eprintln!("sexp: {}", sexp.summarize());

                let sexp_secret_key = sexp.to_secret_key(None)
                    .expect("can extract");
                compare(true, key.secret(), &sexp_secret_key);

                let sexp_secret_key = sexp.to_secret_key(Some(key.mpis()))
                    .expect("can extract");
                compare(true, key.secret(), &sexp_secret_key);
            }
        }

        // Try with data copied from GnuPG's private-keys-v1.d
        // directory.
        for test in &[
            "alice.pgp"
        ]
        {
            let base = "sexp/private-keys-v1.d";

            let cert = Cert::from_bytes(
                crate::tests::file(&format!("{}/{}", base, test)))
                .expect("valid cert");

            for key in cert.keys().secret().map(|ka| ka.key()) {
                let keygrip
                    = Keygrip::of(key.mpis()).expect("has a keygrip");

                eprintln!("Checking {}: {} ({})",
                          test, key.fingerprint(), keygrip);

                let sexp_bytes
                    = crate::tests::file(&format!("{}/{}.key", base, keygrip));
                let sexp_string
                    = String::from_utf8(sexp_bytes.to_vec()).expect("UTF-8");

                let mut key_string = String::new();
                let mut saw_key = false;
                for line in sexp_string.split('\n') {
                    if saw_key {
                        if ! line.is_empty() && &line[0..1] == " " {
                            key_string.push_str(&line[1..]);
                        } else {
                            // We found the end.
                            break;
                        }
                    } else if line.starts_with("Key: (") {
                        saw_key = true;
                        key_string.push_str(&line[5..]);
                    }
                }
                assert!(saw_key);

                let sexp = Sexp::from_bytes(&key_string).expect("valid sexp");

                eprintln!("sexp: {}", sexp.summarize());

                let sexp_secret_key = sexp.to_secret_key(None)
                    .expect("can extract");
                compare(true, key.secret(), &sexp_secret_key);

                let sexp_secret_key = sexp.to_secret_key(Some(key.mpis()))
                    .expect("can extract");
                compare(true, key.secret(), &sexp_secret_key);
            }
        }
    }
}
