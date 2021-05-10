use anyhow::Error;
use bit_vec::BitVec;
use sdkms::api_model::Algorithm::Rsa;
use sdkms::api_model::{
    AgreeKeyMechanism, AgreeKeyRequest, DecryptRequest, KeyOperations,
    ObjectType, SobjectDescriptor, SobjectRequest,
};
use sdkms::SdkmsClient;
use sequoia_openpgp::crypto::mem::Protected;
use sequoia_openpgp::crypto::mpi::PublicKey::ECDH as SequoiaECDH;
use sequoia_openpgp::crypto::{ecdh, mpi, Decryptor, SessionKey};
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::types::Curve;
use sequoia_openpgp::Result;
use yasna::models::ObjectIdentifier as Oid;

pub struct RawDecryptor<'a> {
    pub api_endpoint: &'a str,
    pub api_key:      &'a str,
    pub descriptor:   &'a SobjectDescriptor,
    pub public:       &'a Key<PublicParts, UnspecifiedRole>,
}

const ID_ECDH: [u64; 6] = [1, 2, 840, 10045, 2, 1];

impl Decryptor for RawDecryptor<'_> {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> { &self.public }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> Result<SessionKey> {
        let mut cli = SdkmsClient::builder()
            .with_api_endpoint(&self.api_endpoint)
            .with_api_key(&self.api_key)
            .build()?;

        match ciphertext {
            mpi::Ciphertext::RSA { c } => {
                let decrypt_req = DecryptRequest {
                    cipher: c.value().to_vec().into(),
                    alg:    Some(Rsa),
                    iv:     None,
                    key:    Some(self.descriptor.clone()),
                    mode:   None,
                    ad:     None,
                    tag:    None,
                };

                Ok(cli.decrypt(&decrypt_req)?.plain.to_vec().into())
            }
            mpi::Ciphertext::ECDH { e, .. } => {
                let curve = match self.public().mpis() {
                    SequoiaECDH { curve, .. } => curve.clone(),
                    _ => return Err(Error::msg("inconsistent pk algo")),
                };

                cli = cli.authenticate_with_api_key(&self.api_key)?;

                let ephemeral_der = match curve {
                    Curve::Cv25519 => {
                        let x = e.value()[1..].to_vec();

                        let oid = Oid::from_slice(&[1, 3, 101, 110]);
                        yasna::construct_der(|w| {
                            w.write_sequence(|w| {
                                w.next().write_sequence(|w| {
                                    w.next().write_oid(&oid);
                                });
                                w.next().write_bitvec(&BitVec::from_bytes(&x))
                            });
                        })
                    }
                    _ => {
                        //
                        // Note: SDKMS expects UNRESTRICTED ALGORITHM IDENTIFIER
                        // AND PARAMETERS (RFC5480 sec. 2.1.1) for Nist curves
                        //
                        let id_ecdh = Oid::from_slice(&ID_ECDH);
                        let named_curve = curve_oid(&curve)?;

                        let alg_id = yasna::construct_der(|writer| {
                            writer.write_sequence(|writer| {
                                writer.next().write_oid(&id_ecdh);
                                writer.next().write_oid(&named_curve);
                            });
                        });

                        let subj_public_key = BitVec::from_bytes(&e.value());
                        yasna::construct_der(|writer| {
                            writer.write_sequence(|writer| {
                                writer.next().write_der(&alg_id);
                                writer.next().write_bitvec(&subj_public_key);
                            });
                        })
                    }
                };

                // Import ephemeral public key
                let e_descriptor = {
                    let api_curve = super::sequoia_curve_to_api_curve(&curve)?;
                    let req = SobjectRequest {
                        elliptic_curve: Some(api_curve),
                        key_ops: Some(KeyOperations::AGREEKEY),
                        obj_type: Some(ObjectType::Ec),
                        transient: Some(true),
                        value: Some(ephemeral_der.into()),
                        ..Default::default()
                    };
                    let e_tkey = cli
                        .import_sobject(&req)
                        .unwrap()
                        .transient_key
                        .ok_or_else(|| {
                            Error::msg(
                                "could not retrieve SDKMS transient key \
                                 (representing ECDH ephemeral public key)",
                            )
                        })?;

                    SobjectDescriptor::TransientKey(e_tkey)
                };

                // Agree on a ECDH secret between the recipient private key, and
                // the ephemeral public key.
                let secret: Protected = {
                    let agree_req = AgreeKeyRequest {
                        activation_date:   None,
                        deactivation_date: None,
                        private_key:       self.descriptor.clone(),
                        public_key:        e_descriptor,
                        mechanism:         AgreeKeyMechanism::DiffieHellman,
                        name:              None,
                        group_id:          None,
                        key_type:          ObjectType::Secret,
                        key_size:          curve_key_size(&curve)?,
                        enabled:           true,
                        description:       None,
                        custom_metadata:   None,
                        key_ops:           Some(KeyOperations::EXPORT),
                        state:             None,
                        transient:         true,
                    };

                    let agreed_tkey = cli
                        .agree(&agree_req)
                        .unwrap()
                        .transient_key
                        .ok_or_else(|| {
                            Error::msg("could not retrieve agreed key")
                        })?;

                    let desc = SobjectDescriptor::TransientKey(agreed_tkey);

                    cli.export_sobject(&desc)?
                        .value
                        .ok_or_else(|| Error::msg("could not retrieve secret"))?
                        .to_vec()
                        .into()
                };

                Ok(ecdh::decrypt_unwrap(self.public(), &secret, ciphertext)?
                    .to_vec()
                    .into())
            }
            _ => Err(Error::msg("unsupported/unknown algorithm")),
        }
    }
}

fn curve_oid(curve: &Curve) -> Result<Oid> {
    match curve {
        Curve::Cv25519 => Ok(Oid::from_slice(&[1, 3, 101, 110])),
        Curve::NistP256 => Ok(Oid::from_slice(&[1, 2, 840, 10045, 3, 1, 7])),
        Curve::NistP384 => Ok(Oid::from_slice(&[1, 3, 132, 0, 34])),
        Curve::NistP521 => Ok(Oid::from_slice(&[1, 3, 132, 0, 35])),
        _ => Err(Error::msg("unsupported curve")),
    }
}

fn curve_key_size(curve: &Curve) -> Result<u32> {
    match curve {
        Curve::Cv25519 => Ok(253),
        Curve::NistP256 => Ok(256),
        Curve::NistP384 => Ok(384),
        Curve::NistP521 => Ok(521),
        _ => Err(Error::msg("unsupported curve")),
    }
}
