use sdkms::api_model::Algorithm::Rsa;
use sdkms::api_model::{
    AgreeKeyMechanism, AgreeKeyRequest, DecryptRequest, EllipticCurve,
    KeyOperations, ObjectType, SobjectDescriptor, SobjectRequest,
};
use sdkms::SdkmsClient;
use sequoia_openpgp::crypto::mem::Protected;
use sequoia_openpgp::crypto::{ecdh, mpi, Decryptor, SessionKey};
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::Result as SequoiaResult;
use yasna::models::ObjectIdentifier;

pub struct RawDecryptor<'a> {
    pub api_endpoint: &'a str,
    pub api_key:      &'a str,
    pub descriptor:   &'a SobjectDescriptor,
    pub public:       &'a Key<PublicParts, UnspecifiedRole>,
}

impl Decryptor for RawDecryptor<'_> {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> { &self.public }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> SequoiaResult<SessionKey> {
        let http_client = SdkmsClient::builder()
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

                Ok(http_client.decrypt(&decrypt_req)?.plain.to_vec().into())
            }
            mpi::Ciphertext::ECDH { e, .. } => {
                let cli =
                    http_client.authenticate_with_api_key(&self.api_key)?;

                //
                // Note: The algorithm OID parsed by SDKMS is UNRESTRICTED
                // ALGORITHM IDENTIFIER AND PARAMETERS (RFC5480 sec. 2.1.1)
                //
                let ephemeral_der = {
                    let id_ecdh =
                        ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]);

                    let named_curve = ObjectIdentifier::from_slice(&[
                        1, 2, 840, 10045, 3, 1, 7,
                    ]);

                    let alg_id = yasna::construct_der(|writer| {
                        writer.write_sequence(|writer| {
                            writer.next().write_oid(&id_ecdh);
                            writer.next().write_oid(&named_curve);
                        });
                    });

                    let subj_public_key =
                        bit_vec::BitVec::from_bytes(&e.value());
                    yasna::construct_der(|writer| {
                        writer.write_sequence(|writer| {
                            writer.next().write_der(&alg_id);
                            writer.next().write_bitvec(&subj_public_key);
                        });
                    })
                };

                // Import ephemeral public key
                let e_descriptor = {
                    let req = SobjectRequest {
                        elliptic_curve: Some(EllipticCurve::NistP256),
                        key_ops: Some(KeyOperations::AGREEKEY),
                        obj_type: Some(ObjectType::Ec),
                        transient: Some(true),
                        value: Some(ephemeral_der.into()),
                        ..Default::default()
                    };
                    let e_tkey = cli
                        .import_sobject(&req)?
                        .transient_key
                        .ok_or(anyhow::Error::msg(
                            "could not retrieve SDKMS transient key \
                             (representing ECDH ephemeral public key)",
                        ))?;

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
                        key_size:          256,
                        enabled:           true,
                        description:       None,
                        custom_metadata:   None,
                        key_ops:           Some(KeyOperations::EXPORT),
                        state:             None,
                        transient:         true,
                    };

                    let agreed_tkey =
                        cli.agree(&agree_req)?.transient_key.ok_or(
                            anyhow::Error::msg("could not retrieve agreed key"),
                        )?;

                    let desc = SobjectDescriptor::TransientKey(agreed_tkey);

                    cli.export_sobject(&desc)?
                        .value
                        .ok_or(anyhow::Error::msg("could not retrieve secret"))?
                        .to_vec()
                        .into()
                };

                Ok(ecdh::decrypt_unwrap(self.public(), &secret, ciphertext)?
                    .to_vec()
                    .into())
            }
            _ => {
                return Err(anyhow::Error::msg(
                    "unsupported/unknown algorithm",
                ))?
            }
        }
    }
}
