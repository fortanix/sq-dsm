use sdkms::api_model::Algorithm::Rsa;
use sdkms::api_model::{
    AgreeKeyMechanism, AgreeKeyRequest, Blob, DecryptRequest, EllipticCurve,
    KeyOperations, ObjectType, SobjectDescriptor, SobjectRequest,
};
use sdkms::SdkmsClient;
use sequoia_openpgp::crypto::{mpi, Decryptor, SessionKey};
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::Result as SequoiaResult;

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

        let plain: Vec<u8> = match ciphertext {
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

                http_client.decrypt(&decrypt_req)?.plain.into()
            }
            mpi::Ciphertext::ECDH { e, key: _key } => {
                // Get primary key public key
                let sobject =
                    http_client.get_sobject(None, self.descriptor).unwrap();
                let blob = sobject.pub_key.unwrap();
                // println!("{:?}", blob);
                // println!("raw:        {:?}", e.value());
                // let (x, y) = e.decode_point(&Curve::NistP256)?;
                // let mut value = vec![0; 1 + x.len()];
                // value[0] = 40;
                // value[1..].copy_from_slice(x);

                // println!("{:?}", value);
                // let e = openpgp::crypto::mpi::MPI::new_compressed_point(x);
                let value = e.value();

                use yasna::models::ObjectIdentifier;

                // DER encode public key (see RFC5480)
                let ecdh_oid =
                    ObjectIdentifier::from_slice(&[1, 3, 132, 1, 12]);
                let curve_oid =
                    ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]);

                let alg_id = yasna::construct_der(|writer| {
                    writer.write_sequence(|writer| {
                        writer.next().write_oid(&ecdh_oid); // id-ecDH
                        writer.next().write_oid(&curve_oid); // named curve
                    });
                });
                let bv = bit_vec::BitVec::from_bytes(&value);
                let der = yasna::construct_der(|writer| {
                    writer.write_sequence(|writer| {
                        writer.next().write_der(&alg_id); // algorithm
                        writer.next().write_bitvec(&bv); // subjectPublicKey
                    });
                });

                let der: Blob = der.to_vec().into();
                println!("my:    {:?}", der);
                println!("");
                println!("        ID: {:?}", alg_id);
                println!("ok:    {:?}", blob);

                println!("");
                println!("point = {:?} ({})", value, value.len());
                // Import transient Sobject
                let req = SobjectRequest {
                    elliptic_curve: Some(EllipticCurve::NistP256),
                    key_ops: Some(KeyOperations::APPMANAGEABLE),
                    // key_size: Some(256),
                    obj_type: Some(ObjectType::Ec),
                    name: Some("test".to_string()),
                    // transient: Some(true),
                    value: Some(der.clone()),
                    ..Default::default()
                };
                let _import_resp = http_client.import_sobject(&req);
                println!("{:?}", _import_resp);
                let agree_req = AgreeKeyRequest {
                    activation_date:   None,
                    deactivation_date: None,
                    private_key:       self.descriptor.clone(),
                    public_key:        SobjectDescriptor::TransientKey(
                        der.into(),
                    ),
                    mechanism:         AgreeKeyMechanism::DiffieHellman,
                    name:              None,
                    group_id:          None,
                    key_type:          ObjectType::Secret,
                    key_size:          256,
                    enabled:           true,
                    description:       None,
                    custom_metadata:   None,
                    key_ops:           Some(
                        KeyOperations::APPMANAGEABLE | KeyOperations::DECRYPT,
                    ),
                    state:             None,
                    transient:         true,
                };

                let agree_resp = http_client.agree(&agree_req);
                println!("{:?}", agree_resp);
                unimplemented!()
            }
            _ => unimplemented!(),
        };

        Ok(plain.into())
    }
}
