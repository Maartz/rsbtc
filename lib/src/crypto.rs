use crate::sha256::Hash;

use ecdsa::signature::{SignerMut, Verifier};
use ecdsa::{Signature as ECDSASignature, SigningKey, VerifyingKey};
use k256::{Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Signature(ECDSASignature<Secp256k1>);

impl Signature {
    pub fn sign_output(output_hash: &Hash, private_key: &PrivateKey) -> Self {
        private_key.sign(output_hash)
    }

    pub fn verify(&self, output_hash: &Hash, public_key: &PublicKey) -> bool {
        public_key
            .0
            .verify(&output_hash.as_bytes(), &self.0)
            .is_ok()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey<Secp256k1>);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PrivateKey(#[serde(with = "signkey_serde")] SigningKey<Secp256k1>);

impl PrivateKey {
    pub fn new_key() -> Self {
        let secret_key = SecretKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        PrivateKey(SigningKey::from(secret_key))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().clone())
    }

    pub fn sign(&self, hash: &Hash) -> Signature {
        let mut signing_key = self.0.clone();
        let signature = signing_key.sign(&hash.as_bytes());
        Signature(signature)
    }
}

mod signkey_serde {
    use serde::Deserialize;
    pub fn serialize<S>(
        key: &super::SigningKey<super::Secp256k1>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&key.to_bytes())
    }
    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<super::SigningKey<super::Secp256k1>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::<u8>::deserialize(deserializer)?;
        Ok(super::SigningKey::from_slice(&bytes).unwrap())
    }
}
