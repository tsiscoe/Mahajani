use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding};
use sha2::Sha256;

/// Default RSA key size in bits (2048-bit NIST/OpenPGP security floor)
pub const RSA_KEY_BITS: usize = 2048;

#[derive(Clone)]
pub struct KeyPair2048 {
    pub signing_key: SigningKey<Sha256>,
    pub verifying_key: VerifyingKey<Sha256>,
}

impl KeyPair2048 {
    /// Generate a 2048-bit RSA key pair (minimum NIST/OpenPGP security floor)
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let private_key =
            RsaPrivateKey::new(&mut rng, RSA_KEY_BITS).expect("RSA-2048 generation failed");
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Sign challenge nonce and return base64 signature
    pub fn sign_challenge(&self, challenge: &str) -> String {
        let mut rng = rand::thread_rng();
        let signature = self
            .signing_key
            .sign_with_rng(&mut rng, challenge.as_bytes());
        BASE64.encode(signature.to_vec())
    }
}
