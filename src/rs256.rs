use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::BoxedUint;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use sha2::Sha256;

pub(crate) use rsa::PublicKey;

pub(crate) fn public_key(n: &[u8], e: &[u8]) -> Option<PublicKey> {
    if n.is_empty() || e.is_empty() || e.len() > 4 {
        return None;
    }
    PublicKey::new(BoxedUint::from_be_slice_vartime(n), BoxedUint::from_be_slice_vartime(e)).ok()
}

pub(crate) fn jwk_key(n: &str, e: &str) -> Option<PublicKey> {
    let n = URL_SAFE_NO_PAD.decode(n.trim_end_matches('=')).ok()?;
    let e = URL_SAFE_NO_PAD.decode(e.trim_end_matches('=')).ok()?;
    public_key(&n, &e)
}

pub(crate) fn verify(key: &PublicKey, signing_input: &str, signature: &str) -> bool {
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else { return false };
    let Ok(signature) = Signature::try_from(signature.as_slice()) else { return false };
    VerifyingKey::<Sha256>::new(key.clone()).verify(signing_input.as_bytes(), &signature).is_ok()
}
