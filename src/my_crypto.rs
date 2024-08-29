use anyhow::{bail, Result};
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, pkcs1v15::Pkcs1v15Sign, pkcs8::DecodePublicKey};
use sha1::{Digest, Sha1};
use sha2::Sha256;

#[allow(unused)]
pub fn my_calc_sha1(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(input);
    let result = hasher.finalize();
    let buf = result.to_vec();
    assert_eq!(buf.len(), 160 / 8);
    buf
}

#[allow(unused)]
pub fn my_calc_sha256(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let buf = result.to_vec();
    assert_eq!(buf.len(), 256 / 8);
    buf
}

#[allow(unused)]
pub fn my_verify_rsa_sign(pubkey_u8_encoded: &[u8], hash_algo: &str, hash_value: &[u8], signature: &[u8]) -> Result<bool> {
    // refer the definition "pub fn read_rsa_public_key()" in "src/crypto.rsa.rs" in "viadkim" crate
    let pubkey =  RsaPublicKey::from_public_key_der(pubkey_u8_encoded).or_else(|e| {
        // Supply initial error if fallback fails, too.
        RsaPublicKey::from_pkcs1_der(pubkey_u8_encoded).map_err(|_| e)
    })?;

    // refer the definition "pub fn verify_rsa()" in "src/crypto.rsa.rs" in "viadkim" crate
    let scheme = match hash_algo {
        "sha1" => Pkcs1v15Sign::new::<Sha1>(),
        "sha256" => Pkcs1v15Sign::new::<Sha256>(),
        _ => bail!("BUG"),
    };
    let result = pubkey.verify(scheme, hash_value, signature);
    match result {
        Ok(()) => return Ok(true),
        Err(e) => {
            println!("RSA signature verification is failed: {}", e);
            return Ok(false);
        },
    }
}
