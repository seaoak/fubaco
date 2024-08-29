use anyhow::{anyhow, Result};
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, pkcs1v15::Pkcs1v15Sign, pkcs8::DecodePublicKey};
use sha1::{Digest, Sha1};
use sha2::Sha256;

//====================================================================
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MyHashAlgo {
    Sha1,
    Sha256,
}

impl std::fmt::Display for MyHashAlgo {
    fn fmt(&self, dest: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            Self::Sha1   => "sha1",
            Self::Sha256 => "sha256",
        };
        write!(dest, "{}", s)
    }
}

impl TryFrom<&str> for MyHashAlgo {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            _ => Err(anyhow!("MyHashAlgo: invalid value: \"{}\"", value)),
        }
    }
}

//====================================================================
#[allow(unused)]
pub fn my_calc_hash(algo: MyHashAlgo, input: &[u8]) -> Vec<u8> {
    match algo {
        MyHashAlgo::Sha1 => my_calc_sha1(input),
        MyHashAlgo::Sha256 => my_calc_sha256(input),
    }
}

fn my_calc_sha1(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(input);
    let result = hasher.finalize();
    let buf = result.to_vec();
    assert_eq!(buf.len(), 160 / 8);
    buf
}

fn my_calc_sha256(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let buf = result.to_vec();
    assert_eq!(buf.len(), 256 / 8);
    buf
}

//====================================================================
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MyAsymmetricAlgo {
    Rsa,
    Ed25519,
}

impl std::fmt::Display for MyAsymmetricAlgo {
    fn fmt(&self, dest: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            Self::Rsa     => "rsa",
            Self::Ed25519 => "ed25519",
        };
        write!(dest, "{}", s)
    }
}

impl TryFrom<&str> for MyAsymmetricAlgo {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "rsa" => Ok(Self::Rsa),
            "ed25519" => Ok(Self::Ed25519),
            _ => Err(anyhow!("MyAsymmetricAlgo: unknown value: \"{}\"", value)),
        }
    }
}

//====================================================================
#[allow(unused)]
pub fn my_verify_sign(pubkey_algo: MyAsymmetricAlgo, pubkey_u8_encoded: &[u8], hash_algo: MyHashAlgo, hash_value: &[u8], signature: &[u8]) -> Result<bool> {
    match pubkey_algo {
        MyAsymmetricAlgo::Rsa => my_verify_rsa_sign(pubkey_u8_encoded, hash_algo, hash_value, signature),
        MyAsymmetricAlgo::Ed25519 => my_verify_ed25519_sign(pubkey_u8_encoded, hash_algo, hash_value, signature),
    }
}

fn my_verify_rsa_sign(pubkey_u8_encoded: &[u8], hash_algo: MyHashAlgo, hash_value: &[u8], signature: &[u8]) -> Result<bool> {
    // refer the definition "pub fn read_rsa_public_key()" in "src/crypto/rsa.rs" in "viadkim" crate
    let pubkey =  RsaPublicKey::from_public_key_der(pubkey_u8_encoded).or_else(|e| {
        // Supply initial error if fallback fails, too.
        RsaPublicKey::from_pkcs1_der(pubkey_u8_encoded).map_err(|_| e)
    })?;

    // refer the definition "pub fn verify_rsa()" in "src/crypto/rsa.rs" in "viadkim" crate
    let scheme = match hash_algo {
        MyHashAlgo::Sha1 => Pkcs1v15Sign::new::<Sha1>(),
        MyHashAlgo::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
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

fn my_verify_ed25519_sign(pubkey_u8_encoded: &[u8], hash_algo: MyHashAlgo, hash_value: &[u8], signature: &[u8]) -> Result<bool> {
    Err(anyhow!("*NOT IMPLEMENT YET*\n{:?} {:?} {:?} {:?}", pubkey_u8_encoded, hash_algo, hash_value, signature))
}
