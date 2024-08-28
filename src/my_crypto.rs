use std::fs::File;
use std::io::{BufWriter, Write};

use anyhow::{anyhow, Result};
use der_parser;
use rsa::{BigUint, RsaPublicKey};
use rsa::pkcs1v15::Pkcs1v15Sign;
use win_crypto_ng::hash::{HashAlgorithm, HashAlgorithmId};

#[allow(unused)]
pub fn my_calc_sha1(input: &[u8]) -> Vec<u8> {
    let algo = HashAlgorithm::open(HashAlgorithmId::Sha1).unwrap();
    let mut hash = algo.new_hash().unwrap();
    hash.hash(input).unwrap();
    let result = hash.finish().unwrap();
    assert_eq!(result.len(), 160 / 8);
    let mut buf = Vec::<u8>::new();
    buf.extend(result.as_slice().into_iter());
    buf
}

#[allow(unused)]
pub fn my_calc_sha256(input: &[u8]) -> Vec<u8> {
    let algo = HashAlgorithm::open(HashAlgorithmId::Sha256).unwrap();
    let mut hash = algo.new_hash().unwrap();
    hash.hash(input).unwrap();
    let result = hash.finish().unwrap();
    assert_eq!(result.len(), 256 / 8);
    let mut buf = Vec::<u8>::new();
    buf.extend(result.as_slice().into_iter());
    buf
}

#[allow(unused)]
pub fn my_verify_rsa_sign(pubkey_u8_encoded: &[u8], hash_value: &[u8], signature: &[u8]) -> Result<bool> {
    let public_exponent = 65537u32; // see "section 3.3.1" and "section 3.3.2" in RFC6376
    let s = pubkey_u8_encoded.iter().map(|x| format!("{:02x}", x)).collect::<Vec<String>>().join("");
    println!("RSA pubkey (ASN.1 DER-encoded): {}", s);
    if false {
        let f = File::create("pubkey.der").unwrap();
        let mut writer = BufWriter::new(f);
        writer.write_all(pubkey_u8_encoded).unwrap();
        writer.flush().unwrap();
    }
    let pubkey_u8: &[u8] = (|data| match der_parser::parse_der(data) { // decode DER format
        Ok((_rem, v)) => {
            let sequence = v.as_sequence()?;
            for obj in sequence.iter() {
                if let Ok(v) = obj.as_bitstring() {
                    let slice_u8 = obj.as_slice().unwrap();
                    match der_parser::parse_der(slice_u8) {
                        Ok((_rem, v)) => {
                            let sequence = v.as_sequence()?;
                            if sequence.len() != 2 {
                                return Err(anyhow!("RSA pubkey is invalid format (inner of DER)"));
                            }
                            let mut iter = sequence.iter();
                            let pubkey_u8 = iter.next().unwrap().as_slice()?;
                            let exponent = iter.next().unwrap().as_u32()?;
                            assert_eq!(exponent, public_exponent);
                            return Ok(pubkey_u8);
                        },
                        Err(e) => {
                            return Err(anyhow!("RSA pubkey is not decodable as nested ASN.1 DER: {}", e));
                        },
                    }
                }
            }
            return Err(anyhow!("RSA pubkey is invalid DER format"));
        },
        Err(e) => {
            return Err(anyhow!("RSA pubkey is not decodable as ASN.1 DER: {}", e));
        },
    })(pubkey_u8_encoded)?;
    let s = pubkey_u8.iter().map(|x| format!("{:02x}", x)).collect::<Vec<String>>().join("");
    println!("RSA pubkey: {}", s);
    let bit_length = (pubkey_u8.len() as u32 - 1) * u8::BITS;
    if !(bit_length == 512 || bit_length == 1024 || bit_length == 2048 || bit_length == 4096) { // see "Section 3.3.3" in RFC6376
        return Err(anyhow!("RSA key size is invalid: {}", bit_length));
    }
    if signature.len() as u32 * u8::BITS != bit_length {
        return Err(anyhow!("RSA signature length is invalid: {}", signature.len() as u32 * u8::BITS));
    }
    let pubkey = RsaPublicKey::new(BigUint::from_bytes_be(pubkey_u8), BigUint::from(public_exponent)).unwrap();
    let scheme = Pkcs1v15Sign::new_unprefixed();
    let result = pubkey.verify(scheme, hash_value, signature);
    match result {
        Ok(()) => return Ok(true),
        Err(e) => {
            println!("RSA signature verification is failed: {}", e);
            return Ok(false);
        },
    }
}

#[allow(unused)]
fn debug_der_pubkey(data: &[u8]) -> Result<()> {
    let _pubkey_u8 = match der_parser::parse_der(data) {
        Ok((rem, v)) => {
            println!("DEBUG: BerObject: {:?}", v);
            let sequence = v.as_sequence().unwrap();
            println!("DEBUG: as_sequence: {:?}", sequence);
            println!("DEBUG: length of sequence: {}", sequence.len());
            for obj in sequence.iter() {
                println!("DEBUG: class={:?} tag={:?} length={:?}", obj.class(), obj.tag(), obj.length());
                if let Ok(v) = obj.as_bool() {
                    println!("DEBUG: content is BOOL: {:?}", v);
                }
                if let Ok(v) = obj.as_oid() {
                    println!("DEBUG: content is OID: {:?}", v);
                }
                if let Ok(v) = obj.as_tagged() {
                    println!("DEBUG: content is TAGGED: class={:?} tag={:?} content={:?}", v.0, v.1, v.2);
                }
                if let Ok(v) = obj.as_bitstring() {
                    println!("DEBUG: content is BITSTRING: {:?}", v);
                }
                if let Ok(v) = obj.as_sequence() {
                    println!("DEBUG: content is SEQUCNE: {:?}", v);
                }
                if let Ok(v) = obj.as_set() {
                    println!("DEBUG: content is SET: {:?}", v);
                }
                if let Ok(v) = obj.as_slice() {
                    println!("DEBUG: content is SLICE: {:?}", v);
                    println!("DEBUG: v.len()={}", v.len());
                    println!("DEBUG: ------------------------------");
                    debug_der_pubkey(v)?;
                    println!("DEBUG: ------------------------------");
                }
                if let Ok(v) = obj.as_str() {
                    println!("DEBUG: content is STR: {:?}", v);
                }
            }
            if rem.len() > 0 {
                println!("DEBUG:==============================");
                debug_der_pubkey(rem)?;
            }
        },
        Err(e) => {
            return Err(anyhow!("RSA pubkey is not decodable as ASN.1 DER: {}", e));
        },
    };
    Ok(())
}
