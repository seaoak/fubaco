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
