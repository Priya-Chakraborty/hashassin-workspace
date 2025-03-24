use hex;
use md5::{Digest as Md5Digest, Md5};
use scrypt::{Params, scrypt};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{Digest as Sha3Digest, Sha3_512};

#[derive(Copy, Clone)]
pub enum Algorithm {
    SHA256,
    SHA3_512,
    MD5,
    Scrypt,
}

pub fn hash_password(password: &str, algorithm: Algorithm) -> String {
    match algorithm {
        Algorithm::SHA256 => {
            let mut hasher = Sha256::new();
            hasher.update(password);
            hex::encode(hasher.finalize())
        }
        Algorithm::SHA3_512 => {
            let mut hasher = Sha3_512::new();
            hasher.update(password);
            hex::encode(hasher.finalize())
        }
        Algorithm::MD5 => {
            let mut hasher = Md5::new();
            hasher.update(password);
            hex::encode(hasher.finalize())
        }
        Algorithm::Scrypt => {
            let params = Params::new(17, 8, 1, 32).unwrap();
            let mut output = [0u8; 32];
            scrypt(
                password.as_bytes(),
                b"AAAAAAAAAAAAAAAAAAAAAA",
                &params,
                &mut output,
            )
            .unwrap();
            hex::encode(output)
        }
    }
}
