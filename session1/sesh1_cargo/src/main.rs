// https://github.com/thor314/uncloak-hw/blob/main/hw1/src/lib.rs


use rand::{rngs::ThreadRng,CryptoRng,Rng,RngCore};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

const BITS: usize = 2048;

pub struct RSA {
    pub priv_key: RsaPrivateKey,
    pub pub_key: RsaPublicKey,
}

impl RSA {
    pub fn new() -> Self {
        let priv_key = 
            RsaPrivateKey::new(&mut rand::thread_rng(), BITS
        ).expect("failed to generate a key");
        let pub_key = RsaPublicKey::from(&priv_key);
        Self {priv_key, pub_key}
    }

    pub fn encrypt<R: CryptoRng + RngCore>(&self,data: &[u8]
        , mut rng:R) -> Vec<u8> {
            self
                .pub_key
                .encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(),data)
                .expect("failed to encyrpt")
        }

    pub fn decrypt(&self, enc_data: &[u8]) -> Vec<u8> {
        self 
            .priv_key
            .decrypt(PaddingScheme::new_pkcs1v15_encrypt(),enc_data)
            .expect("failed to decrypt")
    }
}

pub mod vignere {
    
    pub struct Vignere<'a> {
        key: &'a [u8],
    }

    fn check_alphabetic(s: &str) -> anyhow::Result<()> {
        for c in s.chars(){
            match c{
                'a'..='z'=>(),
                _ => return Err(anyhow::anyhow!("Invalid character in key, must be lowercase a-z: {c}")),
            }
        }
        Ok(())
    }


    impl<'a> Vignere<'a> {

        pub fn new(key: &'a str) -> anyhow::Result<Self> {
            check_alphabetic(key)?;
            Ok(Self {key : key.as_bytes()})
        }

        pub fn encrypt(&self, plaintext: &str) -> anyhow::Result<Vec<u8>>{
            check_alphabetic(plaintext)?;
            let key_it = self.key.iter().cycle();
            let out = std::iter::zip(plaintext.bytes(), key_it)
                .map(|(p,k)|{
                    let p = p - b'a';
                    let k = k - b'a';
                    let c = (p+k) % 26;
                    c + b'a'
                })
                .collect::<Vec<_>>();
                Ok(out)
        }

        pub fn decrypt(&self, ciphertext: &str) -> anyhow::Result<String> {
            check_alphabetic(ciphertext)?;
            let key_it = self.key.iter().cycle();
            Ok(
            std::iter::zip(ciphertext.bytes(), key_it)
                .map(|(p,k)|{
                    let p = p - b'a';
                    let k = k - b'a';
                    let c = (26+p-k) % 26;
                    c + b'a'
            })
            .map(|c| c as char)
            .collect(),
            )
        }

    }

    mod test {
        use super::*;

        fn test_vig() {

            let msg = "aoeuidhtnsqjkxbmwvzpyfgcrl";
            let key = "averygoodkey";
            let v = Vignere::new(key).unwrap();
            let ciphertext = v.encrypt(msg).unwrap();
            let plaintext = v.decrypt(&String::from_utf8(ciphertext).unwrap()).unwrap();
            assert_eq!(msg, plaintext);


        }

    }



}

use crate::vignere::Vignere;

fn main() {
    println!("Hello, world!");


    let msg = "aoeuidhtnsqjkxbmwvzpyfgcrl";
    let key = "averygoodkey";
    let v = Vignere::new(key).unwrap();
    let ciphertext = v.encrypt(msg).unwrap();
    let plaintext = v.decrypt(&String::from_utf8(ciphertext).unwrap()).unwrap();
    assert_eq!(msg, plaintext);

    println!("Hello, world!");


}