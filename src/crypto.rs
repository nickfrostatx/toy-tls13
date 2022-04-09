use aes_gcm::aead::{AeadInPlace, NewAead};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::network::CipherSuite;

pub struct HandshakeKeys {
    pub handshake_secret: Vec<u8>,
    pub client_handshake_key: SymmetricKey,
    pub client_finished_key: Vec<u8>,
    pub server_handshake_key: SymmetricKey,
    pub server_finished_key: Vec<u8>,
}

pub struct ApplicationKeys {
    pub client_key: SymmetricKey,
    pub server_key: SymmetricKey,
}

pub struct SymmetricKey {
    cipher_suite: CipherSuite,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    seq: u32,
}

impl SymmetricKey {
    pub fn decrypt(&mut self, record_data: &[u8], mut wrapper: Vec<u8>) -> Result<Vec<u8>, Error> {
        let iv = xor_iv(&self.iv, self.seq);
        let nonce = Nonce::from_slice(&iv);
        self.seq += 1;

        match self.cipher_suite {
            CipherSuite::TlsAes128GcmSha256 => {
                let key = Key::from_slice(&self.key);
                Aes128Gcm::new(key).decrypt_in_place(nonce, record_data, &mut wrapper)?;
                Ok(wrapper)
            }
            CipherSuite::TlsAes256GcmSha256 => {
                let key = Key::from_slice(&self.key);
                Aes256Gcm::new(key).decrypt_in_place(nonce, record_data, &mut wrapper)?;
                Ok(wrapper)
            }
        }
    }

    pub fn encrypt(&mut self, record_data: &[u8], mut wrapper: Vec<u8>) -> Result<Vec<u8>, Error> {
        let iv = xor_iv(&self.iv, self.seq);
        let nonce = Nonce::from_slice(&iv);
        self.seq += 1;

        match self.cipher_suite {
            CipherSuite::TlsAes128GcmSha256 => {
                let key = Key::from_slice(&self.key);
                Aes128Gcm::new(key).encrypt_in_place(nonce, record_data, &mut wrapper)?;
                Ok(wrapper)
            }
            CipherSuite::TlsAes256GcmSha256 => {
                let key = Key::from_slice(&self.key);
                Aes256Gcm::new(key).encrypt_in_place(nonce, record_data, &mut wrapper)?;
                Ok(wrapper)
            }
        }
    }
}

pub fn xor_iv(iv: &[u8], mut num: u32) -> Vec<u8> {
    let mut iv_copy = vec![0; iv.len()];
    iv_copy.copy_from_slice(iv);
    let mut i = iv_copy.len() - 1;
    while num > 0 {
        iv_copy[i] ^= (num & 0xff) as u8;
        num >>= 8;
        i -= 1;
    }
    iv_copy
}

pub fn derive_handshake_keys(
    cipher_suite: CipherSuite,
    shared_secret: &[u8],
    hello_hash: &[u8; 32],
) -> Result<HandshakeKeys, Error> {
    let zeros = [0; 32];
    let empty_hash = Sha256::new().finalize();

    let (_, early_secret) = Hkdf::<Sha256>::extract(Some(&zeros), &zeros);
    let derived_secret = hkdf_expand_label(&early_secret, "derived", &empty_hash, 32)?;
    let (handshake_secret_data, handshake_secret) =
        Hkdf::<Sha256>::extract(Some(&derived_secret), shared_secret);

    let client_handshake_secret = Hkdf::<Sha256>::from_prk(&hkdf_expand_label(
        &handshake_secret,
        "c hs traffic",
        hello_hash,
        32,
    )?)?;
    let client_handshake_key = derive_symmetric_key(cipher_suite, &client_handshake_secret)?;
    let client_finished_key = hkdf_expand_label(&client_handshake_secret, "finished", &[], 32)?;

    let server_handshake_secret = Hkdf::<Sha256>::from_prk(&hkdf_expand_label(
        &handshake_secret,
        "s hs traffic",
        hello_hash,
        32,
    )?)?;
    let server_handshake_key = derive_symmetric_key(cipher_suite, &server_handshake_secret)?;
    let server_finished_key = hkdf_expand_label(&server_handshake_secret, "finished", &[], 32)?;

    Ok(HandshakeKeys {
        handshake_secret: handshake_secret_data.to_vec(),
        client_handshake_key,
        client_finished_key,
        server_handshake_key,
        server_finished_key,
    })
}

pub fn derive_application_keys(
    cipher_suite: CipherSuite,
    handshake_secret: &[u8],
    handshake_hash: &[u8; 32],
) -> Result<ApplicationKeys, Error> {
    let zeros = [0; 32];
    let empty_hash = Sha256::new().finalize();

    let handshake_secret = Hkdf::<Sha256>::from_prk(handshake_secret)?;
    let derived_secret = hkdf_expand_label(&handshake_secret, "derived", &empty_hash, 32)?;
    let (_, master_secret) = Hkdf::<Sha256>::extract(Some(&derived_secret), &zeros);

    let client_secret = Hkdf::<Sha256>::from_prk(&hkdf_expand_label(
        &master_secret,
        "c ap traffic",
        handshake_hash,
        32,
    )?)?;
    let server_secret = Hkdf::<Sha256>::from_prk(&hkdf_expand_label(
        &master_secret,
        "s hs traffic",
        handshake_hash,
        32,
    )?)?;

    Ok(ApplicationKeys {
        client_key: derive_symmetric_key(cipher_suite, &client_secret)?,
        server_key: derive_symmetric_key(cipher_suite, &server_secret)?,
    })
}

fn derive_symmetric_key(
    cipher_suite: CipherSuite,
    secret: &Hkdf<Sha256>,
) -> Result<SymmetricKey, Error> {
    let key_length = match cipher_suite {
        CipherSuite::TlsAes128GcmSha256 => 16,
        CipherSuite::TlsAes256GcmSha256 => 32,
    };
    let key = hkdf_expand_label(&secret, "key", &[], key_length)?;
    let iv = hkdf_expand_label(&secret, "iv", &[], 12)?;
    Ok(SymmetricKey {
        cipher_suite,
        key,
        iv,
        seq: 0,
    })
}

fn hkdf_expand_label(
    secret: &Hkdf<Sha256>,
    label: &str,
    context: &[u8],
    length: u16,
) -> Result<Vec<u8>, Error> {
    let mut key = vec![0; length.into()];
    let full_label = [b"tls13 " as &[u8], label.as_bytes()].concat();
    secret.expand_multi_info(
        &[
            &length.to_be_bytes(),
            &(full_label.len() as u8).to_be_bytes(),
            &full_label,
            &(context.len() as u8).to_be_bytes(),
            &context,
        ],
        &mut key,
    )?;
    Ok(key)
}

pub fn hmac(key: &[u8], msg: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(msg);
    mac
}
