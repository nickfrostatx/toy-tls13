use derive_more::{Display, From};

#[derive(Debug, Display, From)]
pub enum Error {
    AesError(aes_gcm::aead::Error),
    HkdfInvalidLength(hkdf::InvalidLength),
    HkdfInvalidPrkLength(hkdf::InvalidPrkLength),
    IoError(std::io::Error),
}

impl std::error::Error for Error {}
