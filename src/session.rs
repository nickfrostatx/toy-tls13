use std::io::{Read, Write};
use std::net::TcpStream;

use hmac::Mac;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::crypto::{self, ApplicationKeys, SymmetricKey};
use crate::error::Error;
use crate::network::{self, CertificateMessage, Handshake, Record, RecordType};

pub struct TlsSession {
    stream: TcpStream,
    application_keys: ApplicationKeys,
}

impl TlsSession {
    pub fn connect(address: &str, server_name: &str) -> Result<Self, Error> {
        let mut stream = TcpStream::connect(address)?;

        let mut handshake_hasher = Sha256::new();

        let private_key = EphemeralSecret::new(OsRng);
        let public_key = PublicKey::from(&private_key);

        let mut client_random = [0; 32];
        OsRng.fill_bytes(&mut client_random);

        // generate private key
        let client_hello_payload =
            network::client_hello_packet(&client_random, server_name, public_key.as_bytes());
        network::write_record(&mut stream, RecordType::Handshake, &client_hello_payload)?;
        handshake_hasher.update(&client_hello_payload);

        let (server_hello, server_hello_payload) = match network::read_record(&mut stream)? {
            (Record::Handshake(Handshake::ServerHello(server_hello)), _, payload) => {
                (server_hello, payload)
            }
            (Record::Alert(alert), _, _) => panic!("{:?}", alert),
            _ => panic!("expected server hello"),
        };
        handshake_hasher.update(&server_hello_payload);

        let cipher_suite = server_hello.cipher_suite;
        let server_handshake_public_key = PublicKey::from(server_hello.server_public_key.clone());
        let shared_secret = private_key.diffie_hellman(&server_handshake_public_key);
        // Copy because finalize() moves the hasher
        let tmp_hasher = handshake_hasher.clone();
        let hello_hash = tmp_hasher.finalize().into();

        let mut handshake_keys =
            crypto::derive_handshake_keys(cipher_suite, shared_secret.as_bytes(), &hello_hash)?;

        let mut got_finished = false;
        let mut _certificates: Option<CertificateMessage> = None;
        while !got_finished {
            for (record, handshake_hash) in Self::read_wrapped_handshake_records(
                &mut stream,
                &mut handshake_keys.server_handshake_key,
                &mut handshake_hasher,
            )? {
                match record {
                    Handshake::EncryptedExtensions => {}
                    Handshake::Certificate(cert_message) => {
                        _certificates = Some(cert_message);
                        // TODO: verify certificate
                    }
                    Handshake::CertificateVerify(_signature) => {
                        // TODO: verify certificate signature
                    }
                    Handshake::Finished(finished) => {
                        let correct_finished_hash =
                            crypto::hmac(&handshake_keys.server_finished_key, &handshake_hash);
                        if correct_finished_hash
                            .verify_slice(&finished.signature)
                            .is_err()
                        {
                            panic!("Bad server finished");
                        }
                        got_finished = true;
                    }
                    Handshake::ServerHello(_) => panic!("Got another server hello"),
                }
            }
        }

        // This is not part of the handshake hash
        network::write_record(&mut stream, RecordType::ChangeCipherSpec, b"\x01")?;

        let handshake_hash: [u8; 32] = handshake_hasher.finalize().into();
        let client_finished_hash =
            crypto::hmac(&handshake_keys.client_finished_key, &handshake_hash)
                .finalize()
                .into_bytes();
        let client_finished_payload = network::client_finished_packet(&client_finished_hash);
        Self::write_wrapped_record(
            &mut stream,
            &mut handshake_keys.client_handshake_key,
            RecordType::Handshake,
            &client_finished_payload,
        )?;

        let application_keys = crypto::derive_application_keys(
            cipher_suite,
            &handshake_keys.handshake_secret[..],
            &handshake_hash,
        )?;

        Ok(Self {
            stream: TcpStream::connect(address)?,
            application_keys: application_keys,
        })
    }

    fn read_wrapped_handshake_records(
        stream: &mut impl Read,
        key: &mut SymmetricKey,
        hasher: &mut Sha256,
    ) -> Result<Vec<(Handshake, [u8; 32])>, Error> {
        match network::read_record(stream)? {
            (Record::ApplicationData, record_header, payload) => {
                let decrypted_payload = key.decrypt(&record_header, payload)?;

                let record_type_byte = decrypted_payload[decrypted_payload.len() - 1];
                if record_type_byte != 0x16 {
                    panic!("Expected handshake record. Got: 0x{:02x}", record_type_byte);
                }

                // TODO: this should live in network.rs
                let mut i = 0;
                let mut handshakes = Vec::new();
                while i < decrypted_payload.len() - 4 {
                    let len =
                        u16::from_be_bytes(decrypted_payload[i + 2..i + 4].try_into().unwrap())
                            as usize;
                    let new_hasher = hasher.clone();
                    let hash = new_hasher.finalize().into();
                    let handshake_payload = &decrypted_payload[i..i + len + 4];
                    handshakes.push((network::parse_handshake(handshake_payload), hash));
                    hasher.update(handshake_payload);
                    i += len + 4;
                }
                Ok(handshakes)
            }
            (Record::ChangeCipherSpec, _, _) => {
                Self::read_wrapped_handshake_records(stream, key, hasher)
            }
            (Record::Alert(alert), _, _) => panic!("{:?}", alert),
            (record_type, _, _) => panic!("Unexpected record type {:?}", record_type),
        }
    }

    fn write_wrapped_record(
        stream: &mut impl Write,
        key: &mut SymmetricKey,
        record_type: RecordType,
        record: &[u8],
    ) -> Result<(), Error> {
        let payload = [
            record,
            // Wrapped record type
            &[network::record_type_byte(record_type)],
        ]
        .concat();

        // encrypted_payload should be 16 bytes longer than payload for the AEAD tag
        let record_header =
            network::make_record_header(RecordType::ApplicationData, payload.len() as u16 + 16);
        let encrypted_payload = key.encrypt(&record_header, payload)?;

        network::write_record(stream, RecordType::ApplicationData, &encrypted_payload)?;

        Ok(())
    }

    pub fn write(&mut self, payload: &[u8]) -> Result<(), Error> {
        Self::write_wrapped_record(
            &mut self.stream,
            &mut self.application_keys.client_key,
            RecordType::ApplicationData,
            payload,
        )
    }
}
