use std::io::{Read, Write};

#[derive(Debug)]
pub enum RecordType {
    ChangeCipherSpec,
    Handshake,
    ApplicationData,
}

#[derive(Debug)]
pub enum Record {
    ChangeCipherSpec,
    Alert(Alert),
    Handshake(Handshake),
    ApplicationData,
}

#[derive(Debug)]
pub enum Handshake {
    ServerHello(ServerHello),
    EncryptedExtensions,
    Certificate(CertificateMessage),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
}

#[derive(Debug)]
pub struct ServerHello {
    pub server_public_key: [u8; 32],
    pub server_random: [u8; 32],
    pub cipher_suite: CipherSuite,
}

#[derive(Debug)]
pub struct CertificateMessage {
    pub certificates: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub struct CertificateVerify {
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub struct Finished {
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub enum CipherSuite {
    TlsAes128GcmSha256,
    TlsAes256GcmSha256,
}

#[derive(Debug)]
pub struct Alert {
    pub severity: &'static str,
    pub description: &'static str,
}

pub fn write_record(
    stream: &mut impl Write,
    record_type: RecordType,
    payload: &[u8],
) -> std::io::Result<()> {
    let record = [
        &make_record_header(record_type, payload.len() as u16),
        payload,
    ]
    .concat();
    stream.write(&record)?;
    Ok(())
}

pub fn make_record_header(record_type: RecordType, payload_len: u16) -> Vec<u8> {
    [
        &[record_type_byte(record_type)] as &[u8],
        b"\x03\x03",
        &payload_len.to_be_bytes(),
    ]
    .concat()
}

pub fn record_type_byte(record_type: RecordType) -> u8 {
    match record_type {
        RecordType::ChangeCipherSpec => 0x14,
        RecordType::Handshake => 0x16,
        RecordType::ApplicationData => 0x17,
    }
}

pub fn client_hello_packet(
    client_random: &[u8],
    server_name: &str,
    client_public_key: &[u8],
) -> Vec<u8> {
    let server_name_bytes = server_name.as_bytes();
    let ext_server_name = [
        // assigned value for ext "server name"
        b"\x00\x00" as &[u8],
        // length of "server name" ext data
        &(server_name_bytes.len() as u16 + 5).to_be_bytes(),
        // length of first (and only) list entry
        &(server_name_bytes.len() as u16 + 3).to_be_bytes(),
        // list entry is type 0x00 "DNS hostname"
        b"\x00",
        // length of hostname
        &(server_name_bytes.len() as u16).to_be_bytes(),
        server_name_bytes,
    ]
    .concat();

    let ext_key_share = [
        b"\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20",
        client_public_key,
    ]
    .concat();

    let exts = [
        &ext_server_name as &[u8],
        // Supported Groups
        b"\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18",
        // Signature Algorithms
        b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05",
        b"\x05\x01\x08\x06\x06\x01\x02\x01",
        &ext_key_share,
        // PSK Key Exchange Modes
        b"\x00\x2d\x00\x02\x01\x01",
        // Supported Versions
        b"\x00\x2b\x00\x03\x02\x03\x04",
    ]
    .concat();

    let hello_message = [
        // Client Version
        b"\x03\x03",
        client_random,
        // Fake Session ID
        b"\x20\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef",
        b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
        // Cipher Suites
        b"\x00\x02\x13\x01",
        // Compression Methods
        b"\x01\x00",
        &(exts.len() as u16).to_be_bytes(),
        &exts,
    ]
    .concat();

    let packet = [
        // Handshake header
        b"\x01\x00" as &[u8],
        &(hello_message.len() as u16).to_be_bytes(),
        &hello_message,
    ]
    .concat();

    packet
}

pub fn client_finished_packet(verify_data: &[u8]) -> Vec<u8> {
    [
        // Handshake header
        b"\x14\x00" as &[u8],
        &(verify_data.len() as u16).to_be_bytes(),
        verify_data,
    ]
    .concat()
}

pub fn read_record(stream: &mut impl Read) -> std::io::Result<(Record, [u8; 5], Vec<u8>)> {
    let mut record_header = [0; 5];
    stream.read(&mut record_header)?;

    let length = u16::from_be_bytes(record_header[3..5].try_into().unwrap());

    let mut payload = vec![0; length.into()];
    stream.read(&mut payload)?;

    let record = match record_header[0] {
        0x14 => Record::ChangeCipherSpec,
        0x15 => Record::Alert(parse_alert(&payload)),
        0x16 => Record::Handshake(parse_handshake(&payload)),
        0x17 => Record::ApplicationData,
        _ => panic!("unknown record type 0x{:02x}", record_header[0]),
    };

    Ok((record, record_header, payload))
}

pub fn parse_handshake(payload: &[u8]) -> Handshake {
    match payload[0] {
        0x02 => Handshake::ServerHello(parse_server_hello(payload)),
        0x08 => Handshake::EncryptedExtensions,
        0x0b => Handshake::Certificate(parse_certificate_message(payload)),
        0x0f => {
            let mut payload_copy = vec![0; payload.len() - 4];
            payload_copy.copy_from_slice(&payload[4..]);
            Handshake::CertificateVerify(CertificateVerify {
                signature: payload_copy,
            })
        }
        0x14 => {
            let mut payload_copy = vec![0; payload.len() - 4];
            payload_copy.copy_from_slice(&payload[4..]);
            Handshake::Finished(Finished {
                signature: payload_copy,
            })
        }
        _ => panic!("Unexpected handshake type: 0x{:02x}", payload[0]),
    }
}

fn parse_server_hello(payload: &[u8]) -> ServerHello {
    let mut server_random = [0; 32];
    server_random.clone_from_slice(&payload[6..38]);

    let cipher_suite = match &payload[71..73] {
        b"\x13\x01" => CipherSuite::TlsAes128GcmSha256,
        b"\x13\x02" => CipherSuite::TlsAes256GcmSha256,
        _ => panic!(
            "Unexpected cipher suite: 0x{:02x}{:02x}",
            payload[71], payload[72]
        ),
    };

    let mut supports_tls13 = false;
    let mut server_public_key = [0; 32];

    let mut ext_start: usize = 76;
    while ext_start + 4 < payload.len() {
        let ext_type = &payload[ext_start..ext_start + 2];
        let ext_length =
            u16::from_be_bytes(payload[ext_start + 2..ext_start + 4].try_into().unwrap()) as usize;
        let ext_payload = &payload[ext_start + 4..ext_start + 4 + ext_length];

        if ext_type == b"\x00\x2b" {
            // Supported versions
            for i in (0..ext_payload.len()).step_by(2) {
                if &ext_payload[i..i + 2] == b"\x03\x04" {
                    supports_tls13 = true;
                    break;
                }
            }
        } else if ext_type == b"\x00\x33" {
            // Key share
            if &ext_payload[..2] != b"\x00\x1d" {
                panic!("Expected x25519");
            }
            server_public_key.clone_from_slice(&ext_payload[4..36]);
        }

        ext_start += ext_length + 4;
    }

    if !supports_tls13 {
        panic!("Server doesn't support TLSv1.3");
    }

    ServerHello {
        server_random,
        server_public_key,
        cipher_suite,
    }
}

fn parse_certificate_message(payload: &[u8]) -> CertificateMessage {
    let certs_end = u16::from_be_bytes(payload[6..8].try_into().unwrap()) as usize + 8;
    let mut cert_start = 8;
    let mut certificates = Vec::new();
    while cert_start + 3 < certs_end {
        let len = u16::from_be_bytes(payload[cert_start + 1..cert_start + 3].try_into().unwrap())
            as usize;
        let cert_slice = &payload[cert_start + 3..cert_start + 3 + len];
        let mut cert = vec![0; cert_slice.len()];
        cert.copy_from_slice(cert_slice);
        certificates.push(cert);
        let cert_extensions_len = u16::from_be_bytes(
            payload[cert_start + 3 + len..cert_start + 3 + len + 2]
                .try_into()
                .unwrap(),
        ) as usize;
        assert_eq!(cert_extensions_len, 0);
        cert_start += len + 5 + cert_extensions_len;
    }
    CertificateMessage { certificates }
}

fn parse_alert(payload: &[u8]) -> Alert {
    let severity = match payload[0] {
        0x01 => "warning",
        0x02 => "fatal",
        _ => "unknown level",
    };
    let description = match payload[1] {
        0x00 => "Close Notify",
        0x0a => "Unexpected Message",
        0x14 => "Bad Record Mac",
        0x15 => "Decryption Failed",
        0x16 => "Record Overflow",
        0x1e => "Decompression Failure",
        0x28 => "Handshake Failure",
        0x29 => "No Certificate",
        0x2a => "Bad Certificate",
        0x2b => "Unsupported Certificate",
        0x2c => "Certificate Revoked",
        0x2d => "Certificate Expired",
        0x2e => "Certificate Unknown",
        0x2f => "Illegal Parameter",
        0x30 => "Unknown CA",
        0x31 => "Access Denied",
        0x32 => "Decode Error",
        0x33 => "Decrypt Error",
        0x3c => "Export Restriction",
        0x46 => "Protocol Version",
        0x47 => "Insufficient Security",
        0x50 => "Internal Error",
        0x56 => "Inappropriate Fallback",
        0x5a => "User Canceled",
        0x64 => "No Renegotiation",
        0x6d => "Missing Extension",
        0x6e => "Unsupported Extension",
        0x6f => "Certificate Unobtainable",
        0x70 => "Unrecognised Name",
        0x71 => "Bad Certificate Status Response",
        0x72 => "Bad Certificate Hash Value",
        0x73 => "Unknown PSK Identity",
        0x74 => "Certificate Required",
        0x78 => "No Application Protocol",
        _ => "(unrecognized alert)",
    };
    Alert {
        severity,
        description,
    }
}
