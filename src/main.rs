mod crypto;
mod error;
mod network;
mod session;

use session::TlsSession;

fn test() -> Result<(), error::Error> {
    let hostname = "www.google.com";
    let mut session = TlsSession::connect(&format!("{}:443", hostname), hostname)?;
    session.write(format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", hostname).as_bytes())?;
    Ok(())
}

fn main() {
    match test() {
        Ok(_) => {}
        Err(err) => panic!("{:?}", err),
    };
}
