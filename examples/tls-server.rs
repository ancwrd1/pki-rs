use std::net::Shutdown;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use native_tls::{Certificate, Identity, TlsAcceptor, TlsConnector};

const HOSTNAME: &str = "localhost";
const PORT: u16 = 8000;

fn accept(server: TcpListener, acceptor: TlsAcceptor) -> Result<(), Box<dyn std::error::Error>> {
    for stream in server.incoming() {
        let mut tls_stream = acceptor.accept(stream?)?;
        let mut buf = Vec::new();
        tls_stream.read_to_end(&mut buf)?;
        println!("{}", String::from_utf8_lossy(&buf));
        tls_stream.get_ref().shutdown(Shutdown::Read)?;
        tls_stream.write_all(b"pong")?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_store = pki::util::create_easy_server_chain(HOSTNAME)?;
    let pkcs8 = key_store.to_pkcs8()?;

    let identity = Identity::from_pkcs8(&pkcs8, &pkcs8)?;
    let acceptor = TlsAcceptor::builder(identity).build()?;
    let server = TcpListener::bind(format!("{}:{}", HOSTNAME, PORT))?;

    std::thread::spawn(move || {
        let _ = accept(server, acceptor);
    });

    let client = TcpStream::connect(format!("{}:{}", HOSTNAME, PORT))?;
    let connector = TlsConnector::builder()
        .add_root_certificate(Certificate::from_der(
            &key_store.certs().last().unwrap().to_der()?,
        )?)
        .build()?;
    let mut tls_stream = connector.connect(HOSTNAME, client)?;
    tls_stream.write_all(b"ping")?;
    tls_stream.get_ref().shutdown(Shutdown::Write)?;

    let mut reply = Vec::new();
    tls_stream.read_to_end(&mut reply)?;
    println!("{}", String::from_utf8_lossy(&reply));

    Ok(())
}
