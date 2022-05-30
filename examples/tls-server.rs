use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use native_tls::{Certificate, Identity, TlsAcceptor, TlsConnector};

const HOSTNAME: &str = "localhost";

fn accept(server: TcpListener, acceptor: TlsAcceptor) -> Result<(), Box<dyn std::error::Error>> {
    for stream in server.incoming() {
        let mut stream = acceptor.accept(stream?)?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        println!("{}", String::from_utf8_lossy(&buf));
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_store = pki::util::create_easy_server_chain(HOSTNAME)?;
    let pkcs8 = key_store.to_pkcs8()?;

    let identity = Identity::from_pkcs8(&pkcs8, &pkcs8)?;
    let acceptor = TlsAcceptor::builder(identity).build()?;
    let server = TcpListener::bind(format!("{}:8000", HOSTNAME))?;

    std::thread::spawn(move || {
        let _ = accept(server, acceptor);
    });

    let client = TcpStream::connect(format!("{}:8000", HOSTNAME))?;
    let connector = TlsConnector::builder()
        .add_root_certificate(Certificate::from_der(
            &key_store.certs().last().unwrap().to_der()?,
        )?)
        .build()?;
    let mut client = connector.connect(HOSTNAME, client)?;
    client.write_all(b"ping")?;
    client.shutdown()?;

    Ok(())
}
