use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::Arc,
};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, Stream,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer};

const HOSTNAME: &str = "localhost";
const PORT: u16 = 8000;

fn accept(
    server: TcpListener,
    config: Arc<ServerConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    for stream in server.incoming() {
        let mut stream = stream?;
        let mut connection = ServerConnection::new(config.clone())?;
        let mut tls_stream = Stream::new(&mut connection, &mut stream);
        let mut buf = vec![0u8; 4];
        tls_stream.read_exact(&mut buf)?;
        println!("{}", String::from_utf8_lossy(&buf));
        tls_stream.sock.shutdown(Shutdown::Read)?;
        tls_stream.write_all(b"pong")?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_store = pki::util::create_easy_server_chain(HOSTNAME)?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            key_store
                .certs()
                .iter()
                .map(|s| CertificateDer::from(s.to_der().unwrap()))
                .collect(),
            PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(key_store.private_key().to_der()?)),
        )?;

    let server = TcpListener::bind(format!("{}:{}", HOSTNAME, PORT))?;

    std::thread::spawn(move || {
        let _ = accept(server, Arc::new(server_config));
    });

    let mut cert_store = RootCertStore::empty();
    cert_store.add(CertificateDer::from(
        key_store.certs().last().unwrap().to_der()?,
    ))?;

    let client_config = ClientConfig::builder()
        .with_root_certificates(cert_store)
        .with_no_client_auth();

    let mut connection = ClientConnection::new(Arc::new(client_config), HOSTNAME.try_into()?)?;
    let mut client = TcpStream::connect(format!("{}:{}", HOSTNAME, PORT))?;

    let mut tls_stream = Stream::new(&mut connection, &mut client);
    tls_stream.write_all(b"ping")?;
    tls_stream.sock.shutdown(Shutdown::Write)?;

    let mut reply = vec![0u8; 4];
    tls_stream.read_exact(&mut reply)?;
    println!("{}", String::from_utf8_lossy(&reply));

    Ok(())
}
