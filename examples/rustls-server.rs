use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::Arc,
};

use rustls::{
    Certificate, ClientConfig, ClientConnection, PrivateKey, RootCertStore, ServerConfig,
    ServerConnection, Stream,
};

const HOSTNAME: &str = "localhost";
const PORT: u16 = 8000;

fn accept(
    server: TcpListener,
    mut connection: ServerConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    for stream in server.incoming() {
        let mut stream = stream?;
        let mut tls_stream = Stream::new(&mut connection, &mut stream);
        let mut buf = Vec::new();
        tls_stream.read_to_end(&mut buf)?;
        println!("{}", String::from_utf8_lossy(&buf));
        tls_stream.sock.shutdown(Shutdown::Read)?;
        tls_stream.write_all(b"pong")?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_store = pki::util::create_easy_server_chain(HOSTNAME)?;

    let server_config = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            key_store
                .certs()
                .iter()
                .map(|s| Certificate(s.to_der().unwrap()))
                .collect(),
            PrivateKey(key_store.private_key().to_der()?),
        )?;

    let connection = ServerConnection::new(Arc::new(server_config))?;
    let server = TcpListener::bind(format!("{}:{}", HOSTNAME, PORT))?;

    std::thread::spawn(move || {
        let _ = accept(server, connection);
    });

    let mut cert_store = RootCertStore::empty();
    cert_store.add(&Certificate(key_store.certs().last().unwrap().to_der()?))?;

    let client_config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()?
        .with_root_certificates(cert_store)
        .with_no_client_auth();

    let mut connection = ClientConnection::new(Arc::new(client_config), HOSTNAME.try_into()?)?;
    let mut client = TcpStream::connect(format!("{}:{}", HOSTNAME, PORT))?;

    let mut tls_stream = Stream::new(&mut connection, &mut client);
    tls_stream.write_all(b"ping")?;
    tls_stream.sock.shutdown(Shutdown::Write)?;

    let mut reply = Vec::new();
    tls_stream.read_to_end(&mut reply)?;
    println!("{}", String::from_utf8_lossy(&reply));

    Ok(())
}
