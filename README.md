# PKI tools for Rust

This project contains Rust library for PKI-related tasks such as generating and validating certificate chains.
It can be used to easily create certificate chains on the fly for testing purposes.

See `tests/test_gen_chain.rs` and `examples/tls-server.rs` for detailed examples. 

## Server example (native-tls)

```rust,no_run
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_store = pki::util::create_easy_server_chain(HOSTNAME)?;
    let pkcs8 = key_store.to_pkcs8()?;

    let identity = Identity::from_pkcs8(&pkcs8, &pkcs8)?;
    let acceptor = TlsAcceptor::builder(identity).build()?;
    let server = TcpListener::bind(format!("{}:{}", HOSTNAME, PORT))?;
    for stream in server.incoming() {
        let mut stream = acceptor.accept(stream?)?;
    }
}
```

## Client example (native-tls)

```rust,no_run
fn client(key_store: &KeyStore) -> Result<(), Box<dyn std::error::Error>> {
    let client = TcpStream::connect(format!("{}:{}", HOSTNAME, PORT))?;
    let connector = TlsConnector::builder()
        .add_root_certificate(Certificate::from_der(
            &key_store.certs().last().unwrap().to_der()?,
        )?)
        .build()?;
    let mut client = connector.connect(HOSTNAME, client)?;
}
```

## License

Licensed under MIT or Apache license ([LICENSE-MIT](https://opensource.org/licenses/MIT) or [LICENSE-APACHE](https://opensource.org/licenses/Apache-2.0))
