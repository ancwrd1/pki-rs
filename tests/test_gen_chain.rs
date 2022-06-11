use std::{
    ops::Add,
    time::{Duration, SystemTime},
};

use pki::{
    CertName, CertUsage, CertificateBuilder, CertificateVerifier, KeyStore, PrivateKey, Result,
};

const PASSWORD: &str = "changeit";
const CN: &str = "mycert";

fn gen_ca_store(cn: &str, signer: Option<&KeyStore>) -> Result<KeyStore> {
    let mut builder = CertificateBuilder::new();

    let subject = CertName::new([("C", "US"), ("O", "Acme"), ("CN", cn)])?;

    builder
        .subject(subject)
        .signer(signer)
        .usage(CertUsage::CA)
        .not_after(SystemTime::now().add(Duration::from_secs(365 * 10 * 24 * 60 * 60)))
        .private_key(PrivateKey::new_ec()?);

    let store = builder.build()?;

    CertificateVerifier::new()
        .ca_root(store.certs().last().unwrap())
        .verify(store.certs())?;

    Ok(store)
}

fn gen_entity_store(signer: &KeyStore) -> Result<KeyStore> {
    let mut builder = CertificateBuilder::new();

    let subject = CertName::new([("C", "US"), ("O", "Acme"), ("CN", CN)])?;

    builder
        .subject(subject)
        .signer(signer)
        .usage(CertUsage::TlsClient)
        .alt_names(["192.168.1.1", "acme.home.lan"])
        .private_key(PrivateKey::new_ec()?);

    let store = builder.build()?;

    CertificateVerifier::new()
        .ca_root(signer.certs().last().unwrap())
        .verify(store.certs())?;

    Ok(store)
}

fn assert_parsed(parsed: &KeyStore) {
    assert!(parsed.certs()[0]
        .subject_name()
        .entries()
        .any(|(k, v)| k == "CN" && v == CN));

    assert!(parsed.certs()[1]
        .subject_name()
        .entries()
        .any(|(k, v)| k == "CN" && v == "Intermediate CA"));

    assert!(parsed.certs()[2]
        .subject_name()
        .entries()
        .any(|(k, v)| k == "CN" && v == "Root CA"));
}

fn gen_chain() -> Result<()> {
    let root_store = gen_ca_store("Root CA", None)?;
    let intermediate_store = gen_ca_store("Intermediate CA", Some(&root_store))?;
    let entity_store = gen_entity_store(&intermediate_store)?;

    let pkcs12 = entity_store.to_pkcs12(CN, PASSWORD)?;
    //std::fs::write("/tmp/keystore.p12", &pkcs12).unwrap();
    let parsed = KeyStore::from_pkcs12(&pkcs12, PASSWORD)?;
    assert_parsed(&parsed);

    let pkcs8 = entity_store.to_pkcs8()?;
    //std::fs::write("/tmp/keystore.pem", &pkcs8).unwrap();
    let parsed = KeyStore::from_pkcs8(&pkcs8)?;
    assert_parsed(&parsed);

    Ok(())
}

#[test]
fn test_gen_chain() {
    gen_chain().unwrap();
}
