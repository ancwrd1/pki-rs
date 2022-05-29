use std::{
    ops::Add,
    time::{Duration, SystemTime},
};

use pki_rs::{
    CertName, CertUsage, CertificateBuilder, CertificateVerifier, KeyStore, PrivateKey, Result,
};

const PASSWORD: &str = "changeit";

fn gen_ca_store(cn: &str, signer: Option<&KeyStore>) -> Result<KeyStore> {
    let mut builder = CertificateBuilder::new();

    if let Some(signer) = signer {
        builder.signer(signer);
    }

    builder
        .subject(CertName::new([
            ("C", "DK"),
            ("O", "EveryonePrint"),
            ("CN", cn),
        ])?)
        .usage(CertUsage::Ca)
        .not_after(SystemTime::now().add(Duration::from_secs(365 * 10 * 24 * 60 * 60)))
        .private_key(PrivateKey::new_ec()?);

    let store = builder.build()?;

    CertificateVerifier::new()
        .ca_root(&store.certs().last().unwrap())
        .verify(store.certs())?;

    Ok(store)
}

fn gen_entity_store(signer: &KeyStore) -> Result<KeyStore> {
    let cn = "mycert";
    let mut builder = CertificateBuilder::new();

    builder
        .subject(CertName::new([
            ("C", "DK"),
            ("O", "EveryonePrint"),
            ("CN", cn),
        ])?)
        .signer(signer)
        .usage(CertUsage::Client)
        .alt_names(["172.22.1.1", "t14s.home.lan"])
        .private_key(PrivateKey::new_ec()?);

    let store = builder.build()?;

    CertificateVerifier::new()
        .ca_root(&signer.certs().last().unwrap())
        .verify(store.certs())?;

    Ok(store)
}

fn gen_chain() -> Result<()> {
    let root_store = gen_ca_store("Root CA", None)?;
    let intermediate_store = gen_ca_store("Intermediate CA", Some(&root_store))?;
    let entity_store = gen_entity_store(&intermediate_store)?;

    let pkcs12 = entity_store.to_pkcs12("mycert", PASSWORD)?;
    //std::fs::write("/tmp/keystore.p12", &pkcs12).unwrap();
    KeyStore::from_pkcs12(&pkcs12, PASSWORD)?;

    Ok(())
}

#[test]
fn test_gen_chain() {
    gen_chain().unwrap();
}
