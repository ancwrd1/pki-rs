//! Utility functions
use std::{
    ops::Add,
    time::{Duration, SystemTime},
};

use crate::{CertName, CertUsage, CertificateBuilder, KeyStore, PrivateKey, Result};

fn gen_ca_store() -> Result<KeyStore> {
    CertificateBuilder::new()
        .subject(CertName::new([("CN", "Root CA")])?)
        .usage(CertUsage::CA)
        .not_after(SystemTime::now().add(Duration::from_secs(365 * 10 * 24 * 60 * 60)))
        .private_key(PrivateKey::new_rsa(2048)?)
        .build()
}

fn gen_entity_store(signer: &KeyStore, hostname: &str) -> Result<KeyStore> {
    CertificateBuilder::new()
        .subject(CertName::new([("CN", hostname)])?)
        .signer(signer)
        .usage(CertUsage::TlsServer)
        .alt_names([hostname])
        .private_key(PrivateKey::new_rsa(2048)?)
        .build()
}

/// Easily create a certificate chain to be used by TLS servers.
/// The chain will contain two certificates: the leaf `hostname` certificate and `Root CA` root certificate.
pub fn create_easy_server_chain(hostname: &str) -> Result<KeyStore> {
    let ca_store = gen_ca_store()?;
    gen_entity_store(&ca_store, hostname)
}
