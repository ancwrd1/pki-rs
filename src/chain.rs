//! Certificate chain generation and validation
use std::{
    net::Ipv4Addr,
    ops::Add,
    time::{Duration, SystemTime},
};

use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    stack::Stack,
    x509::{self, store::X509StoreBuilder, X509StoreContext, X509},
};

use crate::model::{CertName, CertUsage, Certificate, KeyStore, PkiError, PrivateKey, Result};

/// Default validity days of the entity certificate
pub const DEFAULT_CERT_VALIDITY_DAYS: u64 = 825;

/// Default RSA key size
pub const DEFAULT_RSA_KEY_LENGTH: u32 = 2048;

/// Certificate builder is used to create X.509 certificate chains
pub struct CertificateBuilder<'a> {
    signer: Option<&'a KeyStore>,
    subject: Option<CertName>,
    usage: CertUsage,
    alt_names: Vec<String>,
    not_before: SystemTime,
    not_after: SystemTime,
    serial_number: Option<u128>,
    path_len: i32,
    private_key: Option<PrivateKey>,
}

impl<'a> Default for CertificateBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> CertificateBuilder<'a> {
    /// Create a new certificate builder with default parameters
    pub fn new() -> Self {
        Self {
            signer: None,
            subject: None,
            usage: CertUsage::TlsServer,
            alt_names: Vec::new(),
            not_before: SystemTime::now(),
            not_after: SystemTime::now().add(Duration::from_secs(
                DEFAULT_CERT_VALIDITY_DAYS * 24 * 60 * 60,
            )),
            serial_number: None,
            path_len: i32::MAX,
            private_key: None,
        }
    }

    /// Specify certificate signer. If omitted or None a self-signed certificate is created.
    pub fn signer<S>(&mut self, signer: S) -> &mut Self
    where
        S: Into<Option<&'a KeyStore>>,
    {
        self.signer = signer.into();
        self
    }

    /// Specify certificate usage
    pub fn usage(&mut self, usage: CertUsage) -> &mut Self {
        self.usage = usage;
        self
    }

    /// Specify DNS or IP names for the subjectAltName extension.
    /// This is a required setting for the TLS SNI matching.
    pub fn alt_names<S, I>(&mut self, alt_names: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.alt_names = alt_names
            .into_iter()
            .map(|name| name.as_ref().to_owned())
            .collect::<Vec<_>>();
        self
    }

    /// Specify start date of the certificate
    pub fn not_before(&mut self, time: SystemTime) -> &mut Self {
        self.not_before = time;
        self
    }

    /// Specify expiration date of the certificate
    pub fn not_after(&mut self, time: SystemTime) -> &mut Self {
        self.not_after = time;
        self
    }

    /// Specify a custom private key for the certificate chain.
    /// If not specified a default RSA-2048 key will be generated.
    pub fn private_key(&mut self, key: PrivateKey) -> &mut Self {
        self.private_key = Some(key);
        self
    }

    /// Specify certificate subject
    pub fn subject(&mut self, name: CertName) -> &mut Self {
        self.subject = Some(name);
        self
    }

    /// Specify serial number for the certificate, default is current Unix timestamp.
    pub fn serial_number(&mut self, number: u64) -> &mut Self {
        self.serial_number = Some(number as u128);
        self
    }

    /// Specify pathlen parameter for CA certificate, default is i32::MAX
    pub fn path_len(&mut self, path_len: i32) -> &mut Self {
        self.path_len = path_len;
        self
    }

    /// Create X.509 certificate chain
    pub fn build(&self) -> Result<KeyStore> {
        let cert_key = match self.private_key {
            Some(ref private_key) => private_key.clone(),
            None => PrivateKey::new_rsa(DEFAULT_RSA_KEY_LENGTH)?,
        };

        let empty_name: CertName;
        let subject = match self.subject.as_ref() {
            Some(subject) => subject.0.as_ref(),
            None => {
                empty_name = CertName::new([] as [(&str, &str); 0])?;
                empty_name.0.as_ref()
            }
        };

        let mut builder = X509::builder()?;
        builder.set_pubkey(&cert_key.0)?;
        builder.set_version(2)?;
        builder.set_issuer_name(
            self.signer
                .map(|s| s.certs()[0].subject_name().into())
                .unwrap_or(subject),
        )?;
        builder.set_not_before(
            Asn1Time::from_unix(
                self.not_before
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs() as _,
            )?
            .as_ref(),
        )?;
        builder.set_not_after(
            Asn1Time::from_unix(
                self.not_after
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs() as _,
            )?
            .as_ref(),
        )?;
        builder.set_subject_name(subject)?;

        let serial_number = match self.serial_number {
            Some(number) => number.to_be_bytes(),
            None => SystemTime::UNIX_EPOCH.elapsed()?.as_millis().to_be_bytes(),
        };
        let asn_number = Asn1Integer::from_bn(BigNum::from_slice(&serial_number)?.as_ref())?;
        builder.set_serial_number(&asn_number)?;

        // man x509v3_config
        let mut basic_cons = x509::extension::BasicConstraints::new();

        if self.usage == CertUsage::CA {
            basic_cons.ca().critical().pathlen(self.path_len as _);
        }
        builder.append_extension(basic_cons.build()?)?;

        let subj_key = x509::extension::SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))?;

        builder.append_extension(subj_key)?;

        let auth_key = x509::extension::AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&builder.x509v3_context(self.signer.map(|s| s.certs()[0].0.as_ref()), None))?;

        builder.append_extension(auth_key)?;

        if self.usage != CertUsage::CA {
            let mut extended_key_usage = x509::extension::ExtendedKeyUsage::new();
            match self.usage {
                CertUsage::TlsServer => {
                    extended_key_usage.server_auth();
                }
                CertUsage::TlsClient => {
                    extended_key_usage.client_auth();
                }
                CertUsage::CodeSign => {
                    extended_key_usage.code_signing();
                }
                CertUsage::TlsServerAndClient => {
                    extended_key_usage.server_auth().client_auth();
                }
                _ => {}
            }
            builder.append_extension(extended_key_usage.build()?)?;
        }

        let mut key_usage = x509::extension::KeyUsage::new();
        match self.usage {
            CertUsage::CA => {
                key_usage.key_cert_sign().crl_sign();
            }
            CertUsage::TlsServer | CertUsage::TlsClient | CertUsage::TlsServerAndClient => {
                key_usage
                    .digital_signature()
                    .non_repudiation()
                    .key_encipherment()
                    .data_encipherment();
            }
            CertUsage::CodeSign => {
                key_usage.digital_signature().non_repudiation();
            }
        }
        builder.append_extension(key_usage.build()?)?;

        if !self.alt_names.is_empty() {
            let mut subj_alt_name = x509::extension::SubjectAlternativeName::new();
            for name in &self.alt_names {
                if name.parse::<Ipv4Addr>().is_ok() {
                    subj_alt_name.ip(name);
                } else {
                    subj_alt_name.dns(name);
                }
            }
            builder.append_extension(subj_alt_name.build(&builder.x509v3_context(None, None))?)?;
        }

        if let Some(signer) = self.signer {
            builder.sign(&signer.private_key().0, MessageDigest::sha256())?;
        } else {
            builder.sign(&cert_key.0, MessageDigest::sha256())?;
        }

        let mut certs: Vec<Certificate> = vec![builder.build().into()];
        if let Some(signer) = self.signer {
            for cert in signer.certs() {
                certs.push(cert.clone());
            }
        }

        KeyStore::new(cert_key, certs)
    }
}

/// Certificate chain verifier
pub struct CertificateVerifier<'a> {
    roots: Vec<&'a Certificate>,
    default_paths: bool,
}

impl<'a> Default for CertificateVerifier<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> CertificateVerifier<'a> {
    /// Create new verifier instance
    pub fn new() -> Self {
        Self {
            roots: Vec::new(),
            default_paths: true,
        }
    }

    /// Enable standard trusted CA roots for validation, default is true
    pub fn default_paths(&mut self, flag: bool) -> &mut Self {
        self.default_paths = flag;
        self
    }

    /// Specify a custom CA root certificate
    pub fn ca_root(&mut self, root: &'a Certificate) -> &mut Self {
        self.roots.push(root);
        self
    }

    /// Verify a given certificate chain. The first element in the chain must be a leaf certificate.
    pub fn verify(&self, chain: &[Certificate]) -> Result<()> {
        if chain.is_empty() {
            return Err(PkiError::InvalidParameters);
        }

        let mut store_builder = X509StoreBuilder::new()?;
        if self.default_paths {
            store_builder.set_default_paths()?;
        }
        for root in &self.roots {
            store_builder.add_cert(root.0.clone())?;
        }
        let store = store_builder.build();

        let mut context = X509StoreContext::new()?;

        let mut stack = Stack::new()?;
        for cert in &chain[1..] {
            stack.push(cert.0.clone())?;
        }

        let result = context.init(&store, &chain[0].0, &stack, |context| context.verify_cert())?;

        if !result {
            Err(PkiError::Verify(context.error()))
        } else {
            Ok(())
        }
    }
}
