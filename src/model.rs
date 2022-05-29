use std::{borrow::Cow, time::SystemTimeError};

use openssl::{
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    nid::Nid,
    pkcs12::Pkcs12,
    pkey::{Id, PKey, Private},
    rsa::Rsa,
    stack::Stack,
    symm::Cipher,
    x509::{X509Name, X509NameEntries, X509NameRef, X509VerifyResult, X509},
};

pub type Result<T> = std::result::Result<T, PkiError>;

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error(transparent)]
    Openssl(#[from] ErrorStack),
    #[error(transparent)]
    SystemTime(#[from] SystemTimeError),
    #[error(transparent)]
    Verify(#[from] X509VerifyResult),
    #[error("Invalid parameters")]
    InvalidParameters,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum PrivateKeyType {
    Rsa,
    Ec,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum CertUsage {
    Ca,
    Server,
    Client,
}

impl CertUsage {
    pub fn extended_usage(&self) -> &'static str {
        match self {
            Self::Server => "serverAuth",
            Self::Client => "clientAuth",
            Self::Ca => "",
        }
    }

    pub fn usage(&self) -> &'static str {
        match self {
            Self::Server | Self::Client => {
                "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment"
            }
            Self::Ca => "keyCertSign,cRLSign",
        }
    }

    pub fn is_ca(&self) -> bool {
        matches!(self, Self::Ca)
    }
}

#[derive(Debug, Clone)]
pub struct PrivateKey(pub(crate) PKey<Private>);

impl PrivateKey {
    pub fn new_rsa(bits: u32) -> Result<Self> {
        Ok(Self(PKey::from_rsa(Rsa::generate(bits)?)?))
    }

    pub fn new_ec() -> Result<Self> {
        Ok(Self(PKey::from_ec_key(EcKey::generate(
            EcGroup::from_curve_name(Nid::SECP256K1)?.as_ref(),
        )?)?))
    }

    pub fn from_der(data: &[u8]) -> Result<Self> {
        Ok(Self(PKey::private_key_from_der(data)?))
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.0.private_key_to_der()?)
    }

    pub fn from_pkcs8(data: &[u8], password: &str) -> Result<Self> {
        Ok(Self(PKey::private_key_from_pkcs8_passphrase(
            data,
            password.as_bytes(),
        )?))
    }

    pub fn to_pkcs8(&self, password: &str) -> Result<Vec<u8>> {
        Ok(self
            .0
            .private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), password.as_bytes())?)
    }

    pub fn bits(&self) -> u32 {
        self.0.bits()
    }

    pub fn key_type(&self) -> PrivateKeyType {
        match self.0.id() {
            Id::RSA => PrivateKeyType::Rsa,
            Id::EC => PrivateKeyType::Ec,
            _ => PrivateKeyType::Other,
        }
    }
}

impl From<PrivateKey> for PKey<Private> {
    fn from(key: PrivateKey) -> Self {
        key.0
    }
}

impl From<PKey<Private>> for PrivateKey {
    fn from(key: PKey<Private>) -> Self {
        Self(key)
    }
}

#[derive(Debug, Clone)]
pub struct Certificate(pub(crate) X509);

impl Certificate {
    pub fn from_der(data: &[u8]) -> Result<Self> {
        Ok(Self(X509::from_der(data)?))
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_der()?)
    }

    pub fn subject_name(&self) -> CertNameRef {
        CertNameRef(self.0.subject_name())
    }
}

impl From<Certificate> for X509 {
    fn from(cert: Certificate) -> Self {
        cert.0
    }
}

impl From<X509> for Certificate {
    fn from(cert: X509) -> Self {
        Self(cert)
    }
}

pub struct CertName(pub(crate) X509Name);

impl CertName {
    pub fn new<I, F, V>(parts: I) -> Result<Self>
    where
        I: IntoIterator<Item = (F, V)>,
        F: AsRef<str>,
        V: AsRef<str>,
    {
        let mut builder = X509Name::builder()?;
        for (field, value) in parts.into_iter() {
            builder.append_entry_by_text(field.as_ref(), value.as_ref())?;
        }
        let name = builder.build();
        Ok(Self(name))
    }

    pub fn entries(&self) -> CertNameEntries {
        CertNameRef(self.0.as_ref()).entries()
    }
}

impl From<CertName> for X509Name {
    fn from(name: CertName) -> Self {
        name.0
    }
}

impl From<X509Name> for CertName {
    fn from(name: X509Name) -> Self {
        Self(name)
    }
}

#[derive(Clone, Debug)]
pub struct CertNameRef<'a>(pub(crate) &'a X509NameRef);

impl<'a> CertNameRef<'a> {
    pub fn entries(&self) -> CertNameEntries<'a> {
        CertNameEntries(self.0.entries())
    }
}

impl<'a> From<CertNameRef<'a>> for &'a X509NameRef {
    fn from(v: CertNameRef<'a>) -> Self {
        v.0
    }
}

impl<'a> From<&'a X509NameRef> for CertNameRef<'a> {
    fn from(name: &'a X509NameRef) -> Self {
        Self(name)
    }
}

pub struct CertNameEntries<'a>(X509NameEntries<'a>);

impl<'a> Iterator for CertNameEntries<'a> {
    type Item = (&'a str, Cow<'a, str>);

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.0.next()?;
        Some((
            entry.object().nid().short_name().expect("No short name"),
            String::from_utf8_lossy(entry.data().as_slice()),
        ))
    }
}

pub struct KeyStore {
    private_key: PrivateKey,
    certs: Vec<Certificate>,
}

impl KeyStore {
    pub fn new<I>(key: PrivateKey, certs: I) -> Result<Self>
    where
        I: IntoIterator<Item = Certificate>,
    {
        let certs: Vec<_> = certs.into_iter().collect();
        if certs.is_empty() {
            Err(PkiError::InvalidParameters)
        } else {
            Ok(Self {
                private_key: key,
                certs,
            })
        }
    }

    pub fn from_pkcs12(data: &[u8], password: &str) -> Result<Self> {
        let pkcs12 = Pkcs12::from_der(data)?;
        let parsed = pkcs12.parse(password)?;
        let mut certs: Vec<Certificate> = vec![parsed.cert.into()];
        if let Some(chain) = parsed.chain {
            certs.extend(chain.into_iter().rev().map(Into::into));
        }
        Ok(Self {
            private_key: PrivateKey(parsed.pkey),
            certs,
        })
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn certs(&self) -> &[Certificate] {
        &self.certs
    }

    pub fn to_pkcs12(&self, alias: &str, password: &str) -> Result<Vec<u8>> {
        let mut builder = Pkcs12::builder();
        if self.certs.len() > 1 {
            let mut stack = Stack::new()?;
            for cert in &self.certs[1..] {
                stack.push(cert.0.clone())?;
            }
            builder.ca(stack);
        }
        Ok(builder
            .build(password, alias, &self.private_key.0, &self.certs[0].0)?
            .to_der()?)
    }
}
