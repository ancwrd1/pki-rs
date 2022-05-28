use std::{
    io,
    net::Ipv4Addr,
    ops::Add,
    time::{Duration, SystemTime, SystemTimeError},
};

use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkcs12::{ParsedPkcs12, Pkcs12},
    pkey::{PKey, Private},
    rsa::Rsa,
    stack::Stack,
    x509::{X509Extension, X509Name, X509VerifyResult, X509},
};

pub const DEFAULT_CERT_VALIDITY_DAYS: u64 = 825;
pub const DEFAULT_RSA_KEY_LENGTH: u32 = 2048;

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error(transparent)]
    Openssl(#[from] ErrorStack),
    #[error(transparent)]
    SystemTime(#[from] SystemTimeError),
    #[error(transparent)]
    Verify(#[from] X509VerifyResult),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum PrivateKeyType {
    Rsa,
    Ec,
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

pub struct CertificateBuilder<'a> {
    signer: Option<&'a ParsedPkcs12>,
    names: Vec<(String, String)>,
    usage: CertUsage,
    alt_names: String,
    not_before: SystemTime,
    not_after: SystemTime,
    key_type: PrivateKeyType,
    serial_number: Option<u128>,
    path_len: i32,
}

impl<'a> CertificateBuilder<'a> {
    pub fn new() -> Self {
        Self {
            signer: None,
            names: Vec::new(),
            usage: CertUsage::Server,
            alt_names: String::new(),
            not_before: SystemTime::now(),
            not_after: SystemTime::now().add(Duration::from_secs(
                DEFAULT_CERT_VALIDITY_DAYS * 24 * 60 * 60,
            )),
            key_type: PrivateKeyType::Ec,
            serial_number: None,
            path_len: i32::MAX,
        }
    }

    pub fn signer(&mut self, signer: &'a ParsedPkcs12) -> &mut Self {
        self.signer = Some(signer);
        self
    }

    pub fn usage(&mut self, usage: CertUsage) -> &mut Self {
        self.usage = usage;
        self
    }

    pub fn alt_names<S, I>(&mut self, alt_names: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.alt_names = alt_names
            .into_iter()
            .map(|name| {
                if name.as_ref().parse::<Ipv4Addr>().is_ok() {
                    format!("IP:{}", name.as_ref())
                } else {
                    format!("DNS:{}", name.as_ref())
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        self
    }

    pub fn not_before(&mut self, time: SystemTime) -> &mut Self {
        self.not_before = time;
        self
    }

    pub fn not_after(&mut self, time: SystemTime) -> &mut Self {
        self.not_after = time;
        self
    }

    pub fn key_type(&mut self, key_type: PrivateKeyType) -> &mut Self {
        self.key_type = key_type;
        self
    }

    pub fn subject<F, V, I>(&mut self, names: I) -> &mut Self
    where
        I: IntoIterator<Item = (F, V)>,
        F: AsRef<str>,
        V: AsRef<str>,
    {
        self.names = names
            .into_iter()
            .map(|(f, v)| (f.as_ref().to_owned(), v.as_ref().to_owned()))
            .collect();
        self
    }

    pub fn serial_number(&mut self, number: u64) -> &mut Self {
        self.serial_number = Some(number as u128);
        self
    }

    pub fn path_len(&mut self, path_len: i32) -> &mut Self {
        self.path_len = path_len;
        self
    }

    pub fn build(&self) -> Result<(PKey<Private>, X509), PkiError> {
        let cert_key = match self.key_type {
            PrivateKeyType::Rsa => PKey::from_rsa(Rsa::generate(DEFAULT_RSA_KEY_LENGTH)?)?,
            PrivateKeyType::Ec => PKey::from_ec_key(EcKey::generate(
                EcGroup::from_curve_name(Nid::SECP256K1)?.as_ref(),
            )?)?,
        };

        let mut name_builder = X509Name::builder()?;
        for (field, value) in &self.names {
            name_builder.append_entry_by_text(field, value)?;
        }
        let subject = name_builder.build();

        let mut builder = X509::builder()?;
        builder.set_pubkey(&cert_key)?;
        builder.set_version(2)?;
        builder.set_issuer_name(
            self.signer
                .map(|s| s.cert.subject_name())
                .unwrap_or(&subject),
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
        builder.set_subject_name(&subject)?;

        let serial_number = match self.serial_number {
            Some(number) => number.to_be_bytes(),
            None => SystemTime::UNIX_EPOCH.elapsed()?.as_millis().to_be_bytes(),
        };
        let asn_number = Asn1Integer::from_bn(BigNum::from_slice(&serial_number)?.as_ref())?;
        builder.set_serial_number(&asn_number)?;

        // man x509v3_config
        builder.append_extension(X509Extension::new(
            None,
            Some(&builder.x509v3_context(None, None)),
            "basicConstraints",
            &format!(
                "critical,CA:{}{}",
                if self.usage.is_ca() { "TRUE" } else { "FALSE" },
                match self.usage {
                    CertUsage::Ca => format!(",pathlen:{}", self.path_len),
                    _ => String::new(),
                }
            ),
        )?)?;

        builder.append_extension(X509Extension::new(
            None,
            Some(&builder.x509v3_context(None, None)),
            "subjectKeyIdentifier",
            "hash",
        )?)?;

        builder.append_extension(X509Extension::new(
            None,
            Some(&builder.x509v3_context(self.signer.map(|s| s.cert.as_ref()), None)),
            "authorityKeyIdentifier",
            "keyid,issuer",
        )?)?;

        if !self.usage.is_ca() {
            builder.append_extension(X509Extension::new(
                None,
                Some(&builder.x509v3_context(None, None)),
                "extendedKeyUsage",
                &format!("critical,{}", self.usage.extended_usage()),
            )?)?;
        }

        builder.append_extension(X509Extension::new(
            None,
            Some(&builder.x509v3_context(None, None)),
            "keyUsage",
            &format!("critical,{}", self.usage.usage()),
        )?)?;

        if !self.alt_names.is_empty() {
            builder.append_extension(X509Extension::new(
                None,
                Some(&builder.x509v3_context(None, None)),
                "subjectAltName",
                &self.alt_names,
            )?)?;
        }

        if let Some(ref signer) = self.signer {
            builder.sign(&signer.pkey, MessageDigest::sha256())?;
        } else {
            builder.sign(&cert_key, MessageDigest::sha256())?;
        }

        let cert = builder.build();

        Ok((cert_key, cert))
    }

    pub fn build_pkcs12(&self, password: &str, alias: &str) -> Result<Pkcs12, PkiError> {
        let (key, cert) = self.build()?;

        let mut pkcs12_builder = Pkcs12::builder();

        if let Some(ref signer) = self.signer {
            let mut stack = Stack::new()?;
            stack.push(signer.cert.clone())?;

            if let Some(ref signer_stack) = signer.chain {
                for cert in signer_stack {
                    stack.push(cert.to_owned())?;
                }
            }
            pkcs12_builder.ca(stack);
        }
        Ok(pkcs12_builder.build(password, alias, &key, &cert)?)
    }
}

#[cfg(test)]
mod tests {
    use openssl::x509::{store::X509StoreBuilder, X509StoreContext};
    use uuid::Uuid;

    use super::*;

    const PASSWORD: &str = "changeit";

    fn gen_ca_store(cn: &str, signer: Option<&ParsedPkcs12>) -> Result<Pkcs12, PkiError> {
        let mut builder = CertificateBuilder::new();

        if let Some(signer) = signer {
            builder.signer(signer);
        }

        builder
            .subject([("C", "DK"), ("O", "EveryonePrint"), ("CN", cn)])
            .usage(CertUsage::Ca)
            .not_after(SystemTime::now().add(Duration::from_secs(365 * 10 * 24 * 60 * 60)))
            .key_type(PrivateKeyType::Ec);

        Ok(builder.build_pkcs12(PASSWORD, "ca")?)
    }

    fn gen_entity_store(signer: &ParsedPkcs12) -> Result<Pkcs12, PkiError> {
        let uuid = Uuid::new_v4();
        let mut builder = CertificateBuilder::new();

        builder
            .subject([
                ("C", "DK"),
                ("O", "EveryonePrint"),
                ("CN", &uuid.to_string()),
            ])
            .signer(&signer)
            .usage(CertUsage::Client)
            .alt_names(["172.22.1.1", "t14s.home.lan"])
            .key_type(PrivateKeyType::Ec);

        Ok(builder.build_pkcs12(PASSWORD, &uuid.to_string())?)
    }

    fn gen_chain() -> Result<(), PkiError> {
        let root_store = gen_ca_store("Root CA", None)?;
        let root_signer = root_store.parse(PASSWORD)?;

        let intermediate_store = gen_ca_store("Intermediate CA", Some(&root_signer))?;
        let intermediate_signer = intermediate_store.parse(PASSWORD)?;

        let entity_store = gen_entity_store(&intermediate_signer)?;
        std::fs::write("/tmp/keystore.p12", entity_store.to_der()?)?;
        let entity = entity_store.parse(PASSWORD)?;

        let mut store_builder = X509StoreBuilder::new()?;
        store_builder.set_default_paths()?;
        store_builder.add_cert(root_signer.cert)?;
        let store = store_builder.build();

        let mut context = X509StoreContext::new()?;
        let verify_result =
            context.init(&store, &entity.cert, &entity.chain.unwrap(), |context| {
                context.verify_cert()
            })?;

        if !verify_result {
            Err(PkiError::Verify(context.error()))
        } else {
            Ok(())
        }
    }

    #[test]
    fn test_gen_chain() {
        gen_chain().unwrap();
    }
}
