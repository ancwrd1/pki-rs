use pki_rs::{PrivateKey, PrivateKeyType};

fn do_test(key: PrivateKey) {
    let der = key.to_der().unwrap();
    let parsed = PrivateKey::from_der(&der).unwrap();
    assert_eq!(parsed.to_der().unwrap(), der);

    let pkcs8 = key.to_pkcs8("test").unwrap();
    PrivateKey::from_pkcs8(&pkcs8, "test").unwrap();
}

#[test]
fn test_private_key() {
    let key = PrivateKey::new_ec().unwrap();
    assert_eq!(key.bits(), 256);
    assert_eq!(key.key_type(), PrivateKeyType::Ec);
    do_test(key);

    let key = PrivateKey::new_rsa(2048).unwrap();
    assert_eq!(key.bits(), 2048);
    assert_eq!(key.key_type(), PrivateKeyType::Rsa);
    do_test(key);

    let key = PrivateKey::new_rsa(4096).unwrap();
    assert_eq!(key.bits(), 4096);
    assert_eq!(key.key_type(), PrivateKeyType::Rsa);
    do_test(key);
}
