var searchIndex = JSON.parse('{\
"pki":{"doc":"PKI tools for Rust","t":[0,0,0,3,3,17,17,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,13,3,3,3,4,3,13,13,13,3,13,13,4,3,4,6,13,13,13,13,13,13,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,12,12,5],"n":["chain","model","util","CertificateBuilder","CertificateVerifier","DEFAULT_CERT_VALIDITY_DAYS","DEFAULT_RSA_KEY_LENGTH","alt_names","borrow","borrow","borrow_mut","borrow_mut","build","ca_root","default","default","default_paths","from","from","into","into","new","new","not_after","not_before","path_len","private_key","serial_number","signer","subject","try_from","try_from","try_into","try_into","type_id","type_id","usage","verify","CA","CertName","CertNameEntries","CertNameRef","CertUsage","Certificate","CodeSign","Ec","InvalidParameters","KeyStore","Openssl","Other","PkiError","PrivateKey","PrivateKeyType","Result","Rsa","SystemTime","TlsClient","TlsServer","TlsServerAndClient","Verify","bits","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","certs","clone","clone","clone","clone","clone","clone_into","clone_into","clone_into","clone_into","clone_into","entries","entries","eq","eq","extended_usage","fmt","fmt","fmt","fmt","fmt","fmt","fmt","from","from","from","from","from","from","from","from","from","from","from","from","from","from","from","from","from_der","from_der","from_pem","from_pkcs12","from_pkcs8","from_pkcs8_der","from_pkcs8_pem","into","into","into","into","into","into","into","into","into","into_iter","key_type","new","new","new_ec","new_rsa","next","partial_cmp","partial_cmp","private_key","source","subject_name","to_der","to_der","to_owned","to_owned","to_owned","to_owned","to_owned","to_pem","to_pkcs12","to_pkcs8","to_pkcs8_der","to_pkcs8_pem","to_string","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","usage","0","0","0","create_easy_server_chain"],"q":["pki","","","pki::chain","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","pki::model","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","pki::model::PkiError","","","pki::util"],"d":["Certificate chain generation and validation","Model definitions","Utility functions","Certificate builder is used to create X.509 certificate …","Certificate chain verifier","Default validity days of the entity certificate","Default RSA key size","Specify DNS or IP names for the subjectAltName extension. …","","","","","Create X.509 certificate chain","Specify a custom CA root certificate","","","Enable standard trusted CA roots for validation, default …","Returns the argument unchanged.","Returns the argument unchanged.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Create a new certificate builder with default parameters","Create new verifier instance","Specify expiration date of the certificate","Specify start date of the certificate","Specify pathlen parameter for CA certificate, default is …","Specify a custom private key for the certificate chain. If …","Specify serial number for the certificate, default is …","Specify certificate signer. If omitted or None a …","Specify certificate subject","","","","","","","Specify certificate usage","Verify a given certificate chain. The first element in the …","","DN-encoded X.509 name","X.509 name entries iterator","Reference to X.509 name","Certificate target usage","X.509 certificate","","","","A key store holding a private key and a chain of …","","","PKI errors","PrivateKey represents a private key","Private key type","PKI result","","","","","","","Return number of bits in the private key","","","","","","","","","","","","","","","","","","","Return certificate chain of this key store, leaf …","","","","","","","","","","","Return entries iterator","Return entries iterator","","","Get the extended usage string","","","","","","","","","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","","Returns the argument unchanged.","","","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","","","Returns the argument unchanged.","","Returns the argument unchanged.","Parse private key from DER format","Create certificate from DER format","Create certificate from PEM format","Load key store from the PKCS12/PFX file","Load key store from PEM-encoded PKCS8 file which contains …","Parse private key from encrypted PKCS8 DER format","Parse private key from PKCS8 PEM format","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","Return key type","Create new name from the parts, each part is a pair of …","Create new key store. The first certificate entry must be …","Create EC secp384r1 private key","Create RSA private key with a given bit length","","","","Return private key of this key store","","Get certificate subject name","Convert private key to DER format","Serialize certificate into DER format","","","","","","Serialize certificate into PEM format","Write key store to PKCS12/PFX file","Write key store to PEM-encoded PKCS8 file","Convert private key to encrypted PKCS8 DER format","Convert private key to PKCS8 PEM format","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Get the usage string","","","","Easily create a certificate chain to be used by TLS …"],"i":[0,0,0,0,0,0,0,1,1,2,1,2,1,2,1,2,2,1,2,1,2,1,2,1,1,1,1,1,1,1,1,2,1,2,1,2,1,2,3,0,0,0,0,0,3,4,5,0,5,4,0,0,0,0,4,5,3,3,3,5,6,7,8,9,5,4,3,6,10,11,7,8,9,5,4,3,6,10,11,9,4,3,6,10,11,4,3,6,10,11,7,11,4,3,3,5,5,4,3,6,10,11,7,7,8,9,5,5,5,5,4,3,6,6,10,10,11,11,6,10,10,9,9,6,6,7,8,9,5,4,3,6,10,11,8,6,7,9,6,6,8,4,3,9,5,10,6,10,4,3,6,10,11,10,9,9,6,6,5,7,8,9,5,4,3,6,10,11,7,8,9,5,4,3,6,10,11,7,8,9,5,4,3,6,10,11,3,12,13,14,0],"f":[null,null,null,null,null,null,null,[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["result",6,[["keystore",3]]]],[[["",0],["certificate",3]],["",0]],[[]],[[]],[[["",0],["bool",0]],["",0]],[[]],[[]],[[]],[[]],[[]],[[]],[[["",0],["systemtime",3]],["",0]],[[["",0],["systemtime",3]],["",0]],[[["",0],["i32",0]],["",0]],[[["",0],["privatekey",3]],["",0]],[[["",0],["u64",0]],["",0]],[[["",0]],["",0]],[[["",0],["certname",3]],["",0]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[["",0]],["typeid",3]],[[["",0]],["typeid",3]],[[["",0],["certusage",4]],["",0]],[[["",0]],["result",6]],null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,[[["",0]],["u32",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]]],[[["",0]],["privatekeytype",4]],[[["",0]],["certusage",4]],[[["",0]],["privatekey",3]],[[["",0]],["certificate",3]],[[["",0]],["certnameref",3]],[[["",0],["",0]]],[[["",0],["",0]]],[[["",0],["",0]]],[[["",0],["",0]]],[[["",0],["",0]]],[[["",0]],["certnameentries",3]],[[["",0]],["certnameentries",3]],[[["",0],["privatekeytype",4]],["bool",0]],[[["",0],["certusage",4]],["bool",0]],[[["",0]],["str",0]],[[["",0],["formatter",3]],["result",6]],[[["",0],["formatter",3]],["result",6]],[[["",0],["formatter",3]],["result",6]],[[["",0],["formatter",3]],["result",6]],[[["",0],["formatter",3]],["result",6]],[[["",0],["formatter",3]],["result",6]],[[["",0],["formatter",3]],["result",6]],[[["x509name",3]]],[[]],[[]],[[]],[[["x509verifyresult",3]]],[[]],[[["errorstack",3]]],[[["systemtimeerror",3]]],[[]],[[]],[[]],[[["pkey",3,[["private",4]]]]],[[["x509",3]]],[[]],[[["x509nameref",3]]],[[]],[[],["result",6]],[[],["result",6]],[[],["result",6]],[[["str",0]],["result",6]],[[],["result",6]],[[["str",0]],["result",6]],[[],["result",6]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[["",0]],["privatekeytype",4]],[[],["result",6]],[[["privatekey",3]],["result",6]],[[],["result",6]],[[["u32",0]],["result",6]],[[["",0]],["option",4]],[[["",0],["privatekeytype",4]],["option",4,[["ordering",4]]]],[[["",0],["certusage",4]],["option",4,[["ordering",4]]]],[[["",0]],["privatekey",3]],[[["",0]],["option",4,[["error",8]]]],[[["",0]],["certnameref",3]],[[["",0]],["result",6,[["vec",3,[["u8",0]]]]]],[[["",0]],["result",6,[["vec",3,[["u8",0]]]]]],[[["",0]]],[[["",0]]],[[["",0]]],[[["",0]]],[[["",0]]],[[["",0]],["result",6,[["vec",3,[["u8",0]]]]]],[[["",0],["str",0],["str",0]],["result",6,[["vec",3,[["u8",0]]]]]],[[["",0]],["result",6,[["vec",3,[["u8",0]]]]]],[[["",0],["str",0]],["result",6,[["vec",3,[["u8",0]]]]]],[[["",0]],["result",6,[["vec",3,[["u8",0]]]]]],[[["",0]],["string",3]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[["",0]],["typeid",3]],[[["",0]],["typeid",3]],[[["",0]],["typeid",3]],[[["",0]],["typeid",3]],[[["",0]],["typeid",3]],[[["",0]],["typeid",3]],[[["",0]],["typeid",3]],[[["",0]],["typeid",3]],[[["",0]],["typeid",3]],[[["",0]],["str",0]],null,null,null,[[["str",0]],["result",6,[["keystore",3]]]]],"p":[[3,"CertificateBuilder"],[3,"CertificateVerifier"],[4,"CertUsage"],[4,"PrivateKeyType"],[4,"PkiError"],[3,"PrivateKey"],[3,"CertName"],[3,"CertNameEntries"],[3,"KeyStore"],[3,"Certificate"],[3,"CertNameRef"],[13,"Openssl"],[13,"SystemTime"],[13,"Verify"]]}\
}');
if (window.initSearch) {window.initSearch(searchIndex)};