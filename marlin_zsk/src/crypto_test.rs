#![allow(dead_code)]
#![allow(unused)]
mod crypto_test {
    use crate::crypto::{generate_proof_zebralancer_rewarding, verify_proof_zebralancer_rewarding,
        DummyRNG};
    use std::{convert::TryFrom, ffi::{CStr, CString}};
    use rsa::{PublicKey, RSAPublicKey, RSAPrivateKey, PaddingScheme, PublicKeyEncoding};
    use hex;



    #[test]
    fn test_generate_proof_encryption() {

    let mut rng = DummyRNG {};
    let public_pem = r#"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApUNwnvaqk3HRiIfRCgXr
u8NlVFsP3s/9ifZ9AwKKMzy52DuOosHRywZtWhnNZTzDARjzXs0U9GCAzcwq5pH7
pUZ/ZK8wSZZxRIG7WeHua8NxmsLmqyAIdb6KyO9eBV9uK8l2b/ieXsQLtnZaNrvb
WAbkXAlliO9FGJnvnonZVxyz2BcbpBZ5jFA/eUgjN+aM6E3Y4ugL1Rm2EdMvNErU
ukZ6r8Qp6zB25moYcVZKWDrY5j81qo6iz1vI1Y4prgQ4JmU/UkXeQ5JBTo1Ocvyy
dITpxKGkuxr1oiQypuOTeeiHrqoJOY2N/t6f52A110prFdBt629RDViwM7kypDXM
swIDAQAB
-----END PUBLIC KEY-----"#;
    let public_pem = rsa::pem::parse(public_pem).unwrap();
    let public_key = RSAPublicKey::try_from(public_pem).expect("failed to parse key");
    // Encrypt
    let data = b"hello";
    let padding = PaddingScheme::new_oaep::<sha2::Sha512>();
    let enc_data = public_key.encrypt(&mut rng, padding, &data[..]).expect("failed to encrypt");
    // Next converting public key, encrypted data, raw_data to hex encoded c_char
    let encoded_public_key = CString::new(hex::encode(public_key.to_pkcs1().unwrap()))
                                .expect("Convert to CString error");
    let encoded_raw_data = CString::new(hex::encode(data)).unwrap();
    let encoded_enc_data = CString::new(hex::encode(enc_data)).unwrap();
    let pv = generate_proof_zebralancer_rewarding(encoded_raw_data.as_ptr(), encoded_public_key.as_ptr(), encoded_enc_data.as_ptr());
    // Get proof and vk
    let vfy = verify_proof_zebralancer_rewarding(encoded_enc_data.into_raw(), pv.proof, pv.verify_key);
    assert_eq!(vfy, true);

    // Test false encryption data
    let encoded_enc_data = {
        let data = b"hell";
        let padding = PaddingScheme::new_oaep::<sha2::Sha512>();
        let enc_data = public_key.encrypt(&mut rng, padding, data).unwrap();
        CString::new(hex::encode(enc_data)).unwrap()
    };
    let vfy = verify_proof_zebralancer_rewarding(encoded_enc_data.into_raw(), pv.proof, pv.verify_key);
    assert_eq!(vfy, false);
    }
}