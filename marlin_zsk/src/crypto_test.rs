#![allow(dead_code)]
#![allow(unused)]
mod crypto_test {
    use crate::crypto::{generate_proof_zebralancer_rewarding, verify_proof_zebralancer_rewarding,
        DummyRNG};
    use crate::{convert_c_hexstr_to_bytes, DataEvaluationResults};
    use std::{convert::TryFrom, ffi::{CStr, CString}};
    use libc::c_char;
    use rsa::{PublicKey, RSAPublicKey, RSAPrivateKey, PaddingScheme, PublicKeyEncoding, PrivateKeyEncoding};
    use hex;

    #[test]
    fn test_generate_proof_encryption() {

    let mut rng = DummyRNG {};
    let private_pem = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA4Youqbl/ofYP6Et9jLQyQ6i7e63HFT3z5chn+2qZZhxg0ww7
IkdSiqpVO/+Ng58fyG4l1vSeKucfh2nuojO8jn+FRxKrKTeuSriBJZcieQaRIOk2
ujYbUy6XUir45n4MsUqhSpNIkA41GOIf9wxYyAJ/5wV7pZ6cFqp9M22rm+K1Tw7H
t+55eEe7CePS+XXz9F2OYkVZKNfcYpv9R+hdB7vqdQ3hasSbjCyxouDAozMXExld
X1t34VIHGX4hZT6drn0LTj57yX12eKOIwq57iOsmCGb8HpI0bJPvU5qemTjWRdpd
88+xbAZRBfXbBUKfW7MoQTHu1EcsHWSc5aSNIQIDAQABAoIBAQCP2rxCoz+GRVUG
HEhbG4BH6XKTw1aM9PQA5x9znB11pLoZQt7g0U8ThOtSloBjqHX0OFVIUsQjp0FT
9LwxlwA4f5u5pm2nn406uY4eNNTXDto4fKfcg7BQERKRZTlWgqWD248e6uxIfdde
JLSwtZ5XDEkaSEQCcjUqu9mZmOTxSqlBI33uTLjuwj1AKNq2oaVlB7oRfLQnCrbv
g17Lj7dVScl+EkZul3+4zld0x8chLesMc4eSxwpB7voCCCfjHrAuE18Rrr5ff6c+
Q/ekkKA+0VA4OAdPFp7bFyj405dO8Ai1k7CeHYGkyC0ZRuZSlg5kfQP9HeI61Oic
++VcWubBAoGBAO3BIef6l8pvp9uuHiT6hsvY8KY53WdgzKkeseyU7KGzZG/P+Aay
+4VsY09vhCyMcJ2Yf1R2aIAzyHOHShB7owh6xXVGg+oWPL/Wt4KZPktO/bwPlppE
0df385/D/AbeAMVh3gHHwfvtp+/rOzpo9POw1shUxGMdxK5ohyko6d+5AoGBAPLZ
FW2qFHeDrZjN+5ee9wUiLHE96nLL6kOfLRTA+vE/VCL2+vc+2amxPlMcFokxsaAT
7M3QrMb1p7uOauc0ZMTWgjsMRJwJVc0BQchXIsK1qiBkUVGujST0BdtPe5wxUruv
qfBJ1DQkNvCZXDl07aFQaMIR7wKo8yTc0pwslLypAoGBAM3jTuplzubmdDU//ijF
rs9+aT95oqqwX+sggrG+cYDCKfrN3RpoCnoLV6DlkE9Huwouki1hcLN8pFyvTssh
Vhi0wKQDUZ74bNkwJrB45kIvAHnIAgJMEHB270luXaTQwVgsnSVriCgTMTgJu7uk
QmN5wzWuenbew4DJUiqpnIY5AoGAHIV0Z9HO345+h/DBOLh5yIeP8qjT7TGXzONX
9xUHI+hNKGIbbYhbJfvkFvy4hNpqQyOz7yQv9poJXhTG52qW3ytWVjsFn9HU2uPn
5vCc64NMfMtrZY17lDh4q541JU4BqntiGQ+CtbD/JtjMJQ9fjU+VTh2vFX/kNpMc
xSzTNykCgYEAiuK1k+ncOKmY6zPcsB+CQIcv8SA3wbWkPciY72excBuDWTmP+gZq
Vus4O4qIf2NPOoN2vDU1mjupUgRYIPb4TVDWdGPZFqTgYKfOUHShrhaQYpj7Br1k
SDBwSyWcJQiMNGKujV4cU2BPcikqpukmMh1pewDMy7cRggheClGkmZI=
-----END RSA PRIVATE KEY-----
"#;
    let private_pem = rsa::pem::parse(private_pem).unwrap();
    let encoded_private_key = CString::new(hex::encode(rsa::pem::encode(&private_pem))).unwrap();
    let private_key = RSAPrivateKey::try_from(private_pem).expect("failed to parse private key");
    
    let public_key = RSAPublicKey::from(&private_key);
    // Encrypt
    let data = b"hello";
    let padding = PaddingScheme::new_oaep::<sha2::Sha512>();
    let enc_data = public_key.encrypt(&mut rng, padding, &data[..]).expect("failed to encrypt");
    // Next converting public key, encrypted data, raw_data to hex encoded c_char
    let encoded_public_key = {
        let pk_pem = rsa::pem::Pem {
            tag: String::from("RSA PUBLIC KEY"),
            contents: public_key.to_pkcs1().unwrap(),
        };
        CString::new(hex::encode(rsa::pem::encode(&pk_pem))).unwrap()
    };
    let mut v = vec![CString::new(hex::encode(data)).unwrap()];
    let encoded_raw_data: Vec<_> = v.iter().map(|d| d.as_ptr()).collect();
    let mut u = vec![CString::new(hex::encode(enc_data)).unwrap()];
    let mut encoded_enc_data: Vec<_> = u.iter().map(|d| d.as_ptr()).collect();
    let size = 1;
    let data_qualities = vec![100];
    let pv = generate_proof_zebralancer_rewarding(0, 25, data_qualities.as_ptr(), size,
        encoded_public_key.as_ptr(), encoded_private_key.as_ptr(), 
        encoded_enc_data.as_ptr(), encoded_raw_data.as_ptr(), 2048);
    // Get proof and vk
    let eval = vec![DataEvaluationResults{add:175, minus:25,}];
    let vfy = verify_proof_zebralancer_rewarding(eval.as_ptr(), size, encoded_enc_data.as_ptr(), pv.proof, pv.verify_key);
    assert_eq!(vfy, true);

    // Test false encryption data
    let encoded_enc_data = {
        let data = b"hell";
        let padding = PaddingScheme::new_oaep::<sha2::Sha512>();
        public_key.encrypt(&mut rng, padding, data).unwrap()
    };
    let mut v = Vec::new();
    v.push(CString::new(hex::encode(encoded_enc_data)).unwrap());
    let encoded_enc_data: Vec<_> = v.iter().map(|d| d.as_ptr()).collect();
    let vfy = verify_proof_zebralancer_rewarding(eval.as_ptr(), size, encoded_enc_data.as_ptr(), pv.proof, pv.verify_key);
    assert_eq!(vfy, false);
    }

    #[test]
    fn test_generate_proof_multiple_encryptions() {

    let mut rng = DummyRNG {};
    let private_pem = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA4Youqbl/ofYP6Et9jLQyQ6i7e63HFT3z5chn+2qZZhxg0ww7
IkdSiqpVO/+Ng58fyG4l1vSeKucfh2nuojO8jn+FRxKrKTeuSriBJZcieQaRIOk2
ujYbUy6XUir45n4MsUqhSpNIkA41GOIf9wxYyAJ/5wV7pZ6cFqp9M22rm+K1Tw7H
t+55eEe7CePS+XXz9F2OYkVZKNfcYpv9R+hdB7vqdQ3hasSbjCyxouDAozMXExld
X1t34VIHGX4hZT6drn0LTj57yX12eKOIwq57iOsmCGb8HpI0bJPvU5qemTjWRdpd
88+xbAZRBfXbBUKfW7MoQTHu1EcsHWSc5aSNIQIDAQABAoIBAQCP2rxCoz+GRVUG
HEhbG4BH6XKTw1aM9PQA5x9znB11pLoZQt7g0U8ThOtSloBjqHX0OFVIUsQjp0FT
9LwxlwA4f5u5pm2nn406uY4eNNTXDto4fKfcg7BQERKRZTlWgqWD248e6uxIfdde
JLSwtZ5XDEkaSEQCcjUqu9mZmOTxSqlBI33uTLjuwj1AKNq2oaVlB7oRfLQnCrbv
g17Lj7dVScl+EkZul3+4zld0x8chLesMc4eSxwpB7voCCCfjHrAuE18Rrr5ff6c+
Q/ekkKA+0VA4OAdPFp7bFyj405dO8Ai1k7CeHYGkyC0ZRuZSlg5kfQP9HeI61Oic
++VcWubBAoGBAO3BIef6l8pvp9uuHiT6hsvY8KY53WdgzKkeseyU7KGzZG/P+Aay
+4VsY09vhCyMcJ2Yf1R2aIAzyHOHShB7owh6xXVGg+oWPL/Wt4KZPktO/bwPlppE
0df385/D/AbeAMVh3gHHwfvtp+/rOzpo9POw1shUxGMdxK5ohyko6d+5AoGBAPLZ
FW2qFHeDrZjN+5ee9wUiLHE96nLL6kOfLRTA+vE/VCL2+vc+2amxPlMcFokxsaAT
7M3QrMb1p7uOauc0ZMTWgjsMRJwJVc0BQchXIsK1qiBkUVGujST0BdtPe5wxUruv
qfBJ1DQkNvCZXDl07aFQaMIR7wKo8yTc0pwslLypAoGBAM3jTuplzubmdDU//ijF
rs9+aT95oqqwX+sggrG+cYDCKfrN3RpoCnoLV6DlkE9Huwouki1hcLN8pFyvTssh
Vhi0wKQDUZ74bNkwJrB45kIvAHnIAgJMEHB270luXaTQwVgsnSVriCgTMTgJu7uk
QmN5wzWuenbew4DJUiqpnIY5AoGAHIV0Z9HO345+h/DBOLh5yIeP8qjT7TGXzONX
9xUHI+hNKGIbbYhbJfvkFvy4hNpqQyOz7yQv9poJXhTG52qW3ytWVjsFn9HU2uPn
5vCc64NMfMtrZY17lDh4q541JU4BqntiGQ+CtbD/JtjMJQ9fjU+VTh2vFX/kNpMc
xSzTNykCgYEAiuK1k+ncOKmY6zPcsB+CQIcv8SA3wbWkPciY72excBuDWTmP+gZq
Vus4O4qIf2NPOoN2vDU1mjupUgRYIPb4TVDWdGPZFqTgYKfOUHShrhaQYpj7Br1k
SDBwSyWcJQiMNGKujV4cU2BPcikqpukmMh1pewDMy7cRggheClGkmZI=
-----END RSA PRIVATE KEY-----
"#;
    let private_pem = rsa::pem::parse(private_pem).unwrap();
    let encoded_private_key = CString::new(hex::encode(rsa::pem::encode(&private_pem))).unwrap();
    let private_key = RSAPrivateKey::try_from(private_pem).expect("failed to parse private key");
    
    let public_key = RSAPublicKey::from(&private_key);
    // Encrypt
    let data = b"hello";
    let padding = PaddingScheme::new_oaep::<sha2::Sha512>();
    let enc_data = public_key.encrypt(&mut rng, padding, &data[..]).expect("failed to encrypt");
    // Next converting public key, encrypted data, raw_data to hex encoded c_char
    let encoded_public_key = {
        let pk_pem = rsa::pem::Pem {
            tag: String::from("RSA PUBLIC KEY"),
            contents: public_key.to_pkcs1().unwrap(),
        };
        CString::new(hex::encode(rsa::pem::encode(&pk_pem))).unwrap()
    };
    let mut v = vec![CString::new(hex::encode(data)).unwrap()];
    let data_two = b"world.";
    let padding = PaddingScheme::new_oaep::<sha2::Sha512>();
    let mut u = vec![CString::new(hex::encode(enc_data)).unwrap()];
    u.push(CString::new(hex::encode(public_key.encrypt(&mut rng, padding, &data_two[..]).unwrap())).unwrap());
    v.push(CString::new(hex::encode(data_two)).unwrap());
    let encoded_raw_data: Vec<_> = v.iter().map(|d| d.as_ptr()).collect();
    let mut encoded_enc_data: Vec<_> = u.iter().map(|d| d.as_ptr()).collect();
    let size = 1;
    let data_qualities = vec![100, 75];
    let pv = generate_proof_zebralancer_rewarding(0, 25, data_qualities.as_ptr(), size,
        encoded_public_key.as_ptr(), encoded_private_key.as_ptr(), 
        encoded_enc_data.as_ptr(), encoded_raw_data.as_ptr(), 2048);
    // Get proof and vk
    let evals = vec![DataEvaluationResults{add:175, minus:25,}, DataEvaluationResults{add: 150, minus: 0}];
    let vfy = verify_proof_zebralancer_rewarding(evals.as_ptr(), size, encoded_enc_data.as_ptr(), pv.proof, pv.verify_key);
    assert_eq!(vfy, true);

    // Test false encryption data
    let encoded_enc_data = {
        let data = b"hell";
        let padding = PaddingScheme::new_oaep::<sha2::Sha512>();
        public_key.encrypt(&mut rng, padding, data).unwrap()
    };
    let mut v = Vec::new();
    v.push(CString::new(hex::encode(encoded_enc_data)).unwrap());
    let encoded_enc_data_two = {
        let data = b"world";
        let padding = PaddingScheme::new_oaep::<sha2::Sha512>();
        public_key.encrypt(&mut rng, padding, data).unwrap()
    };
    v.push(CString::new(hex::encode(encoded_enc_data_two)).unwrap());
    let encoded_enc_data: Vec<_> = v.iter().map(|d| d.as_ptr()).collect();
    let vfy = verify_proof_zebralancer_rewarding(evals.as_ptr(), size, encoded_enc_data.as_ptr(), pv.proof, pv.verify_key);
    assert_eq!(vfy, false);
    }
}