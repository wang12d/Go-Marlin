use rand::{RngCore};
use rand_core::{Error};
use std::convert::TryFrom;
use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme};


struct DummyRNG {
}

impl RngCore for DummyRNG {
    fn next_u32(&mut self) -> u32 {
        0 as u32
    }
    
    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for elt in dest.iter_mut() {
            *elt = 0;
        }
    }

    fn try_fill_bytes(& mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }
}

fn main() {
    let mut rng = DummyRNG {};
    let private_pem = r#"
    -----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxP3VtKhFcviksOnv4p7P9zxha2qPd+wzYZ2J/7l4MD22Mx1f
GKi3V69A5BVaAc4RHBNnKn+tdSwDiqPwb0ESOqdW7U/IeJV5mQLbc+pkt1/LYZot
RBHavC/EMxUoulHDiLoOYQI/8zPWZXzsPGyJPvqvUEPybkEQCvGgROyOlNeYB2PH
V+6fSedMeGyHd0Y4LK8pN+Thp1Pf4m6sj3gpBvrCCYNvxSehpW3udcsW2KhhZUsr
EuuSKKLKWd6RRVQydIVSRT+m4HAB53zH4R1/FhNY/vh2EAEKVP/j9X0OXa7LbUQE
UZc6PUJ7H5l6QLzsqFfuW7q7OYn2JFgsUn1wYwIDAQABAoIBADKNOTQ9ImVYrVrB
DdBIFPJLSmy4UczijmT0ep9nRxKKI6GGXgsD8NjNnodpe0mPShC8YfMkBK1W+Cmx
3FeQiU8H9mS73qQjJ6s+cnaSpfnw2U5YtFkNg+ZbE6xQN71okhcaN+ppG2Qb3173
6d+vsqC40Bh291WX2LgWPZyyX/yNy3quHnAtv20DKjchx0GGyV6SYDZWVa6nbBPU
XC/LucSILClXDlX+n5rd8f4tdx3L+BbVllEwCM2aSaItFg0Eaf1FO06K/E8vSFeL
LuQ0gN1isI6ht7RWLHi5Zyu32XIe4skPv6xTB3hD2IY8C+RoomCoE8Si3vnpsrYb
UyKtXIECgYEA7ryIvtVLFaXo5esePU3Kj4ggCsVg98ysV+W5OBR1zecHpEpxo27e
yrnoCWd1Wsc+QmABiXmS1opxfPzfniaPMQDXc5srqM+E0SefgwnhdJJv3/diPKZ6
N8qtgi0zdEKickZRJxL6Ts7QNJxhYZe9axiBvprJio2UIf8nd9t0HCECgYEA0zyF
1clq08ohbCYpwGKQaFsSeJRzmG7WQD43erBJavtjSkrwb90qV1a4wLwlP6/TjItd
tNuluY2lJtCMeniCl8l7JFpnHvFLRw1R7AvR3jhzIRam9o6rbwl8jEO4fX05ROhw
nY42U/R4K2LZUtS0/6uAwWKG4xbtwGu6OuddnAMCgYBJ6IIpGh05oXhdnZFqByg7
kTfiPcLMVEfSmmLh8quZx/k8qnNN1mgQuMcWCjpxlRc4M0KmjcWgt5F00VBlRKi1
0f3hY1t70mra2XpvdeKfVSpfWtXF0wApP4zBrT6tsmdaG1zKTPzC4xHgB726GeDh
Q9/+4yqbw0Ll13kfiQgEIQKBgF57Bp2dznNWSGa4Fxqeu1qByZw3QhDfGmN3sJbm
vJ/mOv3i0PIn6SVRe6dxP/Phb+y/9TTMva5l5YWb6AlrV3YOv05+RPt5D6ODGK5M
hx0vAIe/OwSywYkTpCqUq7MtTG0+zggasMASa6F0QCIlU6O7kQZuTEjMW6EiThTE
oYEDAoGBAKchs+EOgLSzqvHrK3+Nc4KN6nJLBCfadELCz1Jf2BXmi+v5k0d/3QmP
IUAAqCmKEkP1J12q93fASmkhSqD8RC8u/mLiZisrrRBt2VTxv0QfupuHSgqwss+N
fCUEIjVyUdJ3B2VLtlORSwaYZ7umR+fgwl1IcGuk7IBPA3nDmAE+
    -----END RSA PRIVATE KEY-----
    "#;
    let private_pem = rsa::pem::parse(private_pem).unwrap();
    let private_key = RSAPrivateKey::try_from(private_pem).expect("failed to parse key");
    let public_key = RSAPublicKey::from(&private_key);
    // Encrypt
    let data = b"hello";
    let padding = PaddingScheme::new_oaep::<sha2::Sha512>();
    let enc_data = public_key.encrypt(&mut rng, padding, &data[..]).expect("failed to encrypt");
    println!("{}", hex::encode(&enc_data));
    let padding = PaddingScheme::new_oaep::<sha2::Sha512>();
    let enc_data = public_key.encrypt(&mut rng, padding, &data[..]).expect("failed to encrypt");
    println!("{}", hex::encode(&enc_data));
    // Decrypt
    let padding = PaddingScheme::new_oaep::<sha2::Sha512>();
    let dec_data = private_key.decrypt(padding, &enc_data).expect("failed to decrypt");
    assert_eq!(&data[..], &dec_data[..]);
}