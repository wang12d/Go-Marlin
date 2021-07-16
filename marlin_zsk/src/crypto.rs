use crate::*;
use std::marker::PhantomData;
use rsa::{RSAPublicKey, PaddingScheme};


const BIGINTEGER_BYTES: usize = 104;

#[derive(Clone)]
struct CryptoCircuit<F: Field> {
    encryted_data: vector<u8>,  // The bytes of encrypted data
    public_key: vector<u8>,     // The bytes of rsa secret key, with key size 2048 bits
    raw_data: vector<u8>,       // The bytes of raw data
    num_constraints: usize,
    num_variables: usize,
    #[doc(hidden)]
    _phantom_field: PhantomData<F>,
}

impl <F: Field> ConstraintSynthesizer<F> for CryptoCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>
    ) {
    // Decoding the public key
    let pem_encoded_pk = String::from_utf8(self.public_key).unwrap();
    // Convert pem encoded string to public key
    let pem = rsa::pem::parse(pem_encoded_pk).except("failed to parse pem");
    let public_key = RSAPublicKey::try_from(pem).expect("failed to parse key");
    let padding = PaddingScheme::new_oaep::<sha2::Sha512>();
    // RSA OAEP decryption
    let encrypted_data = public_key.encrypt(padding, &self.raw_data).expect("failed to decrypt");
    // Now comparing the decrypted data with raw data
    let length = encrypted_data.len();
    let index = 0; let one = cs.new_witness_variable(|| Ok(F::one()))
    while (index < length) {
        let last = index+BIGINTEGER_BYTES; 
        if last > length {
            last = length;
        }
        let encrypted_field = F::read(&encrypted_data[index..last].expect("failed to read encrypted raw data to BigInteger832"));
        let self_encrypted_field = F::read(&self.encryted_data[index..last].expect("failed read raw data to BigInteger832"));
        index = last ;
        let x = cs.new_witness_variable(|| Ok(encrypted_data));
        let y = cs.new_input_variable(|| Ok(self_encrypted_field));
        cs.enforce_constraint(lc!() + (F::one(), x), lc!() + (F::one(), one),  lc!() + (F::one(), y));
    }
    }
}

#[no_mangle]
pub extern "C" fn generate_proof_zebralancer_rewarding() {

}

#[no_mangle]
pub extern "C" fn verify_proof_zebralancer_rewarding(ciphertext: *const c_char) {

}