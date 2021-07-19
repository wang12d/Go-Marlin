use crate::*;
use std::marker::PhantomData;
use rsa::{PublicKey, RSAPublicKey, PaddingScheme};
use rand::RngCore;
use rand_core::Error;

pub struct DummyRNG {
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

#[derive(Clone)]
struct CryptoCircuit<F: Field> {
    encrypted_data: Vec<u8>,  // The bytes of encrypted data
    public_key: Vec<u8>,     // The bytes of rsa secret key, with key size 2048 bits
    raw_data: Vec<u8>,       // The bytes of raw data
    num_constraints: usize,
    num_variables: usize,
    field_bytes: usize,
    #[doc(hidden)]
    _phantom_field: PhantomData<F>,
}

impl <F: Field> ConstraintSynthesizer<F> for CryptoCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>
    ) -> Result<(), SynthesisError> {
    // Decoding the public key
    let mut rng = DummyRNG{};
    // Convert pem encoded string to public key
    let public_key = RSAPublicKey::from_pkcs1(&self.public_key[..]).expect("failed to parse key");
    let padding = PaddingScheme::new_oaep::<sha2::Sha512>();
    // RSA OAEP decryption
    let encrypted_data = public_key.encrypt(&mut rng, padding, &self.raw_data).expect("failed to decrypt");
    // Now comparing the decrypted data with raw data
    let length = encrypted_data.len();
    let mut index = 0; let one = cs.new_witness_variable(|| Ok(F::one())).unwrap();
    // The encoding of encrypted bytes, converts them to a field element
    // and compare the equality of each number
    let mut witness_variables: Vec<ark_relations::r1cs::Variable> = Vec::new();
    let mut input_variables: Vec<ark_relations::r1cs::Variable> = Vec::new();
    while index < length {
        let mut last = index + self.field_bytes; 
        if last > length {
            last = length;
        }
        let encrypted_field = F::read(&field_encode_convert(&encrypted_data[index..last])[..]).expect("failed to read encrypted raw data to field number");
        let self_encrypted_field = F::read(&field_encode_convert(&self.encrypted_data[index..last])[..]).expect("failed read raw data to field number");
        index = last ;
        witness_variables.push(cs.new_witness_variable(|| Ok(encrypted_field)).unwrap());
        input_variables.push(cs.new_input_variable(|| Ok(self_encrypted_field)).unwrap());
    }
    let sz = witness_variables.len();
    for i in 0..sz {
        cs.enforce_constraint(lc!()+(F::one(), witness_variables[i]), lc!()+(F::one(), one), lc!()+(F::one(), input_variables[i]))?;
    }
    Ok(())
    }
}

#[no_mangle]
pub extern "C" fn generate_proof_zebralancer_rewarding(raw_data: *const c_char, public_key: *const c_char, 
    encrypted_data: *const c_char) -> ProofAndVerifyKey {
        let field_bytes = 32; let data_size = 2048; let field_size = 256;
        let num_constraints = {
            let res = data_size / field_size;
            if data_size % field_size == 0 {
                res
            } else {
                res+1
            }
        };
        let circuit = CryptoCircuit {
            encrypted_data: convert_c_hexstr_to_bytes(encrypted_data),
            raw_data: convert_c_hexstr_to_bytes(raw_data),
            public_key: convert_c_hexstr_to_bytes(public_key),
            num_constraints: num_constraints,
            num_variables: 2*num_constraints + 1,
            field_bytes: field_bytes,
            _phantom_field: PhantomData::<Fr>,
        };
        let rng = &mut ark_std::rand::rngs::OsRng;
        let universal_srs = MarlinInst::universal_setup(circuit.num_constraints, circuit.num_variables, 
            circuit.num_variables, rng).unwrap();
        let (index_pk, index_vk) = MarlinInst::index(&universal_srs, circuit.clone()).unwrap();
        // Now generates the marlin zsk proof
        let proof = MarlinInst::prove(&index_pk, circuit, rng).unwrap();
        let mut vec_proof: Vec<u8> = Vec::new();
        proof.serialize(&mut vec_proof).unwrap();
        let box_vec_proof_in_hex = CString::new(encode(vec_proof)).unwrap();
        let mut vec_vk = Vec::new();
        index_vk.serialize(&mut vec_vk).unwrap();
        let box_vec_vk_in_hex = CString::new(encode(vec_vk)).unwrap();
        ProofAndVerifyKey {
            proof: box_vec_proof_in_hex.into_raw(),
            verify_key: box_vec_vk_in_hex.into_raw(), 
        }
}

#[no_mangle]
pub extern "C" fn verify_proof_zebralancer_rewarding(ciphertext: *const c_char, proof: *const c_char, 
    vk: *const c_char) -> bool {
    let rng = &mut ark_std::test_rng();
    let proof = {
        let proof_cstr = unsafe {CStr::from_ptr(proof)};
        let proof_decode = decode(proof_cstr.to_str().unwrap()).unwrap();                
        Proof::deserialize(&proof_decode[..]).unwrap()
    };
    let vk = {
        let vk_cstr = unsafe {CStr::from_ptr(vk)};
        let vk_decode = decode(vk_cstr.to_str().unwrap()).unwrap();
        IndexVerifierKey::deserialize(&vk_decode[..]).unwrap()
    };
    let encrypted_data = {
        let ciphertext = unsafe {CStr::from_ptr(ciphertext)};
        hex::decode(ciphertext.to_str().unwrap()).unwrap()
    };
    let mut index = 0; let length = encrypted_data.len();
    let mut inputs = Vec::new();
    while index < length {
        let mut last = index + 32; 
        if last > length {
            last = length;
        }
        let encrypted_field = Fr::read(&field_encode_convert(&encrypted_data[index..last])[..]).expect("failed to read encrypted raw data to field number"); 
        inputs.push(encrypted_field);
        index = last;
    }
    MarlinInst::verify(&vk, &inputs[..], &proof, rng).unwrap()
}