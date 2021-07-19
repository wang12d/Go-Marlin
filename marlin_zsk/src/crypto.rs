use crate::*;
use std::marker::PhantomData;
use rsa::{RSAPrivateKey, PublicKey, RSAPublicKey, PaddingScheme};
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
    public_key: Vec<u8>,     // The bytes of rsa public key, with key size 2048 bits
    private_key: Vec<u8>,   // The bytes of rsa private key
    raw_data: Vec<u8>,       // The bytes of raw data
    data_quality: Option<F>,
    sigma: Option<F>,
    mu: Option<F>,
    num_constraints: usize,
    num_variables: usize,
    field_bytes: usize,
}

impl <F: Field> ConstraintSynthesizer<F> for CryptoCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>
    ) -> Result<(), SynthesisError> {
    // Decoding the public key
    let one = cs.new_witness_variable(|| Ok(F::one())).unwrap();
    let mut rng = DummyRNG{};
    // Convert pem encoded string to public key
    let public_key = RSAPublicKey::from_pkcs1(&self.public_key[..]).expect("failed to parse public key");
    let private_key = RSAPrivateKey::from_pkcs1(&self.private_key[..]).expect("failed to parse private key");
    let key_pair = {
        let mut res = F::zero();
        let pk = RSAPublicKey::from(&private_key);
        if pk == public_key {
           res += F::one()
        }
        cs.new_witness_variable(|| Ok(res))?
    };
    cs.enforce_constraint(lc!()+(F::one(), key_pair), lc!()+(F::one(), one), lc!()+(F::one(), one))?;
    // TODO: According to the Zebralancer paper, this part should be of vector of encrypted data
    /*************************************************************
    ********The Marlin ZSK Proof Constraint of encryption*********
    *************************************************************/
    let padding = PaddingScheme::new_oaep::<sha2::Sha512>();
    // RSA OAEP decryption
    let encrypted_data = public_key.encrypt(&mut rng, padding, &self.raw_data).expect("failed to decrypt");
    // Now comparing the decrypted data with raw data
    let length = encrypted_data.len();
    let mut index = 0; 
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
        cs.enforce_constraint(lc!()+(F::one(), witness_variables[i]), 
                              lc!()+(F::one(), one), lc!()+(F::one(), 
                              input_variables[i]))?;
    }
    /*************************************************************
    ********The Marlin ZSK Proof Constraint of data quality*******
    *************************************************************/
    let data_quality = cs.new_witness_variable(|| self.data_quality.ok_or(SynthesisError::AssignmentMissing))?;
    let mu = cs.new_witness_variable(|| self.mu.ok_or(SynthesisError::AssignmentMissing))?;
    let sigma = cs.new_witness_variable(|| self.sigma.ok_or(SynthesisError::AssignmentMissing))?;
    let w1 = cs.new_witness_variable(|| {
        let mut data_quality = self.data_quality.ok_or(SynthesisError::AssignmentMissing)?;
        let mu = self.mu.ok_or(SynthesisError::AssignmentMissing)?;
        data_quality.sub_assign(&mu);
        Ok(data_quality)
    })?;
    let w2 = cs.new_witness_variable(|| {
        let mut sigma = self.sigma.ok_or(SynthesisError::AssignmentMissing)?;
        let three = F::one() + F::one() + F::one();
        sigma.mul_assign(&three);

        Ok(sigma)
    })?;

    let w3 = cs.new_witness_variable(|| {
        let mut sigma = self.sigma.ok_or(SynthesisError::AssignmentMissing)?;
        let three = F::one() + F::one() + F::one();
        let two = F::one() + F::one();
        sigma.mul_assign(&three);
        sigma.mul_assign(&two);
        
        Ok(sigma)

    })?;


    let out_minus = cs.new_input_variable(|| {
        let mut data_quality = self.data_quality.ok_or(SynthesisError::AssignmentMissing)?;
        let mu = self.mu.ok_or(SynthesisError::AssignmentMissing)?;
        data_quality.sub_assign(&mu);
        let mut sigma = self.sigma.ok_or(SynthesisError::AssignmentMissing)?;
        let three = F::one() + F::one() + F::one();
        sigma.mul_assign(&three);

        data_quality -= &sigma;

        Ok(data_quality)
    })?;
        
    let out_add = cs.new_input_variable(|| {
        let mut data_quality = self.data_quality.ok_or(SynthesisError::AssignmentMissing)?;
        let mu = self.mu.ok_or(SynthesisError::AssignmentMissing)?;
        data_quality.sub_assign(&mu);
        let mut sigma = self.sigma.ok_or(SynthesisError::AssignmentMissing)?;
        let three = F::one() + F::one() + F::one();
        sigma.mul_assign(&three);

        data_quality += &sigma;

        Ok(data_quality)
    })?;

    let three = F::one() + F::one() + F::one();
    cs.enforce_constraint(lc!() + (F::one(), mu) + (F::one(), w1), lc!() + (F::one(), one), lc!() + (F::one(), data_quality))?;
    cs.enforce_constraint(lc!() + (three, one), lc!() + (F::one(), sigma), lc!() + (F::one(), w2))?;
    cs.enforce_constraint(lc!() + (F::one(), w2) + (F::one(), out_minus), lc!() + (F::one(), one), lc!() + (F::one(), w1))?;
    cs.enforce_constraint(lc!() + (F::one(), w1) + (F::one(), w2), lc!() + (F::one(), one), lc!() + (F::one(), out_add))?;
    cs.enforce_constraint(lc!() + (F::one(), w3) + (F::one(), out_minus), lc!() + (F::one(), one), lc!() + (F::one(), out_add))?;
    Ok(())
    }
}

#[no_mangle]
pub extern "C" fn generate_proof_zebralancer_rewarding(
    mu: usize, sigma: usize, data: usize, raw_data: *const c_char, 
    public_key: *const c_char, private_key: *const c_char, encrypted_data: *const c_char) -> ProofAndVerifyKey {
        let field_bytes = 32; let data_size = 2048; let field_size = 256;
        let num_constraints = {
            let res = data_size / field_size;
            if data_size % field_size == 0 {
                res
            } else {
                res+1
            }
        };
        // TODO: Given aij formula of the number of constraints and variables
        let circuit = CryptoCircuit {
            encrypted_data: convert_c_hexstr_to_bytes(encrypted_data),
            raw_data: convert_c_hexstr_to_bytes(raw_data),
            public_key: convert_c_hexstr_to_bytes(public_key),
            private_key: convert_c_hexstr_to_bytes(private_key),
            num_constraints: num_constraints+1+5, // 1 for key_pair, 5 for quality
            num_variables: 2*(num_constraints + 1) + 8, // Mess number of constraints and variables here
            field_bytes: field_bytes,
            data_quality: Some(Fr::from(data as u128)),
            mu: Some(Fr::from(mu as u128)),
            sigma: Some(Fr::from(sigma as u128)),
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
pub extern "C" fn verify_proof_zebralancer_rewarding(
    quality_one: usize, quality_two: usize, ciphertext: *const c_char, 
    proof: *const c_char, vk: *const c_char) -> bool {
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
    inputs.push(Fr::from(quality_one as u128));
    inputs.push(Fr::from(quality_two as u128));
    MarlinInst::verify(&vk, &inputs[..], &proof, rng).unwrap()
}