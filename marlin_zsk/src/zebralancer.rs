use crate::*;
use ed25519_dalek::{Signature, Verifier, PublicKey, Keypair};
use std::convert::TryInto;
use sha2::Sha256;
use crate::utils::convert_bytes_to_field_elements;
use hmac::{Hmac, NewMac, Mac};

type HmacSha256 = Hmac<Sha256>;


// The ZebraLacner witness, which is used to prove the sk, pk, cert.
// Notes that sk, pk and cert are hex encoded c string.
#[repr(C)]
pub struct ZebraLancerWitness {
    pub sk: *const c_char,
    pub pk: *const c_char,
    pub cert: *const c_char,
}

#[derive(Clone)]
struct ZebraLancerCircuit<F: Field> {
    sk: Vec<u8>, 
    pk: Vec<u8>,
    cert: Vec<u8>,
    prefix: Vec<u8>,
    msg: Vec<u8>,
    mpk: Vec<u8>,
    t1: Vec<u8>,
    t2: Vec<u8>,
    num_variables: usize,
    num_constraints: usize,
    mpk_field_elements: Vec<F>,
    prefix_msg_elements: Vec<F>,
    field_size: usize,
    
}


impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for ZebraLancerCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let one = cs.new_input_variable(|| Ok(ConstraintF::one()))?;
        let cert = Signature::new(self.cert.try_into().unwrap());
        let mpk = PublicKey::from_bytes(&self.mpk[..]).unwrap();
        let field_mpk_witness_variable: Vec<_> =  {
            let field_mpk_elements = convert_bytes_to_field_elements::<ConstraintF>(&self.mpk, self.field_size);
            field_mpk_elements.into_iter().map(|f| cs.new_witness_variable(|| Ok(f)).unwrap()).collect()   // Convert bytes to number for comparsion
        };
        let field_mpk_input_variable: Vec<_> = self.mpk_field_elements.into_iter().map(|f| cs.new_input_variable(|| Ok(f)).unwrap()).collect();
        // Verify the integrity of p||m and mpk
        for (w, i) in field_mpk_witness_variable.into_iter().zip(field_mpk_input_variable.into_iter()) {
            cs.enforce_constraint(lc!() + (ConstraintF::one(), i), 
                                  lc!() + (ConstraintF::one(), one), 
                                  lc!() + (ConstraintF::one(), w))?;
        }
        let prefix_msg = self.prefix.iter().chain(&self.msg).cloned().collect();
        let field_prefix_msg_witness_variable: Vec<_> = {
            let field_prefix_msg_elements = convert_bytes_to_field_elements::<ConstraintF>(&prefix_msg, self.field_size);
            field_prefix_msg_elements.into_iter().map(|f| cs.new_witness_variable(|| Ok(f)).unwrap()).collect()
        };
        let field_prefix_msg_input_variable: Vec<_> = self.prefix_msg_elements.into_iter().map(|f| cs.new_input_variable(|| Ok(f)).unwrap()).collect();
        for (w, i) in field_prefix_msg_witness_variable.into_iter().zip(field_prefix_msg_input_variable.into_iter()) {
            cs.enforce_constraint(lc!() + (ConstraintF::one(), i), 
                                  lc!() + (ConstraintF::one(), one), 
                                  lc!() + (ConstraintF::one(), w))?;
        }

        let w1 = {  // The verification of digital signature
            mpk.verify(&self.pk[..], &cert).unwrap(); // Unit if success verify the result
            Some(ConstraintF::one())
        };
        let w1 = cs.new_witness_variable(|| w1.ok_or(SynthesisError::AssignmentMissing))?;
        let pk = PublicKey::from_bytes(&self.pk[..]).unwrap();
        let key_pair = Keypair::from_bytes(&self.sk[..]).unwrap();
        let w2 = {
            // Check the sk and public key validity
            let gpk: PublicKey = key_pair.public; // From sk generate pk
            let mut val = ConstraintF::zero();
            if gpk == pk {
                val += ConstraintF::one();
            }
            Some(val)
        };
        let w2 = cs.new_witness_variable(|| w2.ok_or(SynthesisError::AssignmentMissing))?;
        let t1 = Some(ConstraintF::read(&field_encode_convert(&self.t1[..])[..]).unwrap());
        let t2 = Some(ConstraintF::read(&field_encode_convert(&self.t2[..])[..]).unwrap());
        let w3 = {
            let mut h = HmacSha256::new_from_slice(&self.prefix[..]).expect("HMAC can take key of any size"); 
            h.update(&self.sk[..]);
            let h_bytes = h.finalize().into_bytes();
            Some(ConstraintF::read(&field_encode_convert(&h_bytes.to_vec()[..])[..]).unwrap())
        };
        let w3 = cs.new_witness_variable(|| w3.ok_or(SynthesisError::AssignmentMissing))?;
        let w4 = {
            let prefix_with_msg: Vec<u8> = self.prefix.iter().chain(&self.msg).cloned().collect();
            let mut h = HmacSha256::new_from_slice(&prefix_with_msg[..]).expect("HMAC can take key of any size"); 
            h.update(&self.sk[..]);
            let h_bytes = h.finalize().into_bytes();
            Some(ConstraintF::read(&field_encode_convert(&h_bytes.to_vec()[..])[..]).unwrap())
        };
        let w4 = cs.new_witness_variable(|| w4.ok_or(SynthesisError::AssignmentMissing))?;
        let t1 = cs.new_input_variable(|| t1.ok_or(SynthesisError::AssignmentMissing))?;
        let t2 = cs.new_input_variable(|| t2.ok_or(SynthesisError::AssignmentMissing))?;

        cs.enforce_constraint(lc!() + (ConstraintF::one(), w1), lc!() + (ConstraintF::one(), one), lc!() + (ConstraintF::one(), one))?;
        cs.enforce_constraint(lc!() + (ConstraintF::one(), w2), lc!() + (ConstraintF::one(), one), lc!() + (ConstraintF::one(), one))?;
        cs.enforce_constraint(lc!() + (ConstraintF::one(), w3), lc!() + (ConstraintF::one(), one), lc!() + (ConstraintF::one(), t1))?;
        cs.enforce_constraint(lc!() + (ConstraintF::one(), w4), lc!() + (ConstraintF::one(), one), lc!() + (ConstraintF::one(), t2))?;

        Ok(())
    }
}


#[no_mangle]
pub extern "C" fn generate_proof_zebralancer(prefix: *const c_char, 
    msg: *const c_char, mpk: *const c_char, t1: *const c_char, 
    t2: *const c_char, witness: ZebraLancerWitness) -> ProofAndVerifyKey {
    let mpk = convert_c_hexstr_to_bytes(mpk); 
    let field_size = 32;
    let mpk_filed_elements = convert_bytes_to_field_elements(&mpk, field_size);
    let prefix = convert_c_hexstr_to_bytes(prefix);
    let msg = convert_c_hexstr_to_bytes(msg);
    let prefix_msg: Vec<_> = prefix.iter().chain(&msg).cloned().collect();  // get prefix
    let prefix_msg_elements = convert_bytes_to_field_elements(&prefix_msg, field_size);
    let circuit = ZebraLancerCircuit {
        num_variables: 7 + 2*(prefix_msg.len() + mpk.len()),
        num_constraints: 4 + prefix_msg.len() + mpk.len(),
        sk: convert_c_hexstr_to_bytes(witness.sk), 
        pk: convert_c_hexstr_to_bytes(witness.pk),
        cert: convert_c_hexstr_to_bytes(witness.cert),
        prefix: prefix,
        msg: msg,
        mpk: mpk,
        t1: convert_c_hexstr_to_bytes(t1), 
        t2: convert_c_hexstr_to_bytes(t2),
        mpk_field_elements: mpk_filed_elements,
        prefix_msg_elements: prefix_msg_elements,
        field_size: 32,
    };

    let rng = &mut ark_std::test_rng();
    let universal_srs = MarlinInst::universal_setup(circuit.num_constraints,
        circuit.num_variables, circuit.num_variables, 
        rng).unwrap();
    let (index_pk, index_vk) = MarlinInst::index(&universal_srs, circuit.clone()).unwrap();

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
pub extern "C" fn verify_proof_zebralancer(prefix: *const c_char, msg: *const c_char, mpk: *const c_char, t1: *const c_char, t2: *const c_char, 
        proof: *const c_char, vk: *const c_char) -> bool {
    let rng = &mut ark_std::test_rng();
    let proof = {
        let proof_cstr = unsafe {CStr::from_ptr(proof)};
        let proof_decode = decode(proof_cstr.to_str().unwrap()).unwrap();                
        Proof::deserialize(&proof_decode[..]).unwrap()
    };
    let field_size = 32;
    let mpk_field_elements: Vec<_> = {
        let mpk_bytes = convert_c_hexstr_to_bytes(mpk);
        convert_bytes_to_field_elements::<Fr>(&mpk_bytes, field_size)
    };
    let prefix_msg_field_elements: Vec<_> = {
        let prefix = convert_c_hexstr_to_bytes(prefix);
        let msg = convert_c_hexstr_to_bytes(msg);
        let prefix_msg = prefix.into_iter().chain(msg).collect();
        convert_bytes_to_field_elements::<Fr>(&prefix_msg, field_size)
    };
    let mut public_inputs: Vec<_> = vec![Fr::from(1)];
    let elements: Vec<_> = mpk_field_elements.into_iter().chain(prefix_msg_field_elements).collect();
    public_inputs = public_inputs.into_iter().chain(elements).collect();
    let vk = {
        let vk_cstr = unsafe {CStr::from_ptr(vk)};
        let vk_decode = decode(vk_cstr.to_str().unwrap()).unwrap();
        IndexVerifierKey::deserialize(&vk_decode[..]).unwrap()
    };

    // adding t1 and t2 to public inputs
    public_inputs.push(Fr::read(&field_encode_convert(&convert_c_hexstr_to_bytes(t1)[..])[..]).unwrap());
    public_inputs.push(Fr::read(&field_encode_convert(&convert_c_hexstr_to_bytes(t2)[..])[..]).unwrap());
    MarlinInst::verify(&vk, &public_inputs, &proof, rng)
        .unwrap()
}