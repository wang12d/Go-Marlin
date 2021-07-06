use crate::*;
use std::marker::PhantomData;
use ed25519_dalek::{Signature, Verifier, PublicKey, Keypair};
use std::convert::TryInto;
use sha2::Sha256;
use hmac::{Hmac, NewMac, Mac};

type HmacSha256 = Hmac<Sha256>;

fn field_encode_convert(raw_vec: Vec<u8>) -> Vec<u8> {
    let fr_element = Fr::new(BigInteger256::read(&raw_vec[..]).unwrap());
    let mut field_encode = Vec::new();
    fr_element.serialize(&mut field_encode).unwrap();
    return field_encode;
}

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
    
    _marker: PhantomData<F>,
}


impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for ZebraLancerCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let cert = Signature::new(self.cert.try_into().unwrap());
        let mpk = PublicKey::from_bytes(&self.mpk[..]).unwrap();
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
        let t1 = Some(ConstraintF::read(&field_encode_convert(self.t1)[..]).unwrap());
        let t2 = Some(ConstraintF::read(&field_encode_convert(self.t2)[..]).unwrap());
        let w3 = {
            let mut h = HmacSha256::new_from_slice(&self.prefix[..]).expect("HMAC can take key of any size"); 
            h.update(&self.sk[..]);
            let h_bytes = h.finalize().into_bytes();
            Some(ConstraintF::read(&field_encode_convert(h_bytes.to_vec())[..]).unwrap())
        };
        let w3 = cs.new_witness_variable(|| w3.ok_or(SynthesisError::AssignmentMissing))?;
        let w4 = {
            let prefix_with_msg: Vec<u8> = self.prefix.iter().chain(&self.msg).cloned().collect();
            let mut h = HmacSha256::new_from_slice(&prefix_with_msg[..]).expect("HMAC can take key of any size"); 
            h.update(&self.sk[..]);
            let h_bytes = h.finalize().into_bytes();
            Some(ConstraintF::read(&field_encode_convert(h_bytes.to_vec())[..]).unwrap())
        };
        let w4 = cs.new_witness_variable(|| w4.ok_or(SynthesisError::AssignmentMissing))?;
        let t1 = cs.new_input_variable(|| t1.ok_or(SynthesisError::AssignmentMissing))?;
        let t2 = cs.new_input_variable(|| t2.ok_or(SynthesisError::AssignmentMissing))?;
        let one = cs.new_input_variable(|| Ok(ConstraintF::one()))?;

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
    let circuit = ZebraLancerCircuit {
        sk: convert_c_hexstr_to_bytes(witness.sk),
        pk: convert_c_hexstr_to_bytes(witness.pk),
        cert: convert_c_hexstr_to_bytes(witness.cert),
        prefix: convert_c_hexstr_to_bytes(prefix),
        msg: convert_c_hexstr_to_bytes(msg),
        mpk: convert_c_hexstr_to_bytes(mpk),
        t1: convert_c_hexstr_to_bytes(t1), 
        t2: convert_c_hexstr_to_bytes(t2),
        num_variables: 7 as usize,
        num_constraints: 4 as usize,            
        _marker: PhantomData::<Fr>,
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
pub extern "C" fn verify_proof_zebralancer(t1: *const c_char, t2: *const c_char, 
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
        MarlinInst::verify(&vk, &[Fr::new(BigInteger256::read(&convert_c_hexstr_to_bytes(t1)[..]).unwrap()), 
        Fr::new(BigInteger256::read(&convert_c_hexstr_to_bytes(t2)[..]).unwrap()), Fr::from(1 as u128)], &proof, rng).unwrap()
}