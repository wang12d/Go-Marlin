/**
 * mask.rs contains function related to data mask. Such that for a
 * real value v, the masked value if m_v. Given masked value as public
 * input, mask.rs provides function to prove that v + m = m_v where m is
 * added masked without reveavling any information about v and m.
 */
use crate::*;

#[derive(Copy, Clone)]
pub struct DataMaskCircuit<F: Field> {
    pub v: Option<F>,
    pub m: Option<F>,
    pub m_v: Option<F>,
}

impl <F: Field> ConstraintSynthesizer<F> for DataMaskCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // The variable vector will be of the form: w = [w_1, w_2, p1, p2]
        let w1 = cs.new_witness_variable(|| self.v.ok_or(SynthesisError::AssignmentMissing))?;
        let w2 = cs.new_witness_variable(|| self.m.ok_or(SynthesisError::AssignmentMissing))?;
        let w3 = cs.new_witness_variable(|| Ok(F::one()))?;
        let p1 = cs.new_input_variable(|| self.m_v.ok_or(SynthesisError::AssignmentMissing))?;

        // Now adding the constraint information
        cs.enforce_constraint(lc!() + (F::one(), w1) + (F::one(), w2), 
                              lc!() + (F::one(), w3), 
                              lc!() + (F::one(), p1))?;
        Ok(())
    }
}

#[no_mangle] // generate_proof_mask generate the zero-knowledge-proof key and 
pub extern "C" fn generate_proof_mask(v: u64, m: u64, m_v: u64) -> ProofAndVerifyKey {
    let rng = &mut ark_std::rand::rngs::OsRng;
    let mask_circuit = DataMaskCircuit {
        v: Some(Fr::from(v)), 
        m: Some(Fr::from(m)),
        m_v: Some(Fr::from(m_v)),
    };
    let universal_srs = MarlinInst::universal_setup(1, 4, 9, rng).unwrap();
    geneate_proof_and_verify_key(MarlinInst::index, MarlinInst::prove, 
        &universal_srs, mask_circuit, rng
    )
}

#[no_mangle]
pub extern "C" fn verify_proof_mask(m_v: u64, proof: *const c_char, vk: *const c_char) -> bool {
    let rng = &mut ark_std::rand::thread_rng();
    let proof_cstr = unsafe {CStr::from_ptr(proof)};
    let proof_decode = decode(proof_cstr.to_str().unwrap()).unwrap();
    let proof = Proof::deserialize(&proof_decode[..]).unwrap();
    let vk_cstr = unsafe {CStr::from_ptr(vk)};
    let vk_decode = decode(vk_cstr.to_str().unwrap()).unwrap();
    let vk = IndexVerifierKey::deserialize(&vk_decode[..]).unwrap();
    MarlinInst::verify(&vk, &[Fr::from(m_v)], &proof, rng).unwrap()
}