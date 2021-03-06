use std::ffi::{CString, CStr};
use libc::c_char;
use ark_bls12_381::{Bls12_381, Fr};
use ark_marlin::{Marlin, Proof, IndexVerifierKey, IndexProverKey, UniversalSRS, Error};
use ark_poly::univariate::DensePolynomial;
use ark_std::rand::RngCore;
use ark_serialize::*;
use ark_poly_commit::{marlin_pc::MarlinKZG10, PolynomialCommitment};
use ark_ff::{biginteger::BigInteger256, Field, FromBytes, PrimeField};
use ark_relations::{lc, r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError}};
use blake2::Blake2s;
use hex::{encode, decode};

type MultiPC = MarlinKZG10<Bls12_381, DensePolynomial<Fr>>;
type MarlinInst = Marlin<Fr, MultiPC, Blake2s>;

#[derive(Copy, Clone)]
struct DataQualityCircuit<F: Field> {
    mu: Option<F>,
    sigma: Option<F>,
    data_quality: Option<F>,
    num_constraints: usize,
    num_variables: usize,
}

mod test;

mod zebralancer;

mod crypto;

mod crypto_test;

mod mask;

mod mask_test;

mod utils;

#[repr(C)]
pub struct ProofAndVerifyKey {
    pub proof: *const c_char,
    pub verify_key: *const c_char,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct DataEvaluationResults {
    pub add: usize,
    pub minus: usize,
}

const NUM_CONSTRAINTS: usize = 5;
const NUM_VARIABLES: usize = 9;
const ONE: usize = 1;

// Implentation of the three sigma rule for evaluating data quality
// Note that due to the R1CS constrain system, the concrete constrain should
// encoded to <A, w> * <B, w> = <C, w> where w is the private witness vector,
// A, B, C are corrsponding coefficients, <a, b> means the dot product of vector a and b.
// The final result is computed as: {
//                              out_add = data-mu+3*sigma
//                              out_minus = data-mu-3*sigma
//                            }
impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for DataQualityCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
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
            let three = ConstraintF::one() + ConstraintF::one() + ConstraintF::one();
            sigma.mul_assign(&three);

            Ok(sigma)
        })?;

        let w3 = cs.new_witness_variable(|| {
            let mut sigma = self.sigma.ok_or(SynthesisError::AssignmentMissing)?;
            let three = ConstraintF::one() + ConstraintF::one() + ConstraintF::one();
            let two = ConstraintF::one() + ConstraintF::one();
            sigma.mul_assign(&three);
            sigma.mul_assign(&two);
            
            Ok(sigma)

        })?;

        let one = cs.new_input_variable(|| Ok(ConstraintF::one()))?;

        let out_minus = cs.new_input_variable(|| {
            let mut data_quality = self.data_quality.ok_or(SynthesisError::AssignmentMissing)?;
            let mu = self.mu.ok_or(SynthesisError::AssignmentMissing)?;
            data_quality.sub_assign(&mu);
            let mut sigma = self.sigma.ok_or(SynthesisError::AssignmentMissing)?;
            let three = ConstraintF::one() + ConstraintF::one() + ConstraintF::one();
            sigma.mul_assign(&three);

            data_quality -= &sigma;

            Ok(data_quality)
        })?;
        
        let out_add = cs.new_input_variable(|| {
            let mut data_quality = self.data_quality.ok_or(SynthesisError::AssignmentMissing)?;
            let mu = self.mu.ok_or(SynthesisError::AssignmentMissing)?;
            data_quality.sub_assign(&mu);
            let mut sigma = self.sigma.ok_or(SynthesisError::AssignmentMissing)?;
            let three = ConstraintF::one() + ConstraintF::one() + ConstraintF::one();
            sigma.mul_assign(&three);

            data_quality += &sigma;

            Ok(data_quality)
        })?;

        let three = ConstraintF::one() + ConstraintF::one() + ConstraintF::one();
        cs.enforce_constraint(lc!() + (ConstraintF::one(), mu) + (ConstraintF::one(), w1), lc!() + (ConstraintF::one(), one), lc!() + (ConstraintF::one(), data_quality))?;
        cs.enforce_constraint(lc!() + (three, one), lc!() + (ConstraintF::one(), sigma), lc!() + (ConstraintF::one(), w2))?;
        cs.enforce_constraint(lc!() + (ConstraintF::one(), w2) + (ConstraintF::one(), out_minus), lc!() + (ConstraintF::one(), one), lc!() + (ConstraintF::one(), w1))?;
        cs.enforce_constraint(lc!() + (ConstraintF::one(), w1) + (ConstraintF::one(), w2), lc!() + (ConstraintF::one(), one), lc!() + (ConstraintF::one(), out_add))?;
        cs.enforce_constraint(lc!() + (ConstraintF::one(), w3) + (ConstraintF::one(), out_minus), lc!() + (ConstraintF::one(), one), lc!() + (ConstraintF::one(), out_add))?;

        Ok(())
    }
}

pub fn convert_c_hexstr_to_bytes(encoded_c_str: *const c_char) -> Vec<u8> {
    let encode_str = unsafe {CStr::from_ptr(encoded_c_str)};
    decode(encode_str.to_str().unwrap()).unwrap()
}

// Convert bytes encoded big integer 256 to ark-workers BigInteger256,
// then converts encoded the BigInteger256 to bytes
pub fn field_encode_convert(raw_vec: &[u8]) -> Vec<u8> {
    let mut bytes = raw_vec.to_vec();
    if bytes.len() < 32 {
        let zeros = vec![0 as u8; 32-bytes.len()];
        bytes.reverse();
        bytes = bytes.into_iter().chain(zeros).collect();
        bytes.reverse();
    }
    let fr_element = Fr::new(BigInteger256::read(&bytes[..]).unwrap());
    let mut field_encode = Vec::new();
    fr_element.serialize(&mut field_encode).unwrap();
    return field_encode;
}

// Given corresponding universal reference string and circuit,
// generating the zero knowledge proof and the verify key.
fn geneate_proof_and_verify_key<F, PC, C, R> (
    index: fn(&UniversalSRS<F,PC>, C)->Result<(IndexProverKey<F, PC>, IndexVerifierKey<F, PC>), Error<PC::Error>>,
    prove: fn(&IndexProverKey<F,PC>, C, &mut R)->Result<Proof<F, PC>, Error<PC::Error>>,
    srs: &UniversalSRS<F, PC>, c: C, zk_rand: &mut R) -> ProofAndVerifyKey  
where F: PrimeField,
      PC: PolynomialCommitment<F, DensePolynomial<F>>, 
      C: ConstraintSynthesizer<F>+Clone, 
      R: RngCore,
      {
    let (index_pk, index_vk) = index(srs, c.clone()).unwrap();

    let proof = prove(&index_pk, c, zk_rand).unwrap();
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
pub extern "C" fn generate_proof_echain(mu: u32, sigma: u32, data: u32) -> ProofAndVerifyKey {
    
    let rng = &mut ark_std::rand::rngs::OsRng;

    let universal_srs = MarlinInst::universal_setup(NUM_CONSTRAINTS, NUM_VARIABLES, NUM_VARIABLES, rng).unwrap();
    let circ = DataQualityCircuit {
        mu: Some(Fr::from(mu as u128)),
        sigma: Some(Fr::from(sigma as u128)),
        data_quality: Some(Fr::from(data as u128)),
        num_constraints: NUM_CONSTRAINTS,
        num_variables: NUM_VARIABLES,
    };
    geneate_proof_and_verify_key(MarlinInst::index, MarlinInst::prove, 
        &universal_srs, circ, rng
    )
}

#[no_mangle]
pub extern "C" fn verify_proof_echain(eval: DataEvaluationResults, proof: *const c_char, vk: *const c_char) -> bool {
    let rng = &mut ark_std::test_rng();
    let proof_cstr = unsafe {CStr::from_ptr(proof)};
    let proof_decode = decode(proof_cstr.to_str().unwrap()).unwrap();
    let proof = Proof::deserialize(&proof_decode[..]).unwrap();
    let vk_cstr = unsafe {CStr::from_ptr(vk)};
    let vk_decode = decode(vk_cstr.to_str().unwrap()).unwrap();
    let vk = IndexVerifierKey::deserialize(&vk_decode[..]).unwrap();
    MarlinInst::verify(&vk, &[Fr::from(ONE as u128), Fr::from(eval.minus as u128), Fr::from(eval.add as u128)], 
        &proof, rng).unwrap()
}

#[no_mangle]
pub extern "C" fn free_proof_and_verify(proof: *const c_char, vk: *const c_char) {
    let _ = unsafe {CString::from_raw(proof as *mut _)};
    let _ = unsafe {CString::from_raw(vk as *mut _)};
}
