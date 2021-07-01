use ark_marlin::{Marlin, Proof, IndexVerifierKey};
use ark_bls12_381::{Bls12_381, Fr};
use ark_poly::univariate::DensePolynomial;
use ark_serialize::*;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_ff::Field;
use ark_relations::{lc, r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError}};
use blake2::Blake2s;

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

#[repr(C)]
pub struct ProofAndVerifyKey {
    pub proof: Vec<u8>,
    pub proof_size: usize,
    pub verify_key: Vec<u8>,
    pub verify_key_size: usize,
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

#[no_mangle]
pub extern "C" fn verify(mu: u32, sigma: u32, data: u32, output_one: u32, output_two: u32) -> bool {

    let rng = &mut ark_std::test_rng();

    let universal_srs = MarlinInst::universal_setup(NUM_CONSTRAINTS, NUM_VARIABLES, NUM_VARIABLES, rng).unwrap();
    let circ = DataQualityCircuit {
        mu: Some(Fr::from(mu as u128)),
        sigma: Some(Fr::from(sigma as u128)),
        data_quality: Some(Fr::from(data as u128)),
        num_constraints: NUM_CONSTRAINTS,
        num_variables: NUM_VARIABLES,
    };
    let (index_pk, index_vk) = MarlinInst::index(&universal_srs, circ.clone()).unwrap();

    let proof = MarlinInst::prove(&index_pk, circ, rng).unwrap();
    MarlinInst::verify(&index_vk, &[Fr::from(ONE as u128), Fr::from(output_one as u128), Fr::from(output_two as u128)], &proof, rng).unwrap()
}

#[no_mangle]
pub extern "C" fn generate_proof(mu: u32, sigma: u32, data: u32) -> ProofAndVerifyKey
{
    
    let rng = &mut ark_std::test_rng();

    let universal_srs = MarlinInst::universal_setup(NUM_CONSTRAINTS, NUM_VARIABLES, NUM_VARIABLES, rng).unwrap();
    let circ = DataQualityCircuit {
        mu: Some(Fr::from(mu as u128)),
        sigma: Some(Fr::from(sigma as u128)),
        data_quality: Some(Fr::from(data as u128)),
        num_constraints: NUM_CONSTRAINTS,
        num_variables: NUM_VARIABLES,
    };
    let (index_pk, index_vk) = MarlinInst::index(&universal_srs, circ.clone()).unwrap();

    let proof = MarlinInst::prove(&index_pk, circ, rng).unwrap();
    let mut vec_proof: Vec<u8> = Vec::new();
    proof.serialize(&mut vec_proof).unwrap();
    let proof_size = proof.serialized_size();
    let mut vec_vk = Vec::new();
    index_vk.serialize(&mut vec_vk).unwrap();
    let index_vk_size = index_vk.serialized_size();
    ProofAndVerifyKey {
        proof: vec_proof,
        proof_size: proof_size,
        verify_key: vec_vk,
        verify_key_size: index_vk_size,
    }
}


#[no_mangle]
pub extern "C" fn verify_proof(out_one: u32, out_two: u32, proof_and_key: ProofAndVerifyKey) -> bool
{
    let rng = &mut ark_std::test_rng();
    let vec_proof = proof_and_key.proof.clone();
    let proof = Proof::deserialize(&vec_proof[..]).unwrap();
    let vec_verify_key = proof_and_key.verify_key.clone();
    let vk = IndexVerifierKey::deserialize(&vec_verify_key[..]).unwrap();
    MarlinInst::verify(&vk, &[Fr::from(ONE as u128), Fr::from(out_one as u128), Fr::from(out_two as u128)], 
        &proof, rng).unwrap()
}
