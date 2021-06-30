use ark_marlin::Marlin;
use ark_bls12_381::{Bls12_381, Fr};
use ark_poly::univariate::DensePolynomial;
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

// Implentation of the three sigma rule for evaluating data quality
// Note that due to the R1CS constrain system, the concrete constrain should
// encoded to <A, w> * <B, w> = <C, w> where w is the private witness vector,
// A, B, C are corrsponding coefficients.
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
        let one = cs.new_input_variable(|| Ok(ConstraintF::one()))?;
        let out = cs.new_witness_variable(|| {
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
        cs.enforce_constraint(lc!() + (ConstraintF::one(), w1) + (ConstraintF::one(), w2), lc!() + (ConstraintF::one(), one), lc!() + (ConstraintF::one(), out))?;

        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn verify() -> bool {

    let rng = &mut ark_std::test_rng();

    let universal_srs = MarlinInst::universal_setup(3, 7, 3, rng).unwrap();
    let circ = DataQualityCircuit {
        mu: Some(Fr::from(0u128)),
        sigma: Some(Fr::from(25u128)),
        data_quality: Some(Fr::from(100u128)),
        num_constraints: 3,
        num_variables: 7,
    };
    let (index_pk, index_vk) = MarlinInst::index(&universal_srs, circ.clone()).unwrap();
    println!("Called index");

    let proof = MarlinInst::prove(&index_pk, circ, rng).unwrap();
    println!("Called prover");

    MarlinInst::verify(&index_vk, &[Fr::from(1u128)], &proof, rng).unwrap()
}
