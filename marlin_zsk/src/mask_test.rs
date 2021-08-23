#![allow(dead_code)]
#![allow(unused)]

mod mask_test {

    use crate::crypto::*;
    use crate::mask::*;
    use crate::*;

    #[test]
    fn test_mask_proof() {
        let proof_and_vk = generate_proof_mask(20, 234234, 234254);
        assert_eq!(verify_proof_mask(234254, proof_and_vk.proof, proof_and_vk.verify_key), true);
        assert_eq!(verify_proof_mask(234252, proof_and_vk.proof, proof_and_vk.verify_key), false);
    }
}