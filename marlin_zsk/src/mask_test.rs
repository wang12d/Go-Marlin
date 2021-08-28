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

    #[test]
    fn test_mask_batch_proof() {
        let proof_and_vk = generate_proof_batch_mask(vec![20, 30, 40, 50, 60, 70, 80, 90, 100, 110], 
                                                     vec![2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000, 11000], 
                                                     vec![2020, 3030, 4040, 5050, 6060, 7070, 8080, 9090, 10100, 11110]);
        assert_eq!(verify_proof_batch_mask(vec![2020, 3030, 4040, 5050, 6060, 7070, 8080, 9090, 10100, 11110], proof_and_vk.proof, proof_and_vk.verify_key), true);
        assert_eq!(verify_proof_batch_mask(vec![2021, 3030, 4040, 5050, 6060, 7070, 8080, 9090, 10100, 11110], proof_and_vk.proof, proof_and_vk.verify_key), false);
    }
}