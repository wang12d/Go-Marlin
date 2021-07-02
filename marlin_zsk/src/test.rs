mod go_marlin {
    use crate::{generate_proof, verify_proof, verify};

    #[test]

    fn proof_and_verify() {
        let pg = generate_proof(0, 25, 100);
        assert_eq!(verify_proof(25, 175, pg), true);
    }

    #[test]
    fn verify_noly() {
        assert_eq!(verify(0, 25, 100, 25, 175), true);
    }
}