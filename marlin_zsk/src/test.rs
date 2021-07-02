mod go_marlin {
    use crate::{generate_proof, verify_proof, verify};
    use std::ffi::{CString, CStr};

    #[test]

    fn proof_and_verify() {
        let pg = generate_proof(0, 25, 100);
        let proof = unsafe {CString::from_raw(pg.proof as *mut _)};
        let vk = unsafe {CString::from_raw(pg.verify_key as *mut _)};
        assert_eq!(verify_proof(25, 175, proof.as_ptr(), vk.as_ptr()), true);
    }

    #[test]
    fn verify_noly() {
        assert_eq!(verify(0, 25, 100, 25, 175), true);
    }
}