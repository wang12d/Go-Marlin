#![allow(dead_code)]
mod go_marlin {
    use crate::{generate_proof_echain, verify_proof_echain};
    use std::ffi::{CString};

    #[test]

    fn proof_and_verify() {
        let pg = generate_proof_echain(0, 25, 100);
        let proof = unsafe {CString::from_raw(pg.proof as *mut _)};
        let vk = unsafe {CString::from_raw(pg.verify_key as *mut _)};
        assert_eq!(verify_proof_echain(25, 175, proof.as_ptr(), vk.as_ptr()), true);
    }
}