#![allow(dead_code)]
mod go_marlin {
    use crate::*;
    use ark_ff::{biginteger::BigInteger256, FromBytes};
    use crate::zebralancer::*;
    use std::ffi::{CString};

    const ERR: &str = "CString error";

    #[test]
    fn proof_and_verify_echain() {
        let pg = generate_proof_echain(0, 25, 100);
        let proof = unsafe {CString::from_raw(pg.proof as *mut _)};
        let vk = unsafe {CString::from_raw(pg.verify_key as *mut _)};
        assert_eq!(verify_proof_echain(25, 175, proof.as_ptr(), vk.as_ptr()), true);
    }

    #[test]
    fn proof_and_verify_zebralancer() {
        let pk = CString::new("8eb91be563e317aec67a60e86e9c8a1ae99a07a58aae084fb8dd46c4f34ed26d").expect(ERR);
        let sk = CString::new("d552dec4b7e9ea866e34ff5dcf465070b3ecc6f39f8d969fb09d99afc214b0eb8eb91be563e317aec67a60e86e9c8a1ae99a07a58aae084fb8dd46c4f34ed26d").expect(ERR);
        let mpk = CString::new("8d30d25a2b0919a3e5e324fdde4c298c45400f1f97e65569a95cf97178796be8").expect(ERR);
        let prefix = CString::new("68656c6c6f").expect(ERR);
        let msg = CString::new("20776f726c642e").expect(ERR);
        let cert = CString::new("2f41ab8dfed91685543c28d0d9361c01ecaba625b4387f78fc8e878dfa1ac46a1e9f90a220ddae5363a1f18cd444b7b2fd622951804655021c557b5c9b9ccb03").expect(ERR);
        let t1 = CString::new("0a7e656a0c1b6b5a10fadbf68bbeabc62a1bc39150e3395e03f6e7ee4688b255").expect(ERR);
        let t2 = CString::new("02de24444262533b4083c0cd16430a8c3ed7ae8380eb019eadca764aac4e132b").expect(ERR);
        let zebralancer_witness = ZebraLancerWitness{
            sk: sk.as_ptr(),
            pk: pk.as_ptr(),
            cert: cert.as_ptr(),
        };
        let pg = generate_proof_zebralancer(prefix.as_ptr(), msg.as_ptr(), mpk.as_ptr(), t1.as_ptr(), t2.as_ptr(), zebralancer_witness);
        let result = verify_proof_zebralancer(t1.as_ptr(), t2.as_ptr(), pg.proof, pg.verify_key);
        assert_eq!(result, true);
    }
}