#![allow(dead_code)]
#![allow(unused)]
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
        assert_eq!(verify_proof_echain(DataEvaluationResults{add:175, minus:25}, proof.as_ptr(), vk.as_ptr()), true);
    }

    #[test]
    fn proof_and_verify_zebralancer() {
        let pk = CString::new("247e085a737848fb4fc14506d5db5ec92de787c68455569ca5f0346773de1a8d").expect(ERR);
        let sk = CString::new("420e81e6678755d42e9c579968b89b520ad16c92708044517877f46cd75552f1247e085a737848fb4fc14506d5db5ec92de787c68455569ca5f0346773de1a8d").expect(ERR);
        let mpk = CString::new("c7b8d0f66cf9f4cf009d5b2244739aa7dbbc786fbc5d26638b4a682e09957b4d986f99c1a072606fdcddf2e4564fc19e948e600331dd9bac4c80fe39ffee3b7e70e2aed0880b2e142a69cf9993df599d9995c8dde9056ccb4f37ce9caf3c436bc69e315ebab0343b90010b7daee71f10d3318470a14fc63acd0aa6d6a2229477f3953f207bfb8b396ee479c153d2fb873e6b673d493bd974f1ca291baa697ece8fb37dbe4a869884b2626462c55b723305e34a17ee5a5e30079cfe4002e572744538b1f0c83064be28a72283bc8d908f0597c659db76aa82c028c304850b960112ddf86978c2df28e41e7303a22bc8eb09131c8f8bf8288f2c2bed7eb5d9c65b").expect(ERR);
        let prefix = CString::new("68656c6c6f").expect(ERR);
        let msg = CString::new("20776f726c642e").expect(ERR);
        let cert = CString::new("c7b8d0f66cf9f4cf009d5b2244739aa7dbbc786fbc5d26638b4a682e09957b4d986f99c1a072606fdcddf2e4564fc19e948e600331dd9bac4c80fe39ffee3b7e70e2aed0880b2e142a69cf9993df599d9995c8dde9056ccb4f37ce9caf3c436bc69e315ebab0343b90010b7daee71f10d3318470a14fc63acd0aa6d6a2229477f3953f207bfb8b396ee479c153d2fb873e6b673d493bd974f1ca291baa697ece8fb37dbe4a869884b2626462c55b723305e34a17ee5a5e30079cfe4002e572744538b1f0c83064be28a72283bc8d908f0597c659db76aa82c028c304850b960112ddf86978c2df28e41e7303a22bc8eb09131c8f8bf8288f2c2bed7eb5d9c65b").expect(ERR);
        let t1 = CString::new("0a7e656a0c1b6b5a10fadbf68bbeabc62a1bc39150e3395e03f6e7ee4688b255").expect(ERR);
        let t2 = CString::new("02de24444262533b4083c0cd16430a8c3ed7ae8380eb019eadca764aac4e132b").expect(ERR);
        let zebralancer_witness = ZebraLancerWitness{
            sk: sk.as_ptr(),
            pk: pk.as_ptr(),
            cert: cert.as_ptr(),
        };
        let pg = generate_proof_zebralancer(prefix.as_ptr(), msg.as_ptr(), mpk.as_ptr(), t1.as_ptr(), t2.as_ptr(), zebralancer_witness);
        let result = verify_proof_zebralancer(prefix.as_ptr(), msg.as_ptr(), mpk.as_ptr(), t1.as_ptr(), t2.as_ptr(), pg.proof, pg.verify_key);
        assert_eq!(result, true);
    }
}