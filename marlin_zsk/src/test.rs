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
    fn proof_zebralancer() {
        let pk = CString::new("77d829b7bea93fc0428656c2d7a201275991fff9707958ada6c5d7e8c9a8712c").expect(ERR);
        let sk = CString::new("5b7ccc110b2265a32d9c9c4ebebccb8e6dc10cf68da9c003735a9288c47f950277d829b7bea93fc0428656c2d7a201275991fff9707958ada6c5d7e8c9a8712c").expect(ERR);
        let mpk = CString::new("53fbfa0f185240b0d98c72c0080222d3b6be6be16affd39800f3bc14dc2c8ebb").expect(ERR);
        // let msk = CString::new("e55aeb9fc6be2f450276f8a9765cc6d57ccfe2a00bd5e7cbbb378c3ff838fe6353fbfa0f185240b0d98c72c0080222d3b6be6be16affd39800f3bc14dc2c8ebb").expect(ERR);
        let prefix = CString::new("68656c6c6f").expect(ERR);
        let msg = CString::new("20776f726c642e").expect(ERR);
        let cert = CString::new("389b100d34ef3a302a2e3d18fcc181b965daf0f5f978ecd832a2d5d5d152d31ffdfb5746955954e68ded23059e308e46d213d0f620c7f329b4ae122457748600").expect(ERR);
        let t1 = CString::new("7945212d2b2e3aad256df296c636af8eee2bee56909eb675345363407a69e5bd").expect(ERR);
        let t2 = CString::new("eb89eda7e9cc68ffb2d25ba74296a64b6f25ee983cb2011be5597a54d88cd23a").expect(ERR);
        let zebralancer_witness = ZebraLancerWitness{
            sk: sk.as_ptr(),
            pk: pk.as_ptr(),
            cert: cert.as_ptr(),
        };
        generate_proof_zebralancer(prefix.as_ptr(), msg.as_ptr(), mpk.as_ptr(), t1.as_ptr(), t2.as_ptr(), zebralancer_witness);
    }
}