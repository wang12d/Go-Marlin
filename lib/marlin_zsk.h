#include <stdbool.h>

typedef struct ProofAndVerifyKey {
    const char* proof;
    const char* vk;
} ProofAndVerifyKey;

typedef struct ZebraLancerWitness {
    const char* sk;
    const char* pk;
    const char* cert;
} ZebraLancerWitness;

ProofAndVerifyKey
generate_proof_echain(unsigned int mu, unsigned int sigma, unsigned int data);


bool 
verify_proof_echain(unsigned int out_one, unsigned int out_two, const char* proof, const char* verify_key);

void
free_proof_and_verify(const char* proof, const char* verify_key);

ProofAndVerifyKey
generate_proof_zebralancer(const char* prefix, const char* msg, 
    const char* mpk, const char* t1, const char* t2, ZebraLancerWitness witness);

bool
verify_proof_zebralancer(const char* t1, const char* t2, const char* proof, const char* vk);