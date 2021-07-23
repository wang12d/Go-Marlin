#include <stdbool.h>

typedef struct {
    const char* proof;
    const char* vk;
} ProofAndVerifyKey;

typedef struct {
    const char* sk;
    const char* pk;
    const char* cert;
} ZebraLancerWitness;

typedef struct {
    unsigned int add;
    unsigned int minus;
} DataEvaluationResult;

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

ProofAndVerifyKey
generate_proof_zebralancer_rewarding(unsigned int mu, unsigned int sigma, unsigned int* data, unsigned int size,
                const char* public_key, const char* private_key, const char** encrypted_data, const char** raw_data);

bool
verify_proof_zebralancer_rewarding(DataEvaluationResult* eval, unsigned int size,
    const char** ciphertext, const char* proof, const char* vk);