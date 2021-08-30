#include <stdbool.h>
#include <stdint.h>

typedef unsigned long long ull;
typedef struct ProofAndVerifyKey {
    const char* proof;
    const char* vk;
} ProofAndVerifyKey;

typedef struct ZebraLancerWitness {
    const char* sk;
    const char* pk;
    const char* cert;
} ZebraLancerWitness;

typedef struct DataEvaluationResult {
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

ProofAndVerifyKey
generate_proof_mask(ull value, ull mask, ull masked_value);

bool
verify_proof_mask(ull masked_value, const char* proof, const char* verify_key);

ProofAndVerifyKey
generate_proof_batch_mask(ull* values, ull* masks, 
        ull* masked_values, ull number_of_elements);

bool
verify_proof_batch_mask(ull* masked_values, ull number_of_elements, 
    const char* proof, const char* vk);