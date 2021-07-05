#include <stdbool.h>

typedef struct ProofAndVerifyKey {
    const char* proof;
    const char* verify_key;
} ProofAndVerifyKey;

ProofAndVerifyKey
generate_proof_echain(unsigned int mu, unsigned int sigma, unsigned int data);


bool 
verify_proof_echain(unsigned int out_one, unsigned int out_two, const char* proof, const char* verify_key);

void
free_proof_and_verify(const char* proof, const char* verify_key);