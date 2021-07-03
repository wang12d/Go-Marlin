#include <stdbool.h>

bool 
verify(unsigned int mu, unsigned int sigma, 
    unsigned int data_quality, unsigned int out_one, unsigned int out_two);

struct ProofAndVerifyKey 
{
    unsigned char** proof;
    unsigned int proof_size;
    unsigned char** verify_key;
    unsigned int verify_key_size;
};

struct ProofAndVerifyKey
generate_proof(unsigned int mu, unsigned int sigma, unsigned int data);


bool 
verify_proof(unsigned int out_one, unsigned int out_two, struct ProofAndVerifyKey proof_and_key);