bool 
verify(unsigned int mu, unsigned int sigma, 
    unsigned int data_quality, unsigned int out_one, unsigned int out_two);

void* generate_proof(unsigned int mu, unsigned int sigma, unsigned int data);


bool verify_proof(unsigned int out_one, unsigned int out_two, void* proof_and_key);