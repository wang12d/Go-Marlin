#include "marlin_zsk.h"
#include <stdio.h>
#include <malloc.h>

int
main()
{
   struct ProofAndVerifyKey pvk = generate_proof(0, 25, 100);
   printf("C proof address: %p\n", (void*) pvk.proof);
   printf("C proof size: %d\n", pvk.proof_size);
   printf("C verify key address: %p\n", (void*) pvk.verify_key);
   printf("C verify key size: %d\n", pvk.verify_key_size);
   printf("Verify result: %d\n", verify_proof(25, 175, pvk));
   return 0;
}