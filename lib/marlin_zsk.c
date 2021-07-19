#include "marlin_zsk.h"
#include <stdio.h>
#include <malloc.h>

int
main()
{
   struct ProofAndVerifyKey pvk = generate_proof_echain(0, 25, 100);
   printf("C proof address: %p\n", (void*) pvk.proof);
   printf("C verify key address: %p\n", (void*) pvk.vk);
   printf("Verify result: %d\n", verify_proof_echain(25, 175, pvk.proof, pvk.vk));
   return 0;
}