#include "marlin_zsk.h"
#include <stdio.h>
#include <malloc.h>
#include <string.h>

int
main()
{
   struct ProofAndVerifyKey pvk = generate_proof_mask(24, 25, 49);
   printf("Proof size: %ld, Verify key size: %ld\n", strlen(pvk.proof), strlen(pvk.vk));
   printf("Verify result: %d\n", verify_proof_mask(49, pvk.proof, pvk.vk));
   uint64_t values[10] = {24, 24, 24, 24, 24, 24, 24, 24, 24, 24}; 
   uint64_t masks[10] = {25, 25, 25, 25, 25, 25, 25, 25, 25, 25};
   uint64_t masked_values[10] = {49, 49, 49, 49, 49, 49, 49, 49, 49, 49};
   struct ProofAndVerifyKey pvkBatch = generate_proof_batch_mask(
      values, masks, masked_values, 2
   );
   printf("Batch proof size: %ld, Batch verify key size: %ld\n", strlen(pvkBatch.proof), strlen(pvkBatch.vk));
   printf("Verify result: %d\n", verify_proof_batch_mask(masked_values, 2, pvkBatch.proof, pvkBatch.vk));
   return 0;
}