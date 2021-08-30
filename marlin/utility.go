package marlin

// #cgo LDFLAGS: -lmarlin_zsk -L${SRCDIR}/../lib
// #include <stdbool.h>
// #include <stdlib.h>
// #include "./../lib/marlin_zsk.h"
import "C"
import (
	"encoding/hex"
	"log"
)

func extractProofAndVerifyKey(proofAndVerifyKey C.ProofAndVerifyKey) (proof Proof, verifyKey VerifyKey) {
	defer C.free_proof_and_verify(proofAndVerifyKey.proof, proofAndVerifyKey.vk)
	encodedProof, encodedVerifyKey := C.GoString(proofAndVerifyKey.proof), C.GoString(proofAndVerifyKey.vk)
	var err error
	if proof, err = hex.DecodeString(encodedProof); err != nil {
		log.Fatalf("Hex decode proof error: %v\n", err)
	}
	if verifyKey, err = hex.DecodeString(encodedVerifyKey); err != nil {
		log.Fatalf("Hex decode verify key error: %v\n", err)
	}
	return proof, verifyKey
}
