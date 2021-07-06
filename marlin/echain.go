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

const (
	minimumParameters = 2
)

type Proof []byte // The proof generate by marlin

type VerifyKey []byte // The verify key of the proof

// EChainGenerateProofAndVerifyKey generates zsk proof of the data quality evaluation result
// which is out_1 = data - mu - 3*sigmaSquare and out_2 = data - mu + 3*sigmaSquare.
// Others can verify whether the result is correct by using the generated proof and verify key
func EChainGenerateProofAndVerifyKey(mu, sigmaSquare, data uint) (proof Proof, verifyKey VerifyKey) {
	proofAndKey := C.generate_proof_echain(C.uint(mu), C.uint(sigmaSquare), C.uint(data))
	defer C.free_proof_and_verify(proofAndKey.proof, proofAndKey.vk)
	encodedProof, encodedVerifyKey := C.GoString(proofAndKey.proof), C.GoString(proofAndKey.vk)
	var err error
	if proof, err = hex.DecodeString(encodedProof); err != nil {
		log.Fatalf("Hex decode proof error: %v\n", err)
	}
	if verifyKey, err = hex.DecodeString(encodedVerifyKey); err != nil {
		log.Fatalf("Hex decode verify key error: %v\n", err)
	}
	return proof, verifyKey
}

// EChainVerify verify the computed result using proof and verify key along with public
// inputs. The result is true if the result is indeed computed as specified.
func EChainVerify(proof Proof, verifyKey VerifyKey, publicInputs ...uint) bool {
	if len(publicInputs) < minimumParameters {
		println("Requiring at least ", minimumParameters, " parameters!")
		return false
	}
	proofHex, verifyKeyHex := C.CString(hex.EncodeToString(proof)), C.CString(hex.EncodeToString(verifyKey))
	verifyResult := C.verify_proof_echain(C.uint(publicInputs[0]), C.uint(publicInputs[1]), proofHex, verifyKeyHex)
	return bool(verifyResult)
}
