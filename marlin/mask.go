package marlin

// #cgo LDFLAGS: -lmarlin_zsk -L${SRCDIR}/../lib
// #include <stdbool.h>
// #include <stdlib.h>
// #include "./../lib/marlin_zsk.h"
import "C"
import "encoding/hex"

// GenerateProofMaskBatch given values, masks and masked_values slice
// generating the marlin zero knowledge proof of each data types of
// the constraint values[i] + masks[i] == masked_values[i].
func GenerateProofBatckMask(values []uint64, masks []uint64,
	maskedValues []uint64) (proof Proof, verifyKey VerifyKey) {
	numberOfElements := len(values)
	cvalues, cmasks, cmaskedValues := make([]C.ulonglong, numberOfElements), make([]C.ulonglong, numberOfElements), make([]C.ulonglong, numberOfElements)
	for i := 0; i < numberOfElements; i++ {
		cvalues[i] = C.ulonglong(values[i])
		cmasks[i] = C.ulonglong(masks[i])
		cmaskedValues[i] = C.ulonglong(maskedValues[i])
	}
	proofAndVerifyKey := C.generate_proof_batch_mask(&cvalues[0],
		&cmasks[0], &cmaskedValues[0], C.ulonglong(numberOfElements))

	return extractProofAndVerifyKey(proofAndVerifyKey)
}

// VerifyProofBatchMask verifies the zero knowledge proof using given inputValues verify key,
// return true if successed otherwise false.
func VerifyProofBatchMask(inputValues []uint64, proof Proof, verifyKey VerifyKey) bool {
	numberOfElements := len(inputValues)
	cinputValues := make([]C.ulonglong, numberOfElements)
	for i := 0; i < numberOfElements; i++ {
		cinputValues[i] = C.ulonglong(inputValues[i])
	}
	hexProof := C.CString(hex.EncodeToString(proof))
	hexVK := C.CString(hex.EncodeToString(verifyKey))
	return bool(C.verify_proof_batch_mask(&cinputValues[0], C.ulonglong(numberOfElements), hexProof, hexVK))
}
