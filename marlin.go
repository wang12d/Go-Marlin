package main

// #cgo LDFLAGS: -lmarlin_zsk -L${SRCDIR}/lib
// #include <stdbool.h>
// #include <stdlib.h>
// #include "./lib/marlin_zsk.h"
// unsigned char to_uchar(unsigned char* ptr, unsigned char move) {
//	return *(ptr + move);
// }
import "C"
import "fmt"

func main() {
	proofAndKey := C.generate_proof(0, 25, 100)
	fmt.Printf("First value: %v\n", *proofAndKey.proof)
	fmt.Printf("Proof size: %v\nVerify key size: %v\n", proofAndKey.proof_size, proofAndKey.verify_key_size)
	fmt.Printf("verify result: %v\n", C.verify_proof(25, 175, proofAndKey))
}
