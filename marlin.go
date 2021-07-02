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
	fmt.Printf("Proof size: %v\nVerify key size: %v\n", proofAndKey.proof_size, proofAndKey.verify_key_size)
	proof, vk := C.CString(C.GoString(proofAndKey.proof)), C.CString(C.GoString(proofAndKey.verify_key))
	C.free_proof_and_verify(proofAndKey.proof, proofAndKey.verify_key)
	fmt.Printf("%v\n%v\n", proof, vk)
	fmt.Printf("verify result: %v\n", C.verify_proof(25, 175, proof, vk))
	fmt.Printf("verify result: %v\n", C.verify_proof(23, 175, proof, vk))
	fmt.Printf("verify result: %v\n", C.verify_proof(25, 174, proof, vk))
	fmt.Printf("verify result: %v\n", C.verify_proof(22, 170, proof, vk))
}
