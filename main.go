package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/wang12d/GoMarlin/marlin"
)

type DummyReader struct {
}

func (dr *DummyReader) Read(p []byte) (n int, err error) {
	n = copy(p, make([]byte, len(p)))
	return n, err
}

func main() {
	proof, vk := marlin.EChainGenerateProofAndVerifyKey(0, 25, 100)
	fmt.Printf("verify result: %v\n", marlin.EChainVerify(proof, vk, marlin.EvaluationResults{175, 25}))
	fmt.Printf("verify result: %v\n", marlin.EChainVerify(proof, vk, marlin.EvaluationResults{175, 23}))
	fmt.Printf("verify result: %v\n", marlin.EChainVerify(proof, vk, marlin.EvaluationResults{174, 25}))
	fmt.Printf("verify result: %v\n", marlin.EChainVerify(proof, vk, marlin.EvaluationResults{170, 22}))

	/************************************************************
	        Zebralacner Rewarding Verification
	************************************************************/
	data := [][]byte{[]byte("hello")}
	dataSize := 2048
	privateKey, _ := rsa.GenerateKey(rand.Reader, dataSize)
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)

	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)

	encryptedData, _ := rsa.EncryptOAEP(sha512.New(), &DummyReader{}, &privateKey.PublicKey, data[0], nil)
	proof, vk = marlin.GenerateEncryptionZKProofAndVerifyKey(0, 25, []uint{100}, publicKeyPem, privateKeyPem, [][]byte{encryptedData}, data, uint(dataSize))

	fmt.Printf("Rewarding verify result: %v\n", marlin.VerifyEncryptionZKProof([]marlin.EvaluationResults{{175, 25}}, [][]byte{encryptedData}, proof, vk))

	values := []uint64{24, 25, 26, 27, 29}
	masks := []uint64{50, 100, 23, 42, 42}
	maskedValues := []uint64{74, 125, 49, 69, 71}

	proof, vk = marlin.GenerateProofBatckMask(values, masks, maskedValues)

	fmt.Printf("Verify batch result: %v\n", marlin.VerifyProofBatchMask(maskedValues, proof, vk))
}
