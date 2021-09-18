package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/wang12d/GoMarlin/marlin"
)

func decode(hexString string) []byte {
	var err error
	var res []byte
	if res, err = hex.DecodeString(hexString); err != nil {
		log.Fatalf("Invalid hex string: %v\n", hexString)
	}
	return res
}

type DummyReader struct {
}

func (dr *DummyReader) Read(p []byte) (n int, err error) {
	n = copy(p, make([]byte, len(p)))
	return n, err
}

func main() {
	proof, vk := marlin.EChainGenerateProofAndVerifyKey(0, 25, 100)
	fmt.Printf("verify result: %v\n", marlin.EChainVerify(proof, vk, 25, 175))
	fmt.Printf("verify result: %v\n", marlin.EChainVerify(proof, vk, 23, 175))
	fmt.Printf("verify result: %v\n", marlin.EChainVerify(proof, vk, 25, 174))
	fmt.Printf("verify result: %v\n", marlin.EChainVerify(proof, vk, 22, 170))

	pk := decode("e94647fef85a6d647904a7ae6433dfacb19e7ac610a7bb901c899d63856a1509")
	sk := decode("74892dc16d86e99ba5cdf9262232b67e4b2c7d2d00d302f35c2108be33db4c50e94647fef85a6d647904a7ae6433dfacb19e7ac610a7bb901c899d63856a1509")
	mpk := decode("1246273e32d7e27db7d9e0ef66db7cc4f0e516ed3a2b5cd60c6356061148d81d")
	prefix, msg := decode("68656c6c6f"), decode("20776f726c642e")
	cert := decode("061df370b8ffc39ebb52baf169fe8547b427c22d3e8ced0f52cac09eef5661fe83f6e4399b6542f512ad65e8262b4fe5fe0f1f6682b65da4002be53f7d361a0b")
	t1 := decode("8459cefa18ebe190783b7726bc5512e3c37056220802728bf4336b81b4dea817")
	t2 := decode("deddaf119e6e47a1a0c5824bd540ee8e6b880f1297523225c101eb75a160e2a8")

	proof, vk = marlin.ZebraLancerGenerateProofAndVerifyKey(prefix, msg, sk, pk, cert, mpk, t1, t2)
	fmt.Printf("ZebraLancer verify result: %v\n", marlin.ZebraLancerVerifyProof(t1, t2, proof, vk))
	t1[0] = t1[0] - 1
	fmt.Printf("ZebraLancer verify result: %v\n", marlin.ZebraLancerVerifyProof(t1, t2, proof, vk))
	/************************************************************
	        Zebralacner Rewarding Verification
	************************************************************/
	data := [][]byte{[]byte("hello")}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
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
	proof, vk = marlin.GenerateEncryptionZKProofAndVerifyKey(0, 25, []uint{100}, publicKeyPem, privateKeyPem, [][]byte{encryptedData}, data)

	fmt.Printf("Rewarding verify result: %v\n", marlin.VerifyEncryptionZKProof([]marlin.EvaluationResults{{25, 175}}, [][]byte{encryptedData}, proof, vk))

	values := []uint64{24, 25, 26, 27, 29}
	masks := []uint64{50, 100, 23, 42, 42}
	maskedValues := []uint64{74, 125, 49, 69, 71}

	proof, vk = marlin.GenerateProofBatckMask(values, masks, maskedValues)

	fmt.Printf("Verify batch result: %v\n", marlin.VerifyProofBatchMask(maskedValues, proof, vk))
}
