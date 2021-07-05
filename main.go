package main

import (
	"fmt"

	"github.com/wang12d/GoMarlin/marlin"
)

func main() {
	proof, vk := marlin.GenerateProofAndVerifyKey(0, 25, 100)
	fmt.Printf("verify result: %v\n", marlin.Verify(proof, vk, 25, 175))
	fmt.Printf("verify result: %v\n", marlin.Verify(proof, vk, 23, 175))
	fmt.Printf("verify result: %v\n", marlin.Verify(proof, vk, 25, 174))
	fmt.Printf("verify result: %v\n", marlin.Verify(proof, vk, 22, 170))
}
