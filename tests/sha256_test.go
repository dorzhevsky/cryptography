package tests

import (
	"crypto/sha256"
	"cryptography/cryptography"
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_Sha256(t *testing.T) {

	input := "hello world"
	// Вычисляем SHA-256 хеш
	h := sha256.Sum256([]byte(input))

	// Преобразуем байты в hex строку
	hexString := hex.EncodeToString(h[:])

	hash := cryptography.NewSha256()
	data := ([]byte)(input)
	res := hash.Compute(data)

	resFormat := fmt.Sprintf("%x", res)
	if resFormat != "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" {
		t.Errorf("Test_Sha256")
	}

	if hexString != "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" {
		t.Errorf("Test_Sha256")
	}
}

func Test_Sha256_Long(t *testing.T) {

	input := "hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world"
	// Вычисляем SHA-256 хеш
	h := sha256.Sum256([]byte(input))

	// Преобразуем байты в hex строку
	hexString := hex.EncodeToString(h[:])

	hash := cryptography.NewSha256()
	data := ([]byte)(input)
	res := hash.Compute(data)

	resFormat := fmt.Sprintf("%x", res)
	if resFormat != "4b46ee44f837960ce36def8d218db06ebb881297b39469345c8370e82610e96c" {
		t.Errorf("Test_Sha256")
	}

	if hexString != "4b46ee44f837960ce36def8d218db06ebb881297b39469345c8370e82610e96c" {
		t.Errorf("Test_Sha256")
	}
}
