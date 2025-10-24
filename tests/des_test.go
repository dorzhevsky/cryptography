package tests

import (
	"cryptography/cryptography"
	"fmt"
	"testing"
)

func Test_DES(t *testing.T) {
	key := ([]byte)("759254678345697456712345")
	iv := ([]byte)("12345678")

	cipher := cryptography.Des(key)

	encrypted := cipher.Encrypt(([]byte)("abcdefghigklmnop"), cryptography.BlockModes.Cbc(iv), cryptography.Paddings.Pkcs())
	encryptedFormat := fmt.Sprintf("%x", encrypted)
	if encryptedFormat != "a5ef3c6d5921c1836f40942460e9c65df4f571e8bc23de7c" {
		t.Errorf("Test_DES")
	}

	decrypted := cipher.Decrypt(encrypted, cryptography.BlockModes.Cbc(iv), cryptography.Paddings.Pkcs())
	decryptedString := (string)(decrypted)
	if decryptedString != "abcdefghigklmnop" {
		t.Errorf("Test_DES")
	}
}
