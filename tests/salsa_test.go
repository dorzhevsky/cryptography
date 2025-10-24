package tests

import (
	"cryptography/cryptography"
	"fmt"
	"testing"
)

func Test_Salsa(t *testing.T) {
	stream := cryptography.NewSalsaStream(([]byte)("123456789_123456789_123456789_12"), ([]byte)("12345678"))
	encryptor := cryptography.NewStreamCipher(stream)

	encrypted := encryptor.Encrypt(([]byte)("123456789_123456789_123456789_123456789_123456789_123456789_123456789_"))
	encryptedFormat := fmt.Sprintf("%x", encrypted)
	if encryptedFormat != "a9557eef8584b664cd09588f8cd07b5076bd6960bbbdd0a28dcf6b1ee2a54a94e1a3052d5852956fcda65774af3e19a9cd40717312ff40957f7575b510053b385069c99c5a3e" {
		t.Errorf("Test_Salsa")
	}

	stream = cryptography.NewSalsaStream(([]byte)("123456789_123456789_123456789_12"), ([]byte)("12345678"))
	decryptor := cryptography.NewStreamCipher(stream)

	decrypted := decryptor.Decrypt(encrypted)
	decryptedString := (string)(decrypted)
	if decryptedString != "123456789_123456789_123456789_123456789_123456789_123456789_123456789_" {
		t.Errorf("Test_Salsa")
	}
}
