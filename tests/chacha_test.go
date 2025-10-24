package tests

import (
	"cryptography/cryptography"
	"fmt"
	"testing"
)

func Test_ChaCha(t *testing.T) {
	stream := cryptography.NewChaChaStream(([]byte)("123456789_123456789_123456789_12"), ([]byte)("123456781234"))
	encryptor := cryptography.NewStreamCipher(stream)

	encrypted1 := encryptor.Encrypt(([]byte)("123456789_123456789_123456789_123456789_123456789_123456789_"))
	encrypted2 := encryptor.Encrypt(([]byte)("123456789_"))
	r := append(encrypted1, encrypted2...)
	encryptedFormat := fmt.Sprintf("%x", r)
	if encryptedFormat != "d7858eaf1223736affeddb820798f02c7bfc3b040db733254c0ad232aeceae0c6bedc69c6791801b407257fa1bcb5dccdedcbd8484cf420da67657e5c3d6efce2b0939e87ca5" {
		t.Errorf("Test_ChaCha")
	}

	stream = cryptography.NewChaChaStream(([]byte)("123456789_123456789_123456789_12"), ([]byte)("123456781234"))
	decryptor := cryptography.NewStreamCipher(stream)

	decrypted := decryptor.Decrypt(r)
	decryptedString := (string)(decrypted)
	if decryptedString != "123456789_123456789_123456789_123456789_123456789_123456789_123456789_" {
		t.Errorf("Test_ChaCha")
	}
}
