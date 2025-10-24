package tests

import (
	"cryptography/cryptography"
	"fmt"
	"testing"
)

func Test_Aes(t *testing.T) {
	key := ([]byte)("1234567891234567")
	iv := ([]byte)("1111111111222222")

	cipher := cryptography.Aes(key)

	encrypted := cipher.Encrypt(([]byte)("abcdefghigklmnop"), cryptography.BlockModes.Cbc(iv), cryptography.Paddings.Pkcs())
	encryptedFormat := fmt.Sprintf("%x", encrypted)
	if encryptedFormat != "0692dd4cd0c07887ee5386668686efb7e38040ae047ad6f5c04a327de5dc1be1" {
		t.Errorf("Test_Aes")
	}

	decrypted := cipher.Decrypt(encrypted, cryptography.BlockModes.Cbc(iv), cryptography.Paddings.Pkcs())
	decryptedString := (string)(decrypted)
	if decryptedString != "abcdefghigklmnop" {
		t.Errorf("Test_Aes")
	}
}
