package tests

import (
	"cryptography/cryptography"
	"testing"
)

func Test_Trivium(t *testing.T) {
	key := []byte{
		0b11111010,
		0b10100111,
		0b01010100,
		0b00000001,
		0b10101110,
		0b01011011,
		0b00001000,
		0b10110101,
		0b01100010,
		0b00001111,
	}

	iv := []byte{
		0b11000111,
		0b01100000,
		0b11111001,
		0b10010010,
		0b00101011,
		0b11000100,
		0b01011101,
		0b11110110,
		0b10001111,
		0b00101000,
	}
	encryptor_generator := cryptography.NewTriviumStream(key, iv)

	encryptor := cryptography.NewStreamCipher(encryptor_generator)

	encrypted := encryptor.Encrypt(([]byte)("123456"))

	decryptor_generator := cryptography.NewTriviumStream(key, iv)

	decryptor := cryptography.NewStreamCipher(decryptor_generator)

	decrypted := (string)(decryptor.Decrypt(encrypted))

	if decrypted != "123456" {
		t.Errorf("Test_Trivium")

	}
}
