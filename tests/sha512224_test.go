package tests

import (
	"crypto/sha512"
	cryptography "cryptography/cryptography/hashing"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSha512224(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Short input",
			input: "hello world",
		},
		{
			name:  "Long input",
			input: "hello world hello world hello world hello world hello world12479ih jjlaqazc erwre wrewrt sfetr tertret were12701 26fe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Вычисляем SHA-256 хеш
			h := sha512.Sum512_224([]byte(tt.input))
			hexString := hex.EncodeToString(h[:])

			hash := cryptography.NewSha512_224()
			data := ([]byte)(tt.input)
			res := hash.Compute(data)

			resFormat := fmt.Sprintf("%x", res)
			if resFormat != hexString {
				t.Errorf("Hash mismatch for input: %s", tt.input)
			}
		})
	}
}
