package tests

import (
	"crypto/sha512"
	cryptography "cryptography/cryptography/hashing"
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_Sha512256(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedHash string
	}{
		{
			name:  "short input",
			input: "hello world",
		},
		{
			name:  "long input",
			input: "hello world hello world hello world hello world hello world12479ih jjlaqazc erwre wrewrt sfetr tertret were12701 26fe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := sha512.Sum512_256([]byte(tt.input))
			hexString := hex.EncodeToString(h[:])

			hash := cryptography.NewSha512_256()
			data := ([]byte)(tt.input)
			res := hash.Compute(data)
			resFormat := fmt.Sprintf("%x", res)

			if resFormat != hexString {
				t.Errorf("Хеши не совпадают для входных данных: %s", tt.input)
			}
		})
	}
}
