package tests

import (
	"crypto/sha512"
	cryptography "cryptography/cryptography/hashing"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSha384(t *testing.T) {
	tests := []struct {
		name  string
		input string
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
			h := sha512.Sum384([]byte(tt.input))
			hexString := hex.EncodeToString(h[:])

			hash := cryptography.NewSha384()
			data := []byte(tt.input)
			res := hash.Compute(data)
			resFormat := fmt.Sprintf("%x", res)

			if resFormat != hexString {
				t.Errorf("Test_Sha384: %s", tt.name)
			}
		})
	}
}
