package tests

import (
	"crypto/sha512"
	cryptography "cryptography/cryptography/hashing"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSha512(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
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

	for _, tc := range testCases {
		input := tc.input
		h := sha512.Sum512([]byte(input))
		hexString := hex.EncodeToString(h[:])

		hash := cryptography.NewSha512()
		data := []byte(input)
		res := hash.Compute(data)

		resFormat := fmt.Sprintf("%x", res)
		if resFormat != hexString {
			t.Errorf("%s: %s", tc.name, "hash mismatch")
		}
	}
}
