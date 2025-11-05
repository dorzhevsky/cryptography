package tests

import (
	"crypto/sha256"
	cryptography "cryptography/cryptography/hashing"
	"encoding/hex"
	"testing"
)

func Test_Sha256(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{
			name:  "short input",
			input: "hello world",
		},
		{
			name:  "long input",
			input: "hello world hello world hello world hello world hello world eryrey sfsdfds wrwehrej sgsgshsdfh sdgsdgsd sagfsg1234567 d dgdg retg",
		},
	}

	for _, tc := range testCases {
		h := sha256.Sum256([]byte(tc.input))
		hexString := hex.EncodeToString(h[:])

		hash := cryptography.NewSha256()
		data := []byte(tc.input)
		res := hash.Compute(data)
		resFormat := hex.EncodeToString(res)

		if resFormat != hexString {
			t.Errorf("%s: hash mismatch", tc.name)
		}
	}
}
