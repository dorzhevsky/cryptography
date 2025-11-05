package tests

import (
	cryptography "cryptography/cryptography/hashing"
	"fmt"
	"testing"
)

func Test_Sha224(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "short input",
			input:    "hello world",
			expected: "2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b",
		},
		{
			name:     "long input",
			input:    "hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world",
			expected: "117202106148bac75bd2beb92736a72fd687f808aebdac289fe6ead4",
		},
	}

	for _, tc := range testCases {
		hash := cryptography.NewSha224()
		data := []byte(tc.input)
		res := hash.Compute(data)
		resFormat := fmt.Sprintf("%x", res)
		if resFormat != tc.expected {
			t.Errorf("%s: hash mismatch", tc.name)
		}
	}
}
