package tests

import (
	cryptography "cryptography/cryptography/hashing"
	"encoding/hex"
	"testing"
)

func TestBlake2s(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"hello world", "9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b"},
		{"hello world hello world hello world hello world hello world12479ih jjlaqazc erwre wrewrt sfetr tertret were12701 26fe",
			"1299b189fc48e0fa4545db81278b2b4e03d6feeb013e76d9259e1c4e772e1911"},
	}

	for _, tc := range testCases {
		hash := cryptography.NewBlake2s()
		result := hash.Compute([]byte(tc.input))
		r := hex.EncodeToString(result)
		if r != tc.expected {
			t.Errorf("Blake2s(%q) = %x, expected %x", tc.input, r, tc.expected)
		}
	}
}

// func TestIncapsulationBlake2s(t *testing.T) {
// 	h := cryptography.Blake2s{}
// 	h.Compute([]byte{1})
// }
