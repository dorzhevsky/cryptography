package tests

import (
	cryptography "cryptography/cryptography/hashing"
	"encoding/hex"
	"testing"
)

func TestBlake2b(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "short_input",
			input:    "hello world",
			expected: "021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0",
		},
		{
			name:     "long_input",
			input:    "hello world hello world hello world hello world hello world12479ih jjlaqazc erwre wrewrt sfetr tertret were12701 26fe",
			expected: "b132bfc96378c64f6ca8c79afab6f26014a2e6c1cd4cf95c07ba397ad3ff59128264ec4a77b628d8a4082e19bee77e47b4464174b942cd517521f3bd4261ba24",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash := cryptography.NewBlake2b()
			data := []byte(tc.input)
			res := hash.Compute(data)

			resFormat := hex.EncodeToString(res)
			if resFormat != tc.expected {
				t.Errorf("Test failed for input %q: expected %s, got %s", tc.input, tc.expected, resFormat)
			}
		})
	}
}
