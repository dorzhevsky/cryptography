package tests

import (
	"cryptography/cryptography"
	"fmt"
	"testing"
)

func Test_Sha224(t *testing.T) {

	input := "hello world"

	hash := cryptography.NewSha224()
	data := ([]byte)(input)
	res := hash.Compute(data)

	resFormat := fmt.Sprintf("%x", res)
	if resFormat != "2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b" {
		t.Errorf("Test_Sha224")
	}
}

func Test_Sha224_Long(t *testing.T) {

	input := "hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world"

	hash := cryptography.NewSha224()
	data := ([]byte)(input)
	res := hash.Compute(data)

	resFormat := fmt.Sprintf("%x", res)
	if resFormat != "117202106148bac75bd2beb92736a72fd687f808aebdac289fe6ead4" {
		t.Errorf("Test_Sha224_Long")
	}
}
