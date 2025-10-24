package cryptography

type BlockMode interface {
	Encrypt(bytes []byte, transformer func([]byte) []byte) []byte
	Decrypt(bytes []byte, transformer func([]byte) []byte) []byte
}
