package cryptography

var _ BlockMode = (*EcbBlockMode)(nil)

type EcbBlockMode struct{}

func (mode *EcbBlockMode) Encrypt(bytes []byte, transformer func([]byte) []byte) []byte {
	return transformer(bytes)
}

func (mode *EcbBlockMode) Decrypt(bytes []byte, transformer func([]byte) []byte) []byte {
	return transformer(bytes)
}
