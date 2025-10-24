package cryptography

var _ BlockMode = (*CbcBlockMode)(nil)

type CbcBlockMode struct {
	iv []byte
}

func NewCbcBlockMode(iv []byte) *CbcBlockMode {
	return &CbcBlockMode{iv: iv}
}

func (mode *CbcBlockMode) Encrypt(bytes []byte, transformer func([]byte) []byte) []byte {
	for i := range bytes {
		bytes[i] ^= mode.iv[i]
	}
	transformed := transformer(bytes)
	mode.iv = transformed
	return transformed
}

func (mode *CbcBlockMode) Decrypt(bytes []byte, transformer func([]byte) []byte) []byte {
	transformed := transformer(bytes)
	for i := range transformed {
		transformed[i] ^= mode.iv[i]
	}
	mode.iv = bytes
	return transformed
}
