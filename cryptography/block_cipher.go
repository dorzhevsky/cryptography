package cryptography

type BlockCipher struct {
	encrypt func([]byte) []byte
	decrypt func([]byte) []byte
	size    func() int
}

func (blockCipher *BlockCipher) CreateEncryptor() BlockTransformer {
	return NewDefaultBlockTransformer(blockCipher.encrypt)
}

func (blockCipher *BlockCipher) CreateDecryptor() BlockTransformer {
	return NewDefaultBlockTransformer(blockCipher.decrypt)
}

func (blockCipher *BlockCipher) Encrypt(bytes []byte, mode BlockMode, padding Padding) []byte {

	sourceData := padding.Pad(bytes, blockCipher.size())

	var i = 0
	var result = []byte{}
	length := len(sourceData)

	for i < length {
		start := i
		end := i + blockCipher.size()
		chunk := sourceData[start:end]
		encrypted := mode.Encrypt(chunk, blockCipher.encrypt)
		result = append(result, encrypted...)
		i += blockCipher.size()
	}

	return result
}

func (blockCipher *BlockCipher) Decrypt(bytes []byte, mode BlockMode, padding Padding) []byte {

	length := len(bytes)

	var i = 0

	var data = []byte{}

	for i < length {
		start := i
		end := i + blockCipher.size()
		chunk := bytes[start:end]
		decrypted := mode.Decrypt(chunk, blockCipher.decrypt)
		data = append(data, decrypted...)
		i += blockCipher.size()
	}

	return padding.Unpad(data, blockCipher.size())
}
