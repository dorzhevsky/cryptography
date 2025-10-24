package cryptography

type StreamCipher struct {
	Stream
}

func NewStreamCipher(stream Stream) *StreamCipher {
	return &StreamCipher{Stream: stream}
}

func (cipher *StreamCipher) Encrypt(bytes []byte) []byte {
	stream := cipher.GetBytes(len(bytes))
	res := make([]byte, len(bytes))
	for i := range bytes {
		res[i] = bytes[i] ^ stream[i]
	}
	return res
}

func (cipher *StreamCipher) Decrypt(bytes []byte) []byte {
	return cipher.Encrypt(bytes)
}
