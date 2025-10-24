package cryptography

type Padding interface {
	Pad(data []byte, blockSize int) []byte
	Unpad(data []byte, blockSize int) []byte
}
