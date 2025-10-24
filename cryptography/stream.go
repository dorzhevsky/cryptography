package cryptography

type Stream interface {
	GetBytes(len int) []byte
}
