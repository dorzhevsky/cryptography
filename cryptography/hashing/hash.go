package cryptography

type Hash interface {
	Compute(data []byte) []byte
}
