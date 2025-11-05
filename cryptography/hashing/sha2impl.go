package cryptography

type sha2Impl[T uint32 | uint64] interface {
	S0(x T) T
	S1(x T) T
	Ch(x, y, z T) T
	Maj(x, y, z T) T
	Sigma0(x T) T
	Sigma1(x T) T
}
