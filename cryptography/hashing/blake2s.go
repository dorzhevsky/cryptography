package cryptography

type blake2s struct {
	blake2[uint32]
}

var _ Hash = (*blake2s)(nil)

func NewBlake2s() Hash {
	b := newBlake2[uint32]()
	b.blockSize = 64
	b.rounds = 10
	b.rotations = [4]int{16, 12, 8, 7}
	b.iv = []uint32{
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19,
	}
	return &blake2s{blake2: *b}
}
