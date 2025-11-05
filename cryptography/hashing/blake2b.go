package cryptography

type blake2b struct {
	blake2[uint64]
}

var _ Hash = (*blake2b)(nil)

func NewBlake2b() Hash {
	b := newBlake2[uint64]()
	b.blockSize = 128
	b.rounds = 12
	b.rotations = [4]int{32, 24, 16, 63}
	b.iv = []uint64{
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
	}
	return &blake2b{blake2: *b}
}
