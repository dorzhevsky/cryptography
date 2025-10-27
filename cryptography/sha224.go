package cryptography

type Sha224 struct {
	Sha256
}

func NewSha224() *Sha224 {
	return &Sha224{Sha256{
		initialHash: []uint32{
			0xC1059ED8,
			0x367CD507,
			0x3070DD17,
			0xF70E5939,
			0xFFC00B31,
			0x68581511,
			0x64F98FA7,
			0xBEFA4FA4,
		},
	}}
}

func (sha224 *Sha224) Compute(data []byte) []byte {
	hash := sha224.Sha256.Compute(data)
	return hash[:28]
}
