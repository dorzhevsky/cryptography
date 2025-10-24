package cryptography

var BlockModes = struct {
	Ecb func() BlockMode
	Cbc func(iv []byte) BlockMode
}{
	Ecb: func() BlockMode {
		return &EcbBlockMode{}
	},
	Cbc: func(iv []byte) BlockMode {
		return NewCbcBlockMode(iv)
	},
}
