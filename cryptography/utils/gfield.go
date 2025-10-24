package utils

type GField struct {
	mod uint16
}

func CreateGField(mod uint16) *GField {
	var field = GField{mod: mod}
	return &field
}

func CreateDefaultGField() *GField {
	var field = GField{mod: 0x11B}
	return &field
}

func (field *GField) Add(a, b byte) byte {
	return a ^ b
}

func (field *GField) Sub(a, b byte) byte {
	return a ^ b
}

func (field *GField) Mul(a, b byte) byte {
	var r uint8 = 0
	for i := 0; i < 8; i++ {
		var mask byte = 1 << i
		if (b & mask) != 0 {
			var s uint16 = (uint16)(a)
			for j := 0; j < i; j++ {
				s <<= 1
				if s&0x100 > 0 {
					s ^= 0x11B
				}
			}
			r ^= (byte)(s)
		}
	}

	return r
}

func (field *GField) Inv(a byte) byte {
	if a == 0 {
		return 0
	}
	if a == 1 {
		return 1
	}
	p := a
	t := a
	for t != 0x1 {
		p = t
		t = field.Mul(t, a)
	}

	return p
}

func (field *GField) Pow(a byte, p int) byte {
	if p == 0 {
		return 0x01
	}
	var t uint8 = 1
	for i := 1; i <= p; i++ {
		t = field.Mul(t, a)
	}

	return t
}
