package utils

var (
	word_size = 8
)

type BitArray struct {
	words      []byte
	length     int
	rem_length int
	size       int
}

func NewBitArray(size int) *BitArray {
	length := 0
	for length*word_size < size {
		length++
	}
	register := BitArray{}
	register.size = size
	register.words = make([]byte, length)
	register.length = length
	register.rem_length = size % word_size
	return &register
}

func (register *BitArray) SetByte(b byte, index int) {
	register.words[index] = b
}

func (register *BitArray) ShiftRight(shift int) {
	if shift == 0 {
		return
	}
	if shift > register.size {
		for i := 0; i < register.length; i++ {
			register.words[i] = 0
		}
	}

	p := shift / word_size
	q := shift % word_size

	if p > 0 {
		for i := p; i < register.length; i++ {
			register.words[i] = register.words[i-p]
			register.words[i-p] = 0
		}
	}

	var carry byte = 0
	for i := p; i < register.length; i++ {
		new_carry := register.words[i] << (word_size - q)
		register.words[i] = register.words[i] >> q
		register.words[i] |= carry
		carry = new_carry
	}

	register.words[register.length-1] &= register.mask()
}

func (register *BitArray) GetBit(pos int) bool {
	p := pos / word_size
	q := pos % word_size
	val := register.words[p]
	return ((byte)(val>>(word_size-q-1)) & 0x1) == 1
}

func (register *BitArray) SetBit(pos int, val bool) {
	p := pos / word_size
	q := pos % word_size
	var v byte = 1 << (word_size - q - 1)
	if val {
		register.words[p] |= v
	} else {
		register.words[p] &= ^v
	}
}

func (register *BitArray) ToBytes() []byte {
	return register.words
}

func (register *BitArray) mask() byte {
	var val byte = 0
	for i := 0; i < word_size-register.rem_length; i++ {
		val = (val << 1) | 1
	}
	return ^val
}
