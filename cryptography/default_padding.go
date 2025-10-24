package cryptography

var _ Padding = (*defaultPadding)(nil)

type defaultPadding struct {
	padder func(int) byte
}

func (p *defaultPadding) Pad(data []byte, blockSize int) []byte {
	paddingLength := blockSize - len(data)%blockSize
	pad := make([]byte, paddingLength)
	val := p.padder(paddingLength)
	for i := range pad {
		pad[i] = val
	}
	pad[paddingLength-1] = byte(paddingLength)
	return append(data, pad...)
}

func (p *defaultPadding) Unpad(data []byte, blockSize int) []byte {
	padLength := data[len(data)-1]
	return data[:len(data)-int(padLength)]
}
