package cryptography

var _ Stream = (*SalsaStream)(nil)

type SalsaStream struct {
	key          [8]uint32
	nonce        [2]uint32
	constant     [4]uint32
	block_number uint64
	key_stream   []byte
}

func NewSalsaStream(key []byte, nonce []byte) *SalsaStream {
	stream := SalsaStream{}
	stream.key = [8]uint32(stream.bytes_to_words(key))
	stream.nonce = [2]uint32(stream.bytes_to_words(nonce))
	stream.constant = [4]uint32(stream.bytes_to_words(([]byte)("expand 32-byte k")))
	return &stream
}

func (that *SalsaStream) GetBytes(size int) []byte {

	for len(that.key_stream) < size {
		stream := that.get_block(that.block_number)
		that.key_stream = append(that.key_stream, stream...)
		that.block_number++
	}

	result_stream := that.key_stream[0:size]
	that.key_stream = that.key_stream[size:]

	return result_stream
}

func (that *SalsaStream) bytes_to_words(bytes []byte) []uint32 {
	res := make([]uint32, 0)
	i := 0
	for i < len(bytes) {
		chunk := bytes[i : i+4]
		var val uint32 = 0
		for j := 0; j < len(chunk); j++ {
			val |= uint32(chunk[j]) << (j * 8)
		}
		i += len(chunk)
		res = append(res, val)
	}

	return res
}

func (that *SalsaStream) get_block(block_number uint64) []byte {
	matrix := []uint32{
		that.constant[0], that.key[0], that.key[1], that.key[2],
		that.key[3], that.constant[1], that.nonce[0], that.nonce[1],
		(uint32)(block_number & 0xFFFFFFFF), uint32(block_number >> 32), that.constant[2], that.key[4],
		that.key[5], that.key[6], that.key[7], that.constant[3],
	}

	c := make([]uint32, len(matrix))
	copy(c, matrix)

	for i := 0; i < 10; i++ {
		that.qr(&matrix[0], &matrix[4], &matrix[8], &matrix[12])
		that.qr(&matrix[5], &matrix[9], &matrix[13], &matrix[1])
		that.qr(&matrix[10], &matrix[14], &matrix[2], &matrix[6])
		that.qr(&matrix[15], &matrix[3], &matrix[7], &matrix[11])
		// Even round
		that.qr(&matrix[0], &matrix[1], &matrix[2], &matrix[3])
		that.qr(&matrix[5], &matrix[6], &matrix[7], &matrix[4])
		that.qr(&matrix[10], &matrix[11], &matrix[8], &matrix[9])
		that.qr(&matrix[15], &matrix[12], &matrix[13], &matrix[14])
	}

	for i := 0; i < len(matrix); i++ {
		matrix[i] = matrix[i] + c[i]
	}

	res := that.bytes_from_words(matrix)

	return res
}

func (that *SalsaStream) bytes_from_words(words []uint32) []byte {
	res := make([]byte, 0)

	for i := 0; i < len(words); i++ {
		val := words[i]
		res = append(res, (byte)((val>>0)&0b11111111))
		res = append(res, (byte)((val>>8)&0b11111111))
		res = append(res, (byte)((val>>16)&0b11111111))
		res = append(res, (byte)((val>>24)&0b11111111))
	}

	return res
}

func (that *SalsaStream) rotl(a uint32, shift uint32) uint32 {
	return (((a) << (shift)) | ((a) >> (32 - (shift))))
}

func (that *SalsaStream) qr(a *uint32, b *uint32, c *uint32, d *uint32) {
	*b ^= that.rotl(*a+*d, 7)
	*c ^= that.rotl(*b+*a, 9)
	*d ^= that.rotl(*c+*b, 13)
	*a ^= that.rotl(*d+*c, 18)
}
