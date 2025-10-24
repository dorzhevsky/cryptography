package cryptography

var _ Stream = (*ChaChaStream)(nil)

type ChaChaStream struct {
	key      [8]uint32
	nonce    [3]uint32
	constant [4]uint32

	block_number uint32
	key_stream   []byte
}

func NewChaChaStream(key []byte, nonce []byte) *ChaChaStream {
	cipher := ChaChaStream{}
	cipher.key = [8]uint32(cipher.bytes_to_words(key))
	cipher.nonce = [3]uint32(cipher.bytes_to_words(nonce))
	cipher.constant = [4]uint32(cipher.bytes_to_words(([]byte)("expand 32-byte k")))
	return &cipher
}

func (cipher *ChaChaStream) GetBytes(size int) []byte {

	for len(cipher.key_stream) < size {
		stream := cipher.get_block(cipher.block_number)
		cipher.key_stream = append(cipher.key_stream, stream...)
		cipher.block_number++
	}

	result_stream := cipher.key_stream[0:size]
	cipher.key_stream = cipher.key_stream[size:]

	return result_stream
}

func (cipher *ChaChaStream) bytes_to_words(bytes []byte) []uint32 {
	res := make([]uint32, 0)
	i := 0
	for i < len(bytes) {
		chunk := bytes[i : i+4]
		var val uint32 = 0
		for j := 0; j < len(chunk); j++ {
			shift := j * 8
			val |= uint32(chunk[j]) << shift
		}
		i += len(chunk)
		res = append(res, val)
	}

	return res
}

func (cipher *ChaChaStream) get_block(block_number uint32) []byte {
	matrix := []uint32{
		cipher.constant[0], cipher.constant[1], cipher.constant[2], cipher.constant[3],
		cipher.key[0], cipher.key[1], cipher.key[2], cipher.key[3],
		cipher.key[4], cipher.key[5], cipher.key[6], cipher.key[7],
		block_number, cipher.nonce[0], cipher.nonce[1], cipher.nonce[2],
	}

	c := make([]uint32, len(matrix))
	copy(c, matrix)

	for i := 0; i < 10; i++ {
		cipher.qr(&matrix[0], &matrix[4], &matrix[8], &matrix[12])
		cipher.qr(&matrix[1], &matrix[5], &matrix[9], &matrix[13])
		cipher.qr(&matrix[2], &matrix[6], &matrix[10], &matrix[14])
		cipher.qr(&matrix[3], &matrix[7], &matrix[11], &matrix[15])
		// Even round
		cipher.qr(&matrix[0], &matrix[5], &matrix[10], &matrix[15])
		cipher.qr(&matrix[1], &matrix[6], &matrix[11], &matrix[12])
		cipher.qr(&matrix[2], &matrix[7], &matrix[8], &matrix[13])
		cipher.qr(&matrix[3], &matrix[4], &matrix[9], &matrix[14])
	}

	for i := 0; i < len(matrix); i++ {
		matrix[i] = matrix[i] + c[i]
	}

	res := cipher.bytes_from_words(matrix)

	return res
}

func (cipher *ChaChaStream) bytes_from_words(words []uint32) []byte {
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

func (cipher *ChaChaStream) rotl(a uint32, shift uint32) uint32 {
	return (((a) << (shift)) | ((a) >> (32 - (shift))))
}

func (cipher *ChaChaStream) qr(a *uint32, b *uint32, c *uint32, d *uint32) {
	*a = *a + *b
	*d = cipher.rotl(*d^*a, 16)
	*c = *c + *d
	*b = cipher.rotl(*b^*c, 12)
	*a = *a + *b
	*d = cipher.rotl(*d^*a, 8)
	*c = *c + *d
	*b = cipher.rotl(*b^*c, 7)
}
