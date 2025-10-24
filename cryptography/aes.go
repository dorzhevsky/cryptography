package cryptography

import (
	"cryptography/cryptography/utils"
	"math/bits"
)

var (
	byte_sub_matrix = [8]byte{
		0b11110001,
		0b11100011,
		0b11000111,
		0b10001111,
		0b00011111,
		0b00111110,
		0b01111100,
		0b11111000,
	}

	byte_sub_matrix_inv = []byte{
		0b01010010,
		0b00101001,
		0b10010100,
		0b01001010,
		0b00100101,
		0b10010010,
		0b01001001,
		0b10100100,
	}

	mix_columns_matrix = [4][4]byte{
		{0x02, 0x03, 0x01, 0x01},
		{0x01, 0x02, 0x03, 0x01},
		{0x01, 0x01, 0x02, 0x03},
		{0x03, 0x01, 0x01, 0x02},
	}

	inv_mix_columns_matrix = [4][4]byte{
		{0x0E, 0x0B, 0x0D, 0x09},
		{0x09, 0x0E, 0x0B, 0x0D},
		{0x0D, 0x09, 0x0E, 0x0B},
		{0x0B, 0x0D, 0x09, 0x0E},
	}
	state_size = 4
)

type AESCipher struct {
	BlockCipher
	key   []byte
	keys  [][][]byte
	field *utils.GField
}

func Aes(key []byte) *AESCipher {
	var cipher AESCipher = AESCipher{key: key, field: utils.CreateDefaultGField()}
	cipher.BlockCipher = BlockCipher{encrypt: cipher.encrypt, decrypt: cipher.decrypt, size: cipher.size}
	cipher.expand_key()
	return &cipher
}

func (cipher *AESCipher) encrypt(bytes []byte) []byte {

	state := cipher.bytes_to_matrix(bytes)

	add_round_key(([][]byte)(state), cipher.keys[0])

	for iter := 1; iter <= 9; iter++ {
		cipher.byte_sub_layer(state, cipher.byte_sub)
		cipher.shift_rows_layer(state, shift_rows)
		cipher.mix_columns_layer(state, mix_columns_matrix)
		add_round_key(([][]byte)(state), cipher.keys[iter])
	}

	cipher.byte_sub_layer(state, cipher.byte_sub)
	cipher.shift_rows_layer(state, shift_rows)
	add_round_key(([][]byte)(state), cipher.keys[10])

	res := cipher.matrix_to_bytes(state)

	return res
}

func (cipher *AESCipher) decrypt(bytes []byte) []byte {

	state := cipher.bytes_to_matrix(bytes)

	add_round_key(([][]byte)(state), cipher.keys[10])
	cipher.shift_rows_layer(state, inv_shift_rows)
	cipher.byte_sub_layer(state, cipher.inv_byte_sub)

	for iter := 9; iter >= 1; iter-- {
		add_round_key(([][]byte)(state), cipher.keys[iter])
		cipher.mix_columns_layer(state, inv_mix_columns_matrix)
		cipher.shift_rows_layer(state, inv_shift_rows)
		cipher.byte_sub_layer(state, cipher.inv_byte_sub)
	}

	add_round_key(([][]byte)(state), cipher.keys[0])

	res := cipher.matrix_to_bytes(state)

	return res
}

func (cipher *AESCipher) size() int {
	return 16
}

func (cipher *AESCipher) bytes_to_matrix(bytes []byte) [][]byte {
	state := make([][]byte, state_size)
	for i := 0; i < state_size; i++ {
		state[i] = make([]byte, state_size)
	}
	for i := 0; i < len(bytes); i++ {
		row := i / state_size
		col := i % state_size
		state[row][col] = bytes[i]
	}
	return state
}

func (cipher *AESCipher) matrix_to_bytes(state [][]byte) []byte {
	res := make([]byte, state_size*state_size)
	for i := 0; i < state_size; i++ {
		for j := 0; j < state_size; j++ {
			res[i*state_size+j] = state[i][j]
		}
	}
	return res
}

func (cipher *AESCipher) byte_sub_layer(state [][]byte, byte_sub_func func(byte) byte) {
	for i := 0; i < state_size; i++ {
		for j := 0; j < state_size; j++ {
			state[i][j] = byte_sub_func(state[i][j])
		}
	}
}

func (cipher *AESCipher) shift_rows_layer(state [][]byte, shift_func func([]byte, int) []byte) {
	for i := 0; i < state_size; i++ {
		v := make([]byte, 0)
		for j := 0; j < state_size; j++ {
			v = append(v, state[j][i])
		}
		r := shift_func(v, i)
		for j := 0; j < state_size; j++ {
			state[j][i] = r[j]
		}
	}
}

func (cipher *AESCipher) mix_columns_layer(state [][]byte, matrix [4][4]byte) {
	for i := 0; i < state_size; i++ {
		bytes := state[i]
		result := make([]byte, state_size)
		for i := 0; i < len(matrix); i++ {
			var r byte = 0
			for j := 0; j < len(bytes); j++ {
				r = cipher.field.Add(r, cipher.field.Mul(matrix[i][j], bytes[j]))
			}
			result[i] = r
		}

		state[i] = result
	}
}

func (cipher *AESCipher) expand_key() {
	bytes := cipher.key
	keys := make([]uint32, 0)
	for i := 0; i < len(bytes); i += 4 {
		var t uint32 = 0
		for j := 0; j < 4; j++ {
			var val uint32 = (uint32)(bytes[i+j])
			shift := (4 - j - 1) * 8
			t |= (val << shift)
		}
		keys = append(keys, t)
	}

	var index int = 4
	for index <= 43 {
		var t uint32
		if index%4 == 0 {
			t = keys[index-4] ^ cipher.g(keys[index-1], index/4)
		} else {
			t = keys[index-4] ^ keys[index-1]
		}
		keys = append(keys, t)

		index++
	}

	res := make([][][]byte, 0)

	for i := 0; i < len(keys); i += 4 {
		r := make([][]byte, 0)
		for j := 0; j < 4; j++ {
			var val uint32 = keys[i+j]
			tmp := make([]byte, 0)
			for k := 0; k < 4; k++ {
				b := (byte)((val >> ((4 - k - 1) * 8)) & 0xff)
				tmp = append(tmp, b)
			}
			r = append(r, tmp)
		}
		res = append(res, r)
	}

	cipher.keys = res
}

func (cipher *AESCipher) g(val uint32, round int) uint32 {
	t := val<<8 | (val >> 24)
	var r uint32 = 0
	for i := 0; i < 4; i++ {
		s := byte((t >> (uint32)(8*i)) & 0xff)
		b := cipher.byte_sub(s)
		r |= ((uint32)(b) << (uint32)(8*i))
	}
	p := uint32(cipher.field.Pow(2, round-1))
	res := r ^ (p << 24)
	return res
}

func (cipher *AESCipher) byte_sub(e byte) byte {
	var inverse byte = cipher.field.Inv(e)
	var res byte = 0
	for i := 0; i < len(byte_sub_matrix); i++ {
		mul := byte_sub_matrix[i] & inverse
		sum := bits.OnesCount8(mul) % 2
		res |= ((byte)(sum) << i)
	}
	return res ^ 0b01100011
}

func (cipher *AESCipher) inv_byte_sub(e byte) byte {
	var res byte = 0
	for i := 0; i < len(byte_sub_matrix_inv); i++ {
		mul := byte_sub_matrix_inv[i] & e
		sum := bits.OnesCount8(mul) % 2
		res |= ((byte)(sum) << (8 - i - 1))
	}
	res ^= 0b00000101
	var inverse byte = cipher.field.Inv(res)
	return inverse
}

func add_round_key(state [][]byte, roundKey [][]byte) {
	for i := 0; i < state_size; i++ {
		for j := 0; j < state_size; j++ {
			state[i][j] ^= roundKey[i][j]
		}
	}
}

func shift_rows(bytes []byte, shift int) []byte {
	result := make([]byte, state_size)
	for i := 0; i < len(bytes); i++ {
		result[i] = bytes[(i+shift)%len(bytes)]
	}
	return []byte(result)
}

func inv_shift_rows(bytes []byte, shift int) []byte {
	result := make([]byte, state_size)
	for i := len(bytes) - 1; i >= 0; i-- {
		index := i - shift
		if index < 0 {
			index = len(bytes) + index
		}
		result[i] = bytes[index]
	}
	return result
}
