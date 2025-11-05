package cryptography

import "unsafe"

var (
	sigma = [][]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
		{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
		{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
		{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
		{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
		{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
		{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
		{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
		{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	}
)

type blake2[T uint32 | uint64] struct {
	iv        []T
	rounds    int
	rotations [4]int
	blockSize int
	size      int
}

func (hash *blake2[T]) Compute(data []byte) []byte {
	h := append(make([]T, 0), hash.iv...)
	h[0] ^= (T)((0x01010000 | (hash.size * 8)))
	source := data
	var bytesCompressed uint64 = 0
	remainingBytes := len(source)
	for remainingBytes > hash.blockSize {
		chunk := source[:hash.blockSize]
		bytesCompressed += (uint64)(hash.blockSize)
		h = hash.compress(h, chunk, hash.getCounter(bytesCompressed), false)
		source = source[hash.blockSize:]
		remainingBytes -= hash.blockSize
	}

	bytesCompressed += uint64(remainingBytes)
	source = hash.pad(source)
	h = hash.compress(h, source, hash.getCounter(bytesCompressed), true)

	return hash.uintArrayToByteArray(h)
}

func newBlake2[T uint32 | uint64]() *blake2[T] {
	var zero T
	hash := blake2[T]{
		size: (int)(unsafe.Sizeof(zero)),
	}
	return &hash
}

func (hash *blake2[T]) getCounter(counter uint64) [2]T {
	return [2]T{
		(T)(counter),
		(T)(counter >> (8 * hash.size)),
	}
}

func (hash *blake2[T]) pad(data []byte) []byte {
	res := append(make([]byte, 0), data...)
	paddingSize := hash.blockSize - ((len(data)) % hash.blockSize)
	res = append(res, make([]byte, paddingSize)...)
	return res
}

func (hash *blake2[T]) compress(h []T, chunk []byte, bytesCompressed [2]T, f bool) []T {
	v := append(make([]T, 0), h...)
	v = append(v, hash.iv...)
	v[12] ^= bytesCompressed[0]
	v[13] ^= bytesCompressed[1]
	if f {
		v[14] = (T)((uint64)(v[14]) ^ (uint64)(0xffffffffffffffff))
	}

	m := hash.byteArrayToUintArray(chunk)

	for i := 0; i < hash.rounds; i++ {
		s := sigma[i%10]

		hash.mix(&v[0], &v[4], &v[8], &v[12], m[s[0]], m[s[1]])
		hash.mix(&v[1], &v[5], &v[9], &v[13], m[s[2]], m[s[3]])
		hash.mix(&v[2], &v[6], &v[10], &v[14], m[s[4]], m[s[5]])
		hash.mix(&v[3], &v[7], &v[11], &v[15], m[s[6]], m[s[7]])

		hash.mix(&v[0], &v[5], &v[10], &v[15], m[s[8]], m[s[9]])
		hash.mix(&v[1], &v[6], &v[11], &v[12], m[s[10]], m[s[11]])
		hash.mix(&v[2], &v[7], &v[8], &v[13], m[s[12]], m[s[13]])
		hash.mix(&v[3], &v[4], &v[9], &v[14], m[s[14]], m[s[15]])
	}

	res := make([]T, len(h))
	for i := 0; i < len(h); i++ {
		res[i] = h[i] ^ v[i] ^ v[i+8]
	}

	return res
}

func (hash *blake2[T]) mix(va *T, vb *T, vc *T, vd *T, x T, y T) {
	*va = *va + *vb + x
	*vd = hash.rotr(*vd^*va, hash.rotations[0])
	*vc = *vc + *vd
	*vb = hash.rotr((*vb ^ *vc), hash.rotations[1])
	*va = *va + *vb + y
	*vd = hash.rotr((*vd ^ *va), hash.rotations[2])
	*vc = *vc + *vd
	*vb = hash.rotr((*vb ^ *vc), hash.rotations[3])
}

func (hash *blake2[T]) byteArrayToUintArray(chunk []byte) []T {
	uintArray := make([]T, 0)
	for i := 0; i < len(chunk); i += hash.size {
		c := chunk[i : i+hash.size]
		var v T = 0
		for j := 0; j < hash.size; j++ {
			v |= T(c[j]) << (j * 8)
		}
		uintArray = append(uintArray, v)
	}

	return uintArray
}

func (hash *blake2[T]) rotr(x T, n int) T {
	return (x >> n) | (x << (hash.size*8 - n))
}

func (hash *blake2[T]) uintArrayToByteArray(a []T) []byte {
	res := make([]byte, len(a)*hash.size)
	for i, val := range a {
		for j := 0; j < hash.size; j++ {
			v := val >> (j * 8) & 0xFF
			res[i*hash.size+j] = byte(v)
		}
	}
	return res
}
