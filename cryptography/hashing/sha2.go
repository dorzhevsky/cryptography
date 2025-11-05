package cryptography

import (
	"encoding/binary"
	"unsafe"
)

type sha2[T uint32 | uint64] struct {
	initialHash      []T
	blockSizeInBytes int
	constants        []T
	rounds           int
	impl             sha2Impl[T]
	size             int
}

func (hash *sha2[T]) Compute(data []byte) []byte {
	source := hash.pad(data)
	hashValue := append(make([]T, 0), hash.initialHash...)
	hash.computeHash(source, hashValue)
	return hash.uintArrayToByteArray(hashValue)
}

func newSha2[T uint32 | uint64]() *sha2[T] {
	var zero T
	size := (int)(unsafe.Sizeof(zero))
	return &sha2[T]{size: size}
}

func (hash *sha2[T]) computeHash(source []byte, hashValue []T) {
	for i := 0; i < len(source); i += hash.blockSizeInBytes {
		chunk := source[i : i+hash.blockSizeInBytes]
		w := hash.createSchedule(chunk)
		a, b, c, d, e, f, g, h := hashValue[0], hashValue[1], hashValue[2], hashValue[3], hashValue[4], hashValue[5], hashValue[6], hashValue[7]
		for j := range w {
			s0 := hash.impl.Sigma0(a)
			s1 := hash.impl.Sigma1(e)
			ch := hash.impl.Ch(e, f, g)
			maj := hash.impl.Maj(a, b, c)
			t1 := h + s1 + ch + hash.constants[j] + w[j]
			t2 := s0 + maj
			h = g
			g = f
			f = e
			e = d + t1
			d = c
			c = b
			b = a
			a = t1 + t2
		}
		z := []T{a, b, c, d, e, f, g, h}
		for i := range hashValue {
			hashValue[i] += z[i]
		}
	}
}

func (hash *sha2[T]) uintArrayToByteArray(a []T) []byte {
	size := hash.size
	res := make([]byte, len(a)*size)
	for i, val := range a {
		for j := 0; j < size; j++ {
			v := val >> ((size-1)*8 - (j * 8)) & 0xFF
			res[i*size+j] = byte(v)
		}
	}
	return res
}

func (hash *sha2[T]) pad(data []byte) []byte {
	res := append(make([]byte, 0), data...)
	res = append(res, 0x01<<7)
	dataLengthSize := hash.blockSizeInBytes >> 3
	zeroPaddingSize := hash.blockSizeInBytes - ((len(data) + dataLengthSize + 1) % hash.blockSizeInBytes)
	if zeroPaddingSize != hash.blockSizeInBytes {
		res = append(res, make([]byte, zeroPaddingSize)...)
	}
	res = append(res, make([]byte, dataLengthSize-8)...)
	res = append(res, (hash.uint64ToBytes((uint64)(len(data) * 8)))...)
	return res
}

func (hash *sha2[T]) uint64ToBytes(value uint64) []byte {
	res := make([]byte, 8)
	binary.BigEndian.PutUint64(res, value)
	return res
}

func (hash *sha2[T]) createSchedule(chunk []byte) []T {
	schedule := make([]T, 0)
	size := hash.size
	for i := 0; i < len(chunk); i += size {
		c := chunk[i : i+size]
		var v T = 0
		for j := 0; j < size; j++ {
			v |= T(c[j]) << ((size-1)*8 - (j * 8))
		}
		schedule = append(schedule, v)
	}
	for len(schedule) < hash.rounds {
		i := len(schedule)
		val := hash.impl.S1(schedule[i-2]) + schedule[i-7] + hash.impl.S0(schedule[i-15]) + schedule[i-16]
		schedule = append(schedule, val)
	}
	return schedule
}
