package cryptography

import (
	"encoding/binary"
)

var (
	sha256Constants = []uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	}

	block_size_in_bytes = 64
	schedule_size       = 64
)

type Sha256 struct {
	initialHash []uint32
}

func NewSha256() *Sha256 {
	return &Sha256{
		initialHash: []uint32{
			0x6a09e667,
			0xbb67ae85,
			0x3c6ef372,
			0xa54ff53a,
			0x510e527f,
			0x9b05688c,
			0x1f83d9ab,
			0x5be0cd19,
		},
	}
}

func (hash *Sha256) Compute(data []byte) []byte {
	source := hash.pad(data)
	hashValue := append(make([]uint32, 0), hash.initialHash...)
	hash.computeHash(source, hashValue)
	return hash.uint32ArrayToByteArray(hashValue)
}

func (hash *Sha256) computeHash(source []byte, hashValue []uint32) {
	for i := 0; i < len(source); i += block_size_in_bytes {
		chunk := source[i : i+block_size_in_bytes]
		w := hash.generateSchedule(chunk)
		a, b, c, d, e, f, g, h := hashValue[0], hashValue[1], hashValue[2], hashValue[3], hashValue[4], hashValue[5], hashValue[6], hashValue[7]
		for j := range w {
			s0 := hash.sigma0(a)
			s1 := hash.sigma1(e)
			ch := hash.ch(e, f, g)
			maj := hash.maj(a, b, c)
			t1 := h + s1 + ch + sha256Constants[j] + w[j]
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
		z := []uint32{a, b, c, d, e, f, g, h}
		for i := range hashValue {
			hashValue[i] += z[i]
		}
	}
}

func (hash *Sha256) uint32ArrayToByteArray(a []uint32) []byte {
	res := make([]byte, len(a)*4)
	for i, val := range a {
		binary.BigEndian.PutUint32(res[i*4:], val)
	}
	return res
}

func (hash *Sha256) pad(data []byte) []byte {
	res := append(make([]byte, 0), data...)
	res = append(res, 0x01<<7)
	res = append(res, make([]byte, block_size_in_bytes-((len(data)+8)%block_size_in_bytes)-1)...)
	res = append(res, (hash.uint64ToBytes((uint64)(len(data) * 8)))...)
	return res
}

func (hash *Sha256) uint64ToBytes(value uint64) []byte {
	res := make([]byte, 8)
	binary.BigEndian.PutUint64(res, value)
	return res
}

func (hash *Sha256) generateSchedule(chunk []byte) []uint32 {
	schedule := make([]uint32, 0)
	for i := 0; i < len(chunk); i += 4 {
		schedule = append(schedule, binary.BigEndian.Uint32(chunk[i:i+4]))
	}
	for len(schedule) < schedule_size {
		i := len(schedule)
		val := hash.s1(schedule[i-2]) + schedule[i-7] + hash.s0(schedule[i-15]) + schedule[i-16]
		schedule = append(schedule, val)
	}
	return schedule
}

func (hash *Sha256) s0(x uint32) uint32 {
	return hash.rotr(x, 7) ^ hash.rotr(x, 18) ^ hash.shr(x, 3)
}

func (hash *Sha256) s1(x uint32) uint32 {
	return hash.rotr(x, 17) ^ hash.rotr(x, 19) ^ hash.shr(x, 10)
}

func (hash *Sha256) rotr(x uint32, n int) uint32 {
	return (x >> n) | (x << (32 - n))
}

func (hash *Sha256) shr(x uint32, n int) uint32 {
	return x >> n
}

func (hash *Sha256) ch(x, y, z uint32) uint32 {
	return (x & y) ^ ((^x) & z)
}

func (hash *Sha256) maj(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

func (hash *Sha256) sigma0(x uint32) uint32 {
	return hash.rotr(x, 2) ^ hash.rotr(x, 13) ^ hash.rotr(x, 22)
}

func (hash *Sha256) sigma1(x uint32) uint32 {
	return hash.rotr(x, 6) ^ hash.rotr(x, 11) ^ hash.rotr(x, 25)
}
