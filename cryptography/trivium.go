package cryptography

import (
	"cryptography/cryptography/utils"
)

var _ Stream = (*TriviumStream)(nil)

type TriviumStream struct {
	key            []byte
	iv             []byte
	shift_register [3]*utils.BitArray
	sizes          [3]int
}

func NewTriviumStream(key []byte, iv []byte) *TriviumStream {
	stream := TriviumStream{}
	stream.key = key
	stream.iv = iv
	stream.shift_register = [3]*utils.BitArray{utils.NewBitArray(93), utils.NewBitArray(84), utils.NewBitArray(111)}
	stream.sizes = [3]int{93, 84, 111}

	stream.warmUp()
	return &stream
}

func (stream *TriviumStream) warmUp() {

	for i := range stream.key {
		stream.shift_register[0].SetByte(stream.key[i], i)
	}

	for i := range stream.iv {
		stream.shift_register[1].SetByte(stream.iv[i], i)
	}

	stream.shift_register[2].SetBit(108, true)
	stream.shift_register[2].SetBit(109, true)
	stream.shift_register[2].SetBit(110, true)

	for i := 0; i < 4*288; i++ {
		stream.next()
	}
}

func (stream *TriviumStream) GetBytes(size int) []byte {
	res := make([]byte, size)

	bits := stream.generate(8 * size)
	for i := range bits {
		if bits[i] == 1 {
			res[i/8] |= 1 << uint(7-i%8)
		}
	}
	return res
}

func (stream *TriviumStream) generate(size int) []byte {

	res := make([]byte, 0)

	for i := 0; i < size; i++ {
		t1 := stream.get(65) ^ stream.get(92)
		t2 := stream.get(161) ^ stream.get(176)
		t3 := stream.get(242) ^ stream.get(287)
		z := t1 ^ t2 ^ t3
		res = append(res, z)

		stream.next()
	}

	return res
}

func (stream *TriviumStream) next() {

	t1 := stream.get(65) ^ (stream.get(90) & stream.get(91)) ^ stream.get(92) ^ stream.get(170)
	t2 := stream.get(161) ^ (stream.get(174) & stream.get(175)) ^ stream.get(176) ^ stream.get(263)
	t3 := stream.get(242) ^ (stream.get(285) & stream.get(286)) ^ stream.get(287) ^ stream.get(68)

	stream.shift_register[0].ShiftRight(1)
	stream.shift_register[0].SetBit(0, (bool)(t3 != 0))

	stream.shift_register[1].ShiftRight(1)
	stream.shift_register[1].SetBit(0, (bool)(t1 != 0))

	stream.shift_register[2].ShiftRight(1)
	stream.shift_register[2].SetBit(0, (bool)(t2 != 0))
}

func boolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func (stream *TriviumStream) get(pos int) byte {
	index, p := stream.getPos(pos)
	return boolToByte(stream.shift_register[index].GetBit(p))
}

func (stream *TriviumStream) getPos(pos int) (int, int) {
	total := 0
	for i, e := range stream.sizes {
		total += e
		if total > pos {
			return i, pos - (total - e)
		}
	}

	return 0, 0
}
