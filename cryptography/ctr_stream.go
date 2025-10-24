package cryptography

import (
	"encoding/binary"
)

var _ Stream = (*CtrStream)(nil)

type CtrStream struct {
	iv           []byte
	transformer  BlockTransformer
	block_number uint64
	key_stream   []byte
}

func NewCtrStream(iv []byte, transformer BlockTransformer) *CtrStream {
	cipher := CtrStream{}
	cipher.iv = iv
	cipher.transformer = transformer
	return &cipher
}

func (stream *CtrStream) GetBytes(size int) []byte {

	for len(stream.key_stream) < size {
		block := stream.get_block(stream.block_number)
		stream.key_stream = append(stream.key_stream, block...)
		stream.block_number++
	}

	result := stream.key_stream[0:size]
	stream.key_stream = stream.key_stream[size:]

	return result
}

func (stream *CtrStream) get_block(blockNumber uint64) []byte {
	block := make([]byte, len(stream.iv))
	copy(block, stream.iv)
	binary.BigEndian.PutUint64(block, blockNumber)
	res := stream.transformer.Transform(block)
	return res
}
