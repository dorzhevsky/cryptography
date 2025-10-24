package cryptography

type BlockTransformer interface {
	Transform(bytes []byte) []byte
}
