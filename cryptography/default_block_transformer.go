package cryptography

var _ BlockTransformer = (*DefaultBlockTransformer)(nil)

type DefaultBlockTransformer struct {
	f func([]byte) []byte
}

func NewDefaultBlockTransformer(f func([]byte) []byte) BlockTransformer {
	return &DefaultBlockTransformer{f}
}

func (t *DefaultBlockTransformer) Transform(bytes []byte) []byte {
	return t.f(bytes)
}
