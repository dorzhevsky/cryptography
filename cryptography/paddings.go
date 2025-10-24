package cryptography

var Paddings = struct {
	Pkcs     func() Padding
	Iso10126 func(val byte) Padding
	AnsiX923 func() Padding
}{
	Pkcs: func() Padding {
		return &defaultPadding{padder: func(l int) byte {
			return byte(l)
		}}
	},
	Iso10126: func(val byte) Padding {
		return &defaultPadding{padder: func(l int) byte {
			return val
		}}
	},
	AnsiX923: func() Padding {
		return &defaultPadding{padder: func(l int) byte {
			return 0
		}}
	},
}
