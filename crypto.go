package cryptoEx

import (
	"crypto/cipher"
)

type (
	standardType uint8
	modeType     uint8
	paddingType  uint8
	formatType   uint8
)

var (
	StandardType = struct {
		AES standardType
		DES standardType
	}{
		AES: 1,
		DES: 2,
	}
	ModeType = struct {
		ECB modeType
		CBC modeType
		CTR modeType
		OFB modeType
		CFB modeType
	}{
		ECB: 1,
		CBC: 2,
		CTR: 3,
		OFB: 4,
		CFB: 5,
	}
	PaddingType = struct {
		PKCS5 paddingType
		ZERO  paddingType
	}{
		PKCS5: 1,
		ZERO:  2,
	}
	FormatType = struct {
		BASE64 formatType
		HEX    formatType
	}{
		BASE64: 1,
		HEX:    2,
	}
)

type Crypto interface {
	Encrypt(src, key, vector []byte) (string, error)
	Decrypt(src, key, vector []byte) (string, error)
}

type cryptoMode interface {
	Encrypt(block cipher.Block, data, key, vector []byte) ([]byte, error)
	Decrypt(block cipher.Block, data, key, vector []byte) ([]byte, error)
}

type cryptoPadding interface {
	Padding(ciphertext []byte, blockSize int) []byte
	UnPadding(origData []byte) []byte
}

type cryptoFormat interface {
	Encode(ciphertext []byte) string
	Decode(ciphertext string) ([]byte, error)
}

func NewCrypto(s standardType, m modeType, p paddingType, f formatType) (cryptoer Crypto) {
	mode := getMode(m)
	padding := getPadding(p)
	format := getFormat(f)
	switch s {
	case StandardType.AES:
		cryptoer = &cryptoerByAES{
			mode:    mode,
			padding: padding,
			format:  format,
		}
	case StandardType.DES:
		cryptoer = &cryptoerByDES{
			mode:    mode,
			padding: padding,
			format:  format,
		}
	}
	return
}
