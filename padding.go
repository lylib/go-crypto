package cryptoEx

import (
	"bytes"
)

type paddingByPKCS5 struct {
}

type paddingByZero struct {
}

func (this *paddingByPKCS5) Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func (this *paddingByPKCS5) UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func (this *paddingByZero) Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func (this *paddingByZero) UnPadding(origData []byte) []byte {
	return bytes.TrimFunc(origData,
		func(r rune) bool {
			return r == rune(0)
		})
}

func getPadding(p paddingType) (padding cryptoPadding) {
	switch p {
	case PaddingType.PKCS5:
		padding = &paddingByPKCS5{}
	case PaddingType.ZERO:
		padding = &paddingByZero{}
	}
	return
}
