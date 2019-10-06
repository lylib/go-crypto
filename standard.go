package cryptoEx

import (
	"crypto/aes"
	"crypto/des"
)

type cryptoerByAES struct {
	mode    cryptoMode
	padding cryptoPadding
	format  cryptoFormat
}

type cryptoerByDES struct {
	mode    cryptoMode
	padding cryptoPadding
	format  cryptoFormat
}

func (this *cryptoerByAES) Encrypt(src, key, vector []byte) (string, error) {
	// standard
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// padding
	src = this.padding.Padding(src, block.BlockSize())
	// mode
	ciphertext, err := this.mode.Encrypt(block, src, key, vector)
	if err != nil {
		return "", err
	}
	// format
	return this.format.Encode(ciphertext), nil
}

func (this *cryptoerByAES) Decrypt(src, key, vector []byte) (string, error) {
	// format
	data, err := this.format.Decode(string(src))
	if err != nil {
		return "", err
	}
	// standard
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// mode
	plaintext, err := this.mode.Decrypt(block, data, key, vector)
	if err != nil {
		return "", err
	}
	// padding
	return string(this.padding.UnPadding(plaintext)), nil
}

func (this *cryptoerByDES) Encrypt(src, key, vector []byte) (string, error) {
	// standard
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}
	// padding
	src = this.padding.Padding(src, block.BlockSize())
	// mode
	ciphertext, err := this.mode.Encrypt(block, src, key, vector)
	if err != nil {
		return "", err
	}
	// format
	return this.format.Encode(ciphertext), nil
}

func (this *cryptoerByDES) Decrypt(src, key, vector []byte) (string, error) {
	// format
	data, err := this.format.Decode(string(src))
	if err != nil {
		return "", err
	}
	// standard
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}
	// mode
	plaintext, err := this.mode.Decrypt(block, data, key, vector)
	if err != nil {
		return "", err
	}
	// padding
	return string(this.padding.UnPadding(plaintext)), nil
}
