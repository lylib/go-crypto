package cryptoEx

import (
	"crypto/aes"
	"crypto/des"
)

type aesCrypto struct {
	*CryptoData
}

type desCrypto struct {
	*CryptoData
}

func NewAESCrypto(data *CryptoData) Crypto {
	return &aesCrypto{data}
}

func NewDESCrypto(data *CryptoData) Crypto {
	return &desCrypto{data}
}

func (this *aesCrypto) Encrypt(src, key, vector []byte) (string, error) {
	// standard
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// padding
	src = this.Padding.Padding(src, block.BlockSize())
	// mode
	ciphertext, err := this.Mode.Encrypt(block, src, key, vector)
	if err != nil {
		return "", err
	}
	// format
	return this.Format.Encode(ciphertext), nil
}

func (this *aesCrypto) Decrypt(src, key, vector []byte) (string, error) {
	// format
	data, err := this.Format.Decode(string(src))
	if err != nil {
		return "", err
	}
	// standard
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// mode
	plaintext, err := this.Mode.Decrypt(block, data, key, vector)
	if err != nil {
		return "", err
	}
	// padding
	return string(this.Padding.UnPadding(plaintext)), nil
}

func (this *desCrypto) Encrypt(src, key, vector []byte) (string, error) {
	// standard
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}
	// padding
	src = this.Padding.Padding(src, block.BlockSize())
	// mode
	ciphertext, err := this.Mode.Encrypt(block, src, key, vector)
	if err != nil {
		return "", err
	}
	// format
	return this.Format.Encode(ciphertext), nil
}

func (this *desCrypto) Decrypt(src, key, vector []byte) (string, error) {
	// format
	data, err := this.Format.Decode(string(src))
	if err != nil {
		return "", err
	}
	// standard
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}
	// mode
	plaintext, err := this.Mode.Decrypt(block, data, key, vector)
	if err != nil {
		return "", err
	}
	// padding
	return string(this.Padding.UnPadding(plaintext)), nil
}
