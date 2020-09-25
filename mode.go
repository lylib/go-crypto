package cryptoEx

import (
	"crypto/cipher"
	"errors"
)

type ECBMode struct {
}

type CBCMode struct {
}

type CTRMode struct {
}

type OFBMode struct {
}

type CFBMode struct {
}

func (this *ECBMode) Encrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		return nil, errors.New("Need a multiple of the blocksize")
	}
	ciphertext := make([]byte, len(data))
	dst := ciphertext
	for len(data) > 0 {
		block.Encrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	return ciphertext, nil
}

func (this *ECBMode) Decrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		return nil, errors.New("input not full blocks")
	}
	plaintext := make([]byte, len(data))
	dst := plaintext
	for len(data) > 0 {
		block.Decrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	return plaintext, nil
}

func (this *CBCMode) Encrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	mode.CryptBlocks(ciphertext, data)
	return ciphertext, nil
}

func (this *CBCMode) Decrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(data))
	mode.CryptBlocks(plaintext, data)
	return plaintext, nil
}

func (this *CTRMode) Encrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(data))
	mode.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}

func (this *CTRMode) Decrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(data))
	mode.XORKeyStream(plaintext, data)
	return plaintext, nil
}

func (this *OFBMode) Encrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewOFB(block, iv)
	ciphertext := make([]byte, len(data))
	mode.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}

func (this *OFBMode) Decrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewOFB(block, iv)
	plaintext := make([]byte, len(data))
	mode.XORKeyStream(plaintext, data)
	return plaintext, nil
}

func (this *CFBMode) Encrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	mode.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}

func (this *CFBMode) Decrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(data))
	mode.XORKeyStream(plaintext, data)
	return plaintext, nil
}
