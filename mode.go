package cryptoEx

import (
	"crypto/cipher"
	"errors"
)

type modeByECB struct {
}

type modeByCBC struct {
}

type modeByCTR struct {
}

type modeByOFB struct {
}

type modeByCFB struct {
}

func (this *modeByECB) Encrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
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

func (this *modeByECB) Decrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
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

func (this *modeByCBC) Encrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	mode.CryptBlocks(ciphertext, data)
	return ciphertext, nil
}

func (this *modeByCBC) Decrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(data))
	mode.CryptBlocks(plaintext, data)
	return plaintext, nil
}

func (this *modeByCTR) Encrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(data))
	mode.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}

func (this *modeByCTR) Decrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(data))
	mode.XORKeyStream(plaintext, data)
	return plaintext, nil
}

func (this *modeByOFB) Encrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewOFB(block, iv)
	ciphertext := make([]byte, len(data))
	mode.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}

func (this *modeByOFB) Decrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewOFB(block, iv)
	plaintext := make([]byte, len(data))
	mode.XORKeyStream(plaintext, data)
	return plaintext, nil
}

func (this *modeByCFB) Encrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	mode.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}

func (this *modeByCFB) Decrypt(block cipher.Block, data, key, iv []byte) ([]byte, error) {
	mode := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(data))
	mode.XORKeyStream(plaintext, data)
	return plaintext, nil
}

func getMode(m modeType) (mode cryptoMode) {
	switch m {
	case ModeType.ECB:
		mode = &modeByECB{}
	case ModeType.CBC:
		mode = &modeByCBC{}
	case ModeType.CTR:
		mode = &modeByCTR{}
	case ModeType.OFB:
		mode = &modeByOFB{}
	case ModeType.CFB:
		mode = &modeByCFB{}
	}
	return
}
