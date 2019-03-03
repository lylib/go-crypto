package cryptoEx

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var modes = []string{"ECB", "CBC", "CTR", "OFB", "CFB"}
var paddings = []string{"PKCS5", "PKCS7", "ZERO"}
var formats = []string{"BASE64", "HEX"}

func checkMode(check string) {
	for _, mode := range modes {
		if check == mode {
			return
		}
	}
	panic("mode must in " + strings.Join(modes, ", "))
}
func checkPadding(check string) {
	for _, padding := range paddings {
		if check == padding {
			return
		}
	}
	panic("padding must in " + strings.Join(paddings, ", "))
}
func checkFormat(check string) {
	for _, format := range formats {
		if check == format {
			return
		}
	}
	panic("format must in " + strings.Join(formats, ", "))
}

type Crypto interface {
	EncryptAES(src, key, vector string) (string, error)
	DecryptAES(src, key, vector string) (string, error)

	EncryptDES(src, key, vector string) (string, error)
	DecryptDES(src, key, vector string) (string, error)
}

type cryptoer struct {
	Mode    string
	Padding string
	Format  string
}

func NewCrypto(mode, padding, format string) Crypto {
	c := new(cryptoer)
	checkMode(mode)
	checkPadding(padding)
	checkFormat(format)
	c.Mode = mode
	c.Padding = padding
	c.Format = format
	return c
}

//ECB
func (c *cryptoer) ecb_encrypt(block cipher.Block, data, key, iv []byte) (string, error) {
	bs := block.BlockSize()
	data = c.padding(data, bs)
	if len(data)%bs != 0 {
		return "", errors.New("Need a multiple of the blocksize")
	}
	ciphertext := make([]byte, len(data))
	dst := ciphertext
	for len(data) > 0 {
		block.Encrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	return c.encode(ciphertext), nil
}
func (c *cryptoer) ecb_decrypt(block cipher.Block, data, key, iv []byte) (string, error) {
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		return "", errors.New("input not full blocks")
	}
	plaintext := make([]byte, len(data))
	dst := plaintext
	for len(data) > 0 {
		block.Decrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	return string(c.unpadding(plaintext)), nil
}

//CBC
func (c *cryptoer) cbc_encrypt(block cipher.Block, data, key, iv []byte) (string, error) {
	mode := cipher.NewCBCEncrypter(block, iv)
	data = c.padding(data, block.BlockSize())
	ciphertext := make([]byte, len(data))
	mode.CryptBlocks(ciphertext, data)
	return c.encode(ciphertext), nil
}
func (c *cryptoer) cbc_decrypt(block cipher.Block, data, key, iv []byte) (string, error) {
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(data))
	mode.CryptBlocks(plaintext, data)
	return string(c.unpadding(plaintext)), nil
}

//CTR
func (c *cryptoer) ctr_encrypt(block cipher.Block, data, key, iv []byte) (string, error) {
	mode := cipher.NewCTR(block, iv)
	data = c.padding(data, block.BlockSize())
	ciphertext := make([]byte, len(data))
	mode.XORKeyStream(ciphertext, data)
	return c.encode(ciphertext), nil
}
func (c *cryptoer) ctr_decrypt(block cipher.Block, data, key, iv []byte) (string, error) {
	mode := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(data))
	mode.XORKeyStream(plaintext, data)
	return string(c.unpadding(plaintext)), nil
}

//OFB
func (c *cryptoer) ofb_encrypt(block cipher.Block, data, key, iv []byte) (string, error) {
	mode := cipher.NewOFB(block, iv)
	data = c.padding(data, block.BlockSize())
	ciphertext := make([]byte, len(data))
	mode.XORKeyStream(ciphertext, data)
	return c.encode(ciphertext), nil
}
func (c *cryptoer) ofb_decrypt(block cipher.Block, data, key, iv []byte) (string, error) {
	mode := cipher.NewOFB(block, iv)
	plaintext := make([]byte, len(data))
	mode.XORKeyStream(plaintext, data)
	return string(c.unpadding(plaintext)), nil
}

//CFB
func (c *cryptoer) cfb_encrypt(block cipher.Block, data, key, iv []byte) (string, error) {
	mode := cipher.NewCFBEncrypter(block, iv)
	data = c.padding(data, block.BlockSize())
	ciphertext := make([]byte, len(data))
	mode.XORKeyStream(ciphertext, data)
	return c.encode(ciphertext), nil
}
func (c *cryptoer) cfb_decrypt(block cipher.Block, data, key, iv []byte) (string, error) {
	mode := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(data))
	mode.XORKeyStream(plaintext, data)
	return string(c.unpadding(plaintext)), nil
}

func (c *cryptoer) encode(ciphertext []byte) string {
	if c.Format == "BASE64" {
		return base64.StdEncoding.EncodeToString(ciphertext)
	}
	return fmt.Sprintf("%X", ciphertext)
}
func (c *cryptoer) decode(ciphertext string) ([]byte, error) {
	if c.Format == "BASE64" {
		return base64.StdEncoding.DecodeString(ciphertext)
	}
	return hex.DecodeString(ciphertext)
}
func (c *cryptoer) padding(data []byte, blockSize int) []byte {
	if c.Padding == "ZERO" {
		return ZeroPadding(data, blockSize)
	}
	return PKCS5Padding(data, blockSize)
}
func (c *cryptoer) unpadding(data []byte) []byte {
	if c.Padding == "ZERO" {
		return ZeroUnPadding(data)
	}
	return PKCS5UnPadding(data)
}
