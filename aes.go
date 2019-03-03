package cryptoEx

import (
	"crypto/aes"
)

func (c *cryptoer) EncryptAES(src, key, vector string) (string, error) {
	data := []byte(src)
	keyByte := []byte(key)
	vectorByte := []byte(vector)
	block, err := aes.NewCipher(keyByte)
	if err != nil {
		return "", err
	}
	switch c.Mode {
	case "ECB":
		return c.ecb_encrypt(block, data, keyByte, vectorByte)
	case "CBC":
		return c.cbc_encrypt(block, data, keyByte, vectorByte)
	case "CTR":
		return c.ctr_encrypt(block, data, keyByte, vectorByte)
	case "OFB":
		return c.ofb_encrypt(block, data, keyByte, vectorByte)
	case "CFB":
		return c.cfb_encrypt(block, data, keyByte, vectorByte)
	}
	return "", nil
}

func (c *cryptoer) DecryptAES(src, key, vector string) (string, error) {
	keyByte := []byte(key)
	vectorByte := []byte(vector)
	data, err := c.decode(src)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(keyByte)
	if err != nil {
		return "", err
	}
	switch c.Mode {
	case "ECB":
		return c.ecb_decrypt(block, data, keyByte, vectorByte)
	case "CBC":
		return c.cbc_decrypt(block, data, keyByte, vectorByte)
	case "CTR":
		return c.ctr_decrypt(block, data, keyByte, vectorByte)
	case "OFB":
		return c.ofb_decrypt(block, data, keyByte, vectorByte)
	case "CFB":
		return c.cfb_decrypt(block, data, keyByte, vectorByte)
	}
	return "", nil
}
