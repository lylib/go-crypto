package cryptoEx

import (
	"testing"
)

func TestAESCrypto(t *testing.T) {
	content := []byte("Online project hosting using Git. ")

	key := []byte("X7WBOELqgn6dc8CN")    // 16 byte
	vector := []byte("7vcUPpqeblkHO0Qx") // 16 byte

	aes := NewAESCrypto(&CryptoData{
		Mode:    &ECBMode{},
		Padding: &PKCS5Padding{},
		Format:  &HexFormat{},
	})
	encryptStr, _ := aes.Encrypt(content, key, vector)
	decryptStr, _ := aes.Decrypt([]byte(encryptStr), key, vector)
	t.Log(encryptStr)
	t.Log(decryptStr)
}

func TestDESCrypto(t *testing.T) {
	content := []byte("Online project hosting using Git. ")

	key := []byte("Lyp5NVOq")    // 8 byte
	vector := []byte("oW7nlMbS") // 8 byte

	des := NewDESCrypto(&CryptoData{
		Mode:    &OFBMode{},
		Padding: &ZeroPadding{},
		Format:  &Base64Format{},
	})
	encryptStr, _ := des.Encrypt(content, key, vector)
	decryptStr, _ := des.Decrypt([]byte(encryptStr), key, vector)
	t.Log(encryptStr)
	t.Log(decryptStr)
}
