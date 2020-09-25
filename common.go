package cryptoEx

import "crypto/cipher"

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

type CryptoData struct {
	Mode    cryptoMode
	Padding cryptoPadding
	Format  cryptoFormat
}
