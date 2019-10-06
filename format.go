package cryptoEx

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

type formatByBASE64 struct {
}

type formatByHEX struct {
}

func (this *formatByBASE64) Encode(ciphertext []byte) string {
	return base64.StdEncoding.EncodeToString(ciphertext)
}
func (this *formatByBASE64) Decode(ciphertext string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(ciphertext)
}

func (this *formatByHEX) Encode(ciphertext []byte) string {
	return fmt.Sprintf("%X", ciphertext)
}
func (this *formatByHEX) Decode(ciphertext string) ([]byte, error) {
	return hex.DecodeString(ciphertext)
}

func getFormat(f formatType) (format cryptoFormat) {
	switch f {
	case FormatType.BASE64:
		format = &formatByBASE64{}
	case FormatType.HEX:
		format = &formatByHEX{}
	}
	return
}
