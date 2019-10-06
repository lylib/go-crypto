package cryptoEx

import (
	"fmt"
	"testing"
)

func TestH(t *testing.T) {
	t.Log("GG")
	cAES := NewCrypto(StandardType.AES, ModeType.ECB,
		PaddingType.PKCS5, FormatType.HEX)
	key1 := []byte("123456798765432a")    // 16 byte
	vector1 := []byte("8765432112345678") // 16 byte
	e1, _ := cAES.Encrypt([]byte("Online project hosting using Git. "), key1, vector1)
	fmt.Println(e1)
	d1, _ := cAES.Decrypt([]byte(e1), key1, vector1)
	fmt.Println(d1)

	cDES := NewCrypto(StandardType.DES, ModeType.ECB,
		PaddingType.ZERO, FormatType.BASE64)
	key2 := []byte("123456bA")    // 8 byte
	vector2 := []byte("87654321") // 8 byte
	e2, _ := cDES.Encrypt([]byte("Online project hosting using Git. "), key2, vector2)
	fmt.Println(e2)
	d2, _ := cDES.Decrypt([]byte(e2), key2, vector2)
	fmt.Println(d2)
}
