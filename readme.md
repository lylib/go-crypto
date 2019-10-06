# 说明
> 主要针对“AES和DES加密算法”的应用：
- 加密模式："ECB", "CBC", "CTR", "OFB", "CFB"
- 填充方式："PKCS5", "PKCS7", "ZERO"
- 输出格式："BASE64", "HEX"

# demo
```golang
package main

import (
	"fmt"

	cryptoEx "github.com/lylib/go-crypto"
)

func main() {
	content := []byte("Online project hosting using Git. ")

	// AES
	cAES := cryptoEx.NewCrypto(cryptoEx.StandardType.AES, cryptoEx.ModeType.ECB,
		cryptoEx.PaddingType.PKCS5, cryptoEx.FormatType.HEX)
	key1 := []byte("123456798765432a")    // 16 byte
	vector1 := []byte("8765432112345678") // 16 byte
	e1, _ := cAES.Encrypt(content, key1, vector1)
	fmt.Println(e1)
	d1, _ := cAES.Decrypt([]byte(e1), key1, vector1)
	fmt.Println(d1)

	// DES
	cDES := cryptoEx.NewCrypto(cryptoEx.StandardType.DES, cryptoEx.ModeType.ECB,
		cryptoEx.PaddingType.ZERO, cryptoEx.FormatType.BASE64)
	key2 := []byte("123456bA")    // 8 byte
	vector2 := []byte("87654321") // 8 byte
	e2, _ := cDES.Encrypt(content, key2, vector2)
	fmt.Println(e2)
	d2, _ := cDES.Decrypt([]byte(e2), key2, vector2)
	fmt.Println(d2)
}
```