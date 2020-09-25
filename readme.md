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
	AES_Demo()
	DES_Demo()
}

func AES_Demo() {
	fmt.Println("AES Demo")
	content := []byte("Online project hosting using Git. ")

	key := []byte("X7WBOELqgn6dc8CN")    // 16 byte
	vector := []byte("7vcUPpqeblkHO0Qx") // 16 byte

	aes := cryptoEx.NewAESCrypto(&cryptoEx.CryptoData{
		Mode:    &cryptoEx.ECBMode{},
		Padding: &cryptoEx.PKCS5Padding{},
		Format:  &cryptoEx.HexFormat{},
	})
	encryptStr, _ := aes.Encrypt(content, key, vector)
	decryptStr, _ := aes.Decrypt([]byte(encryptStr), key, vector)
	fmt.Println(encryptStr)
	fmt.Println(decryptStr)
}

func DES_Demo() {
	fmt.Println("DES_Demo")
	content := []byte("Online project hosting using Git. ")

	key := []byte("Lyp5NVOq")    // 8 byte
	vector := []byte("oW7nlMbS") // 8 byte

	des := cryptoEx.NewDESCrypto(&cryptoEx.CryptoData{
		Mode:    &cryptoEx.OFBMode{},
		Padding: &cryptoEx.ZeroPadding{},
		Format:  &cryptoEx.Base64Format{},
	})
	encryptStr, _ := des.Encrypt(content, key, vector)
	decryptStr, _ := des.Decrypt([]byte(encryptStr), key, vector)
	fmt.Println(encryptStr)
	fmt.Println(decryptStr)
}

```