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
	c := cryptoEx.NewCrypto("OFB", "ZERO", "HEX")
	e1, _ := c.EncryptAES("Online project hosting using Git. ", "1234567887654321", "8765432112345678")
	fmt.Println(e1)
	d1, _ := c.DecryptAES(e1, "1234567887654321", "8765432112345678")
	fmt.Println(d1)

	e2, _ := c.EncryptDES("Online project hosting using Git. ", "12345678", "87654321")
	fmt.Println(e2)
	d2, _ := c.DecryptDES(e3, "12345678", "87654321")
	fmt.Println(d2)
}

```