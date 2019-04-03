package cryptoEx

import (
	"fmt"
	"testing"

	cryptoEx "github.com/lylib/go-crypto"
)

func TestH(t *testing.T) {
	t.Log("GG")
	c := cryptoEx.NewCrypto("OFB", "ZERO", "HEX")
	e1, _ := c.EncryptAES("Online project hosting using Git. ", "1234567887654321", "8765432112345678")
	fmt.Println(e1)
	d1, _ := c.DecryptAES(e1, "1234567887654321", "8765432112345678")
	fmt.Println(d1)

	e2, _ := c.EncryptDES("Online project hosting using Git. ", "12345678", "87654321")
	fmt.Println(e2)
	d2, _ := c.DecryptDES(e2, "12345678", "87654321")
	fmt.Println(d2)
}
