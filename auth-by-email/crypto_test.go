package authbyemail

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("AUTH_BY_EMAIL_KEY", "1234567890123456789012345678901212345678901234567890123456789012")
	InitializeCrypto()
	os.Exit(m.Run())
}

// Testing values generated with http://aes.online-domain-tools.com/
func TestEnDecrypt(t *testing.T) {
	ct := CRYPTO.encrypt("test")
	pt, err := CRYPTO.decrypt(ct)
	if err != nil {
		t.Error("Could not decrypt encrypted value")
	}
	if pt != "test" {
		t.Errorf("Decrypt of encrypted text failed: expected `%v`, output `%v`", "test", pt)
	}
}

func TestHash(t *testing.T) {
	if result := CRYPTO.computeHmac([]byte("test")); result != "HUq-zHOjVj2mQ24pUWPrJXEXHvN2eYebibOM8EbJjjE" {
		t.Errorf("Hash failed: expected `%v`, output `%v`", "HUq-zHOjVj2mQ24pUWPrJXEXHvN2eYebibOM8EbJjjE", result)
	}
}
