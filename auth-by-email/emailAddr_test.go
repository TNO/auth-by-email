package authbyemail

import (
	"testing"
)

func TestEmailAddress(t *testing.T) {
	email1 := EmailAddr{
		User:   "alice",
		Domain: "example.com",
	}
	email2 := EmailAddr{
		User:   "ali+++++ce",
		Domain: "e.x.a.m.p.l.e.c.o.m",
	}
	email3 := EmailAddr{
		User:   "alice",
		Domain: "xn--xample-o9a.xn--fiqs8s",
	}
	email4 := EmailAddr{
		User:   "君子",
		Domain: "example.com",
	}

	t.Run("Correct e-mail address", func(t *testing.T) {
        t.Run("Created successfully", func(t *testing.T) {
            testnewmail := func(t *testing.T, s string, e *EmailAddr) {
                testmail, err := NewEmailAddrFromString(s)
                if err != nil {
                    t.Error(err)
                }
                if *testmail != *e {
                    t.Errorf("When creating an e-mail address from %s, got %v, wanted %v", s, *e, *testmail)
                }
            }

            testnewmail(t, "alice@example.com", &email1)
            testnewmail(t, "ALIce@example.com", &email1)
            testnewmail(t, "   alice@example.com ", &email1)
            testnewmail(t, "ali+++++ce@e.x.a.m.p.l.e.c.o.m", &email2)
            testnewmail(t, "alice@ıxample.中国", &email3)
            testnewmail(t, "君子@example.com", &email4)
        })

        t.Run("Successfully expressed as string", func(t *testing.T) {
            testtostring := func(t *testing.T, s string, e *EmailAddr) {
                if e.String() != s {
                    t.Errorf("When converting e-mail %v to string, got %s, wanted %s", *e, e.String(), s)
                }
            }

            testtostring(t, "alice@example.com", &email1)
            testtostring(t, "ali+++++ce@e.x.a.m.p.l.e.c.o.m", &email2)
            testtostring(t, "alice@xn--xample-o9a.xn--fiqs8s", &email3)
            testtostring(t, "君子@example.com", &email4)
        })

        t.Run("Correctly identifies local part ascii", func(t *testing.T) {
            testascii := func(t *testing.T, isAscii bool, e *EmailAddr) {
                if e.LocalPartIsASCII() != isAscii {
                    t.Errorf("When asking if %v has ascii local part, got %v, wanted %v", *e, e.LocalPartIsASCII(), isAscii)
                }
            }

            testascii(t, true, &email1)
            testascii(t, true, &email2)
            testascii(t, true, &email3)
            testascii(t, false, &email4)
        })
    })

    t.Run("Not an e-mail address", func(t *testing.T) {
        t.Run("Error during creation", func(t *testing.T) {
            testnewmail := func(t *testing.T, s string) {
                testmail, err := NewEmailAddrFromString(s)
                if err == nil {
                    t.Errorf("When creating an e-mail address from %s, got %v, wanted an error", s, *testmail)
                }
            }

            testnewmail(t, "randomtext")
        })
    })

}
