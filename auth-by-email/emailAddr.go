package authbyemail

import (
	"errors"
	"fmt"
	"golang.org/x/net/idna"
	"strings"
)

type EmailAddr struct {
	User   string
	Domain string
}

// NewEmailAddrFromString parses a string to find an e-mail address.
func NewEmailAddrFromString(e string) (*EmailAddr, error) {
	e = strings.TrimSpace(e)
	i := strings.LastIndex(e, "@")
	if i == -1 {
		return nil, errors.New("E-mail address does not contain @")
	}

	// Split the domain (part after the @) at each dot, and encode each part to punycode
	punycoded_domain, err := idna.ToASCII(strings.ToLower(e[(i + 1):]))
	if err != nil {
		return nil, fmt.Errorf("Error converting e-mail address domain (bytes: %v) to punycode: %v", []byte(strings.ToLower(e[(i+1):])), err)
	}

	return &EmailAddr{
		User:   strings.ToLower(e[:i]),
		Domain: punycoded_domain,
	}, nil
}

func (e *EmailAddr) String() string {
	return e.User + "@" + e.Domain
}

func (e *EmailAddr) LocalPartIsASCII() bool {
	ascii, err := idna.ToASCII(e.User)
	if err != nil {
		return false
	}
	return ascii == e.User
}
