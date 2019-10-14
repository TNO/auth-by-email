package authbyemail

import (
    "errors"
    "strings"
)

type EmailAddr struct {
    User   string
    Domain string
}

// NewEmailAddrFromString parses a string to find an e-mail address.
func NewEmailAddrFromString(e string) (*EmailAddr, error) {
    i := strings.LastIndex(e, "@")
    if i == -1 {
        return nil, errors.New("E-mail address does not contain @")
    }
    return &EmailAddr{
        User:   strings.ToLower(e[:i]),
        Domain: strings.ToLower(e[(i + 1):]),
    }, nil
}

func (e *EmailAddr) String() string {
    return e.User + "@" + e.Domain
}
