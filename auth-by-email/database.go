package authbyemail

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type Database interface {
	// GetCookieToken checks if the given string corresponds to a valid cookie
	// and returns the cookie information if so.
	GetCookieToken(cookieText string) *CookieToken

	// GetLinkToken checks if the given string corresponds to a sent email
	// and returns the result. If it does correspond to a valid user, the token is
	// returned
	GetLinkToken(linkText string) *LinkToken

	// IsKnownUser checks whether the UserID is valid
	IsKnownUser(user UserID) bool

	// NewCookieToken makes a fresh cookie token for the given user
	// and saves it to the database.
	NewCookieToken(cookieToken CookieToken) (string, error)

	// ValidateCookieToken sets the Validated property of this cookie to true.
	// If there is no such cookie, an error is returned.
	ValidateCookieToken(cookieText string) error

	// DeleteCookieToken removes a given cookie. If none exists, an error is returned.
	DeleteCookieToken(cookieText string) error

	// NewLinkToken makes a fresh link token for the given user
	// and saves it to the database
	NewLinkToken(linkToken LinkToken, validityPeriod time.Duration) (string, error)

	// AddUser adds the given user to the database
	AddUser(user UserID)

	// DelUser removes a user from the database
	DelUser(user UserID) error
}

// newRandom generates 16 cryptographically random bytes and returns them as a
// string of hexadecimal digits.
func newRandom() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic("Can not generate random numbers for the link tokens")
	}
	return hex.EncodeToString(b)
}
