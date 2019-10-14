package authbyemail

// UserID is a keyed hash of an email address
type UserID string

func (c *Crypto) UserIDfromEmail(email *EmailAddr) UserID {
	return UserID(c.computeHmac([]byte(email.String())))
}
