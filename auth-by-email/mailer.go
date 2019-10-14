package authbyemail

type Mailer interface {
	// SendLoginLink sends a user an email with a login link using the given token
	SendLoginLink(email *EmailAddr, token string) error

	// SendAdminLoginRequest sends a user an email with an approval link for the given user
	SendAdminLoginRequest(email *EmailAddr) error

	// DecryptEmail decrypts an e-mail address that was given in an admin approval link
	DecryptEmail(encryptedEmail string) (*EmailAddr, error)
}
