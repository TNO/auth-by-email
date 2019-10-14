package authbyemail

import (
    "log"
)

// The LogMailer is a dummy mailer that does not send mail. but instead prints messages
// to the log.
type LogMailer struct {
    logger *log.Logger
}

func (m *LogMailer) SendLoginLink(email *EmailAddr, token string) error {
    m.logger.Printf("(LogMailer) Hi user %v, here is your login token /auth/welcome?token=%v", email.String(), token)
    return nil
}

func (m *LogMailer) SendAdminLoginRequest(email *EmailAddr) error {
    encryptedEmail := m.encryptEmail(email)
    m.logger.Printf("(LogMailer) Hi admin, please approve or revoke user %v:\n"+
        "/auth/approve?email=%v",
        email.String(), encryptedEmail)
    return nil
}

func (m *LogMailer) DecryptEmail(encryptedEmail string) (*EmailAddr, error) {
    res, err := CRYPTO.decrypt(encryptedEmail)
    if err != nil {
        return nil, err
    }
    return NewEmailAddrFromString(res)
}

func (m *LogMailer) encryptEmail(plainEmail *EmailAddr) string {
    return CRYPTO.encrypt(plainEmail.String())
}
