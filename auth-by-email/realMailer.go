package authbyemail

import (
	"fmt"
	"html/template"
	"log"
	"strings"
)

type RealMailer struct {
	config *Config
	impl   MailerInternal
}

// NewRealMailer returns a mailer with the given configuration.
// In this case, we use the SendInBlue implementation.
func NewRealMailer(config *Config, logger *log.Logger) *RealMailer {
	impl := &SendInBlueMailer{}
	impl.Initialise(config, logger)
	return &RealMailer{config, impl}
}

// EmailMessage represents a message sent by this mailer. There is no From address,
// since that is forced by SendInBlue to be the globally configured From address.
// Instead, we provide a setting for the Reply To address.
type EmailMessage struct {
	ReplyTo *EmailAddr
	To      *EmailAddr
	Subject string
	Body    string
}

// SendLoginLink sends a login link with the given token to a user. The admin
// is given as the reply-to address.
func (m *RealMailer) SendLoginLink(email *EmailAddr, token string) error {
	admin := m.config.adminEmailFromUserEmail(email)
	if admin == nil {
		return fmt.Errorf("Need to mail login link but can not find admin for %v", email.String())
	}

	data := struct {
		User     string
		SiteName string
		Link     template.URL
	}{
		User:     email.String(),
		SiteName: m.config.SiteName,
		Link:     template.URL(m.config.SiteURL + "/auth/welcome?token=" + token),
	}

	var b strings.Builder
	outputTemplate(m.config, &b, TplMailLogin, &data)

	return m.impl.SendMail(&EmailMessage{
		ReplyTo: admin,
		To:      email,
		Subject: "[" + m.config.SiteName + "] Here is your log-in link",
		Body:    b.String(),
	})
}

// SendAdminLoginRequest sends an approve/reject link for the given user to
// their admin.
func (m *RealMailer) SendAdminLoginRequest(email *EmailAddr) error {
	admin := m.config.adminEmailFromUserEmail(email)
	if admin == nil {
		return fmt.Errorf("Need to mail admin approval link but can not find admin for %v", email.String())
	}

	data := struct {
		Admin    string
		User     string
		SiteName string
		Link     template.URL
	}{
		Admin:    admin.String(),
		User:     email.String(),
		SiteName: m.config.SiteName,
		Link:     template.URL(m.config.SiteURL + "/auth/approve?email=" + m.encryptEmail(email)),
	}

	var b strings.Builder
	outputTemplate(m.config, &b, TplMailApprove, &data)

	return m.impl.SendMail(&EmailMessage{
		ReplyTo: m.config.MailerFrom,
		To:      admin,
		Subject: "[" + m.config.SiteName + "] Please approve new user " + email.String(),
		Body:    b.String(),
	})
}

// DecryptEmail decrypts an e-mail address encrypted by encryptEmail. These are sent
// in the admin approval e-mails.
func (m *RealMailer) DecryptEmail(encryptedEmail string) (*EmailAddr, error) {
	res, err := CRYPTO.decrypt(encryptedEmail)
	if err != nil {
		return nil, err
	}
	return NewEmailAddrFromString(res)
}

// encryptEmail encrypts an e-mail address for use in links and e-mails.
func (m *RealMailer) encryptEmail(plainEmail *EmailAddr) string {
	return CRYPTO.encrypt(plainEmail.String())
}
