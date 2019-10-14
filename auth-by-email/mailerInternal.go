package authbyemail

import "log"

type MailerInternal interface {
    // Initialise the mailer (read config etc). Panics on error (e.g. no api-key in environment)
    Initialise(config *Config, logger *log.Logger)

    // Send a mail message
    SendMail(msg *EmailMessage) error
}
