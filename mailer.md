# Creating your own mailer plugin for auth-by-email

If you would rather use your own mailer service for sending e-mail, some work is in order, as you need to implement the relevant mail sending routines in Go.
With this guide, we hope to make this process as simple as possible.

## Relevant files

The mailer plugin for SendInBlue is created in the function `NewRealMailer`, in [realMailer.go](auth-by-email/realMailer.go).
Its implementation must conform to the interface [mailerInternal](auth-by-email/mailerInternal.go).
The implementation for SendInBlue resides in [sendInBlueMailer.go](auth-by-email/sendInBlueMailer.go).

## How to write your own mailer

Usually, a mailer service will give you log-in information, such as an API key.
We normally read this information from the environment.
You should do this in the `Initialise()` method of your mailer, and perform any other configuration required.
If any necessary information is missing, you should panic.

`Initialise()` will be called when the web server starts, and is passed a `Config` and a `log.Logger`.
The latter should be used by your mailer to emit any status messages.
The former contains details given by the user in the Caddyfile; the `Config` type is defined in [config.go](auth-by-email/config.go).

To send an e-mail, the web server will call `SendMail()`, with as its argument a pointer to an `EmailMessage` defined as follows:

```go
type EmailMessage struct {
    ReplyTo *EmailAddr
    To      *EmailAddr
    Subject string
    Body    string
}

type EmailAddr struct {
    User   string
    Domain string
}
```

In `SendMail()`, you should send this message, or return an `error` indicating what went wrong.
For an example, see the SendInBlue implementation.
