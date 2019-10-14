package authbyemail

import (
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "strconv"
    "strings"
)

type SendInBlueMailer struct {
    config *Config
    logger *log.Logger
    apikey string
}

// NewSendInBlueMailer returns a new mailer with the given configuration.
// It reads an API key from the environment and will panic if it is not there,
// so make sure to set SENDINBLUE_API_KEY.
func (m *SendInBlueMailer) Initialise(config *Config, logger *log.Logger) {
    apikey, ok := os.LookupEnv("SENDINBLUE_API_KEY")
    if !ok {
        panic("No API key for SendInBlue in env! please set SENDINBLUE_API_KEY")
    }
    m.config, m.logger, m.apikey = config, logger, apikey
}

// sendMail sends an e-mail message using the SendInBlue API. Normally we use
// the custom Send___ methods instead.
func (m *SendInBlueMailer) SendMail(msg *EmailMessage) error {
    url := "https://api.sendinblue.com/v3/smtp/email"

    payload := strings.NewReader(`{` +
        `"sender":{` +
        `"name":` + strconv.Quote(m.config.SiteName) + `,` +
        `"email":` + strconv.Quote(m.config.MailerFrom.String()) +
        `},` +
        `"to":[{"email":` + strconv.Quote(msg.To.String()) + `}],` +
        `"htmlContent":` + strconv.Quote(msg.Body) + `,` +
        `"subject":` + strconv.Quote(msg.Subject) + `,` +
        `"replyTo":{"email":` + strconv.Quote(msg.ReplyTo.String()) + `}` +
        `}`)

    req, err := http.NewRequest("POST", url, payload)
    if err != nil {
        m.logger.Println("Error sending email (drafting new api request):", err)
        return err
    }

    req.Header.Add("content-type", "application/json")
    req.Header.Add("api-key", m.apikey)

    res, err := http.DefaultClient.Do(req)
    if err != nil {
        m.logger.Println("Error sending email (performing api request):", err)
        return err
    }

    defer res.Body.Close()
    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
        m.logger.Println("Error sending email (reading response to api request):", err)
        return err
    }

    if res.Status[0] != '2' {
        m.logger.Println("Result of sending email (response to api request) starts with non-2xx status. Printing unparsed body, which might contain the error message:")
        m.logger.Println(string(body))
        return fmt.Errorf("Error sending email (API response from SendInBlue mailing provider): %v", string(body))
    }

    return nil
}
