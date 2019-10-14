package authbyemail

import (
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestServeHTTP(t *testing.T) {
    h := NewTestHandler()
    var req *http.Request
    var w *httptest.ResponseRecorder
    var statusCode int

    // Start the basic requests

    // A Forbidden request
    req = httptest.NewRequest("GET", "http://example.com/", nil)
    w = httptest.NewRecorder()
    statusCode, _ = h.ServeHTTP(w, req)
    if statusCode != 0 || w.Result().StatusCode != 403 {
        t.Errorf("Request of protected path should be Forbidden but was %v. %#v", w.Result().StatusCode, w.Result())
    }

    // An unprotected request
    req = httptest.NewRequest("GET", "http://example.com/testpath", nil)
    w = httptest.NewRecorder()
    statusCode, _ = h.ServeHTTP(w, req)
    if statusCode != 0 || w.Result().StatusCode != 200 {
        t.Errorf("Request of unprotected path should be Ok but was %v. %#v", w.Result().StatusCode, w.Result())
    }

    // A non-existing request
    req = httptest.NewRequest("GET", "http://example.com/auth/etc", nil)
    w = httptest.NewRecorder()
    statusCode, _ = h.ServeHTTP(w, req)
    if statusCode != 0 || w.Result().StatusCode != 404 {
        t.Errorf("Request of non-existing path should be Not Found but was %v. %#v", w.Result().StatusCode, w.Result())
    }

    // Make a "good" user and see if they can get a successful request
    userID := UserID("test")
    h.database.AddUser(userID)
    cookie, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: true, BrowserContext: ""})
    req = httptest.NewRequest("GET", "http://example.com/", nil)
    req.Header.Add("Cookie", "authByEmailToken="+cookie)
    w = httptest.NewRecorder()
    statusCode, _ = h.ServeHTTP(w, req)
    if statusCode != 0 || w.Result().StatusCode != 200 {
        t.Errorf("Authenticated request should be OK but was %v. %#v", w.Result().StatusCode, w.Result())
    }
    if body, _ := ioutil.ReadAll(w.Result().Body); string(body) != "Page" {
        t.Errorf("Authenticated request contained incorrect data, wanted `Page`, got %q", string(body))
    }
    h.database.DeleteCookieToken(cookie)
    h.database.DelUser(userID)
}

func NewTestHandler() *AuthByEmailHandler {
    // Set up a handler
    config := newConfig()
    config.Admins = nil
    config.FilesystemRoot = "."
    config.Database = "/tmp/testingdb"
    config.UnprotectedPaths = []string{"testpath"}
    config.Redirect = "testredir"
    config.SiteName = "Test"
    config.SiteURL = "http://example.com"
    config.MailerFrom, _ = NewEmailAddrFromString("admin@example.com")

    return &AuthByEmailHandler{
        Next:     &MockNext{},
        config:   config,
        database: NewMapBasedDatabase(),
        mailer:   &MockMailer{},
        logger:   log.New(&strings.Builder{}, "", log.LstdFlags),
    }
}

type MockNext struct{}

// When our handler "approves" a request it gets sent to a "next" handler. This is a handler
// that serves the word "Page" for all requests, so we can check successful authentication.
func (mn MockNext) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
    fmt.Fprintf(w, "Page")
    return 0, nil
}

type MockMailer struct {
    mail string
}

func (m *MockMailer) SendLoginLink(email *EmailAddr, token string) error {
    m.mail = "login"
    return nil
}

func (m *MockMailer) SendAdminLoginRequest(email *EmailAddr) error {
    m.mail = "admin"
    return nil
}

func (m *MockMailer) DecryptEmail(encryptedEmail string) (*EmailAddr, error) {
    res, err := CRYPTO.decrypt(encryptedEmail)
    if err != nil {
        return nil, err
    }
    return NewEmailAddrFromString(res)
}

func (m *MockMailer) encryptEmail(plainEmail *EmailAddr) string {
    return CRYPTO.encrypt(plainEmail.String())
}

func GetResponseCookie(r *http.Response) *http.Cookie {
    for _, cookie := range r.Cookies() {
        if cookie.Name == "authByEmailToken" {
            return cookie
        }
    }
    return nil
}
