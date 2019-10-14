package authbyemail

import (
    "net/http/httptest"
    "net/url"
    "strings"
    "testing"
)

func TestServeHTTPLogin(t *testing.T) {
    h := NewTestHandler()
    h.database.AddUser(CRYPTO.UserIDfromEmail(h.config.MailerFrom))

    t.Run("Correct request (new user)", func(t *testing.T) {
        req := httptest.NewRequest("POST", "http://example.com/auth/login",
            strings.NewReader(url.Values{"email": {"test@example.com"}, "submit": {"Get"}}.Encode()))
        req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
        w := httptest.NewRecorder()
        statusCode, _ := h.ServeHTTP(w, req)
        if statusCode != 0 || w.Result().StatusCode != 303 {
            t.Errorf("Request of auth/login with new addr should be Ok but was %v. %#v", w.Result().StatusCode, w.Result())
        }
        if h.mailer.(*MockMailer).mail != "admin" {
            t.Error("No signup mail sent when trying to log in with new address")
        }
        if GetResponseCookie(w.Result()) == nil {
            t.Error("Request of auth/login with new addr should get a cookie but got nothing")
        }

    })

    t.Run("Correct request (known user)", func(t *testing.T) {
        req := httptest.NewRequest("POST", "http://example.com/auth/login",
            strings.NewReader(url.Values{"email": {h.config.MailerFrom.String()}, "submit": {"Get"}}.Encode()))
        req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
        w := httptest.NewRecorder()
        statusCode, _ := h.ServeHTTP(w, req)
        if statusCode != 0 || w.Result().StatusCode != 303 {
            t.Errorf("Request of auth/login with known addr should be Ok but was %v. %#v", w.Result().StatusCode, w.Result())
        }
        if h.mailer.(*MockMailer).mail != "login" {
            t.Error("No login mail sent when trying to log in with known address")
        }
        if GetResponseCookie(w.Result()) == nil {
            t.Error("Request of auth/login with known addr should get a cookie but got nothing")
        }

    })

    t.Run("Malformed request (no data)", func(t *testing.T) {
        req := httptest.NewRequest("POST", "http://example.com/auth/login", nil)
        req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
        w := httptest.NewRecorder()
        statusCode, _ := h.ServeHTTP(w, req)
        if statusCode != 0 || w.Result().StatusCode != 400 {
            t.Errorf("Request of auth/login with GET should be Bad Request but was %v. %#v", w.Result().StatusCode, w.Result())
        }
    })

    t.Run("Malformed request (bad email)", func(t *testing.T) {
        req := httptest.NewRequest("POST", "http://example.com/auth/login",
            strings.NewReader(url.Values{"email": {"problem"}, "submit": {"Get"}}.Encode()))
        req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
        w := httptest.NewRecorder()
        statusCode, _ := h.ServeHTTP(w, req)
        if statusCode != 0 || w.Result().StatusCode != 400 {
            t.Errorf("Request of auth/login with GET should be Bad Request but was %v. %#v", w.Result().StatusCode, w.Result())
        }

    })

    t.Run("Malformed request (bad method)", func(t *testing.T) {
        req := httptest.NewRequest("GET", "http://example.com/auth/login?"+url.Values{"email": {"admin@example.com"}, "submit": {"Get"}}.Encode(), nil)
        w := httptest.NewRecorder()
        statusCode, _ := h.ServeHTTP(w, req)
        if statusCode != 0 || w.Result().StatusCode != 400 {
            t.Errorf("Request of auth/login with GET should be Bad Request but was %v. %#v", w.Result().StatusCode, w.Result())
        }
    })
}
