package authbyemail

import (
    "net/http"
    "net/http/httptest"
    "net/url"
    "strings"
    "testing"
)

func TestServeHTTPApprove(t *testing.T) {
    h := NewTestHandler()
    h.database.AddUser(CRYPTO.UserIDfromEmail(h.config.MailerFrom))

    // Standard GET request
    test := func(t *testing.T, desiredStatus int, req *http.Request) {
        w := httptest.NewRecorder()
        statusCode, _ := h.ServeHTTP(w, req)
        if statusCode != 0 || w.Result().StatusCode != desiredStatus {
            t.Errorf("Status code should be %v but was %v. %#v", desiredStatus, w.Result().StatusCode, w.Result())
        }
    }

    t.Run("Ask for confirmation", func(t *testing.T) {
        t.Run("Correct request", func(t *testing.T) {
            test(t, 200, httptest.NewRequest("GET", "http://example.com/auth/approve?"+url.Values{"email": {CRYPTO.encrypt("test@example.com")}, "submit": {"Get"}}.Encode(), nil))
        })
        t.Run("Malformed request (no data)", func(t *testing.T) {
            test(t, 400, httptest.NewRequest("GET", "http://example.com/auth/approve", nil))
        })
        t.Run("Malformed request (bad email)", func(t *testing.T) {
            test(t, 400, httptest.NewRequest("GET", "http://example.com/auth/approve?"+url.Values{"email": {CRYPTO.encrypt("problem")}, "submit": {"Get"}}.Encode(), nil))
        })
        t.Run("Malformed request (bad encryption)", func(t *testing.T) {
            test(t, 400, httptest.NewRequest("GET", "http://example.com/auth/approve?"+url.Values{"email": {"problem"}, "submit": {"Get"}}.Encode(), nil))
        })
    })

    // Standard POST request
    test = func(t *testing.T, desiredStatus int, req *http.Request) {
        req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
        w := httptest.NewRecorder()
        statusCode, _ := h.ServeHTTP(w, req)
        if statusCode != 0 || w.Result().StatusCode != desiredStatus {
            t.Errorf("Status code should be %v but was %v. %#v", desiredStatus, w.Result().StatusCode, w.Result())
        }
    }

    t.Run("Submitted form", func(t *testing.T) {

        t.Run("Correct request (approval)", func(t *testing.T) {
            h.mailer.(*MockMailer).mail = ""
            test(t, 200, httptest.NewRequest("POST", "http://example.com/auth/approve",
                strings.NewReader(url.Values{"email": {CRYPTO.encrypt("test@example.com")}, "action": {"approve"}, "submit": {"Get"}}.Encode())))
            if h.mailer.(*MockMailer).mail != "login" {
                t.Error("No login mail sent after admin approval")
            }
            if email, _ := NewEmailAddrFromString("test@example.com"); !h.database.IsKnownUser(CRYPTO.UserIDfromEmail(email)) {
                t.Error("User not added after admin approval")
            }
        })

        t.Run("Correct request (revocation)", func(t *testing.T) {
            test(t, 200, httptest.NewRequest("POST", "http://example.com/auth/approve",
                strings.NewReader(url.Values{"email": {CRYPTO.encrypt("test@example.com")}, "action": {"revoke"}, "submit": {"Get"}}.Encode())))
            if email, _ := NewEmailAddrFromString("test@example.com"); h.database.IsKnownUser(CRYPTO.UserIDfromEmail(email)) {
                t.Error("User not deleted after admin approval")
            }
        })

        t.Run("Malformed request (no data)", func(t *testing.T) {
            test(t, 400, httptest.NewRequest("POST", "http://example.com/auth/approve", nil))

        })

        t.Run("Malformed request (bad email)", func(t *testing.T) {
            test(t, 400, httptest.NewRequest("POST", "http://example.com/auth/approve",
                strings.NewReader(url.Values{"email": {CRYPTO.encrypt("problem")}, "action": {"revoke"}, "submit": {"Get"}}.Encode())))

        })

        t.Run("Malformed request (bad encryption)", func(t *testing.T) {
            test(t, 400, httptest.NewRequest("POST", "http://example.com/auth/approve",
                strings.NewReader(url.Values{"email": {"problem"}, "action": {"revoke"}, "submit": {"Get"}}.Encode())))

        })

        t.Run("Malformed request (bad action)", func(t *testing.T) {
            test(t, 400, httptest.NewRequest("POST", "http://example.com/auth/approve",
                strings.NewReader(url.Values{"email": {CRYPTO.encrypt("test@example.com")}, "action": {"banana"}, "submit": {"Get"}}.Encode())))
        })
    })
}
