package authbyemail

import (
    "io/ioutil"
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

    // GET request, but we assume it works and search for text
    testString := func(t *testing.T, textToFind string, req *http.Request) {
        w := httptest.NewRecorder()
        statusCode, _ := h.ServeHTTP(w, req)
        if statusCode != 0 || w.Result().StatusCode != 200 {
            t.Errorf("Status code should be 200 but was %v. %#v", w.Result().StatusCode, w.Result())
        }
        responseBytes, _ := ioutil.ReadAll(w.Result().Body) // If error, we won't find the text anyway
        if !strings.Contains(string(responseBytes), textToFind) {
            t.Errorf("Did not find \n%v\n in the following response: \n%v\n", textToFind, string(responseBytes))
        }
    }

    t.Run("Confirmation form correctly identifies existing users", func(t *testing.T) {
        t.Run("New user should not exist", func(t *testing.T) {
            testString(t, "This user does not exist in the database.",
                httptest.NewRequest("GET", "http://example.com/auth/approve?"+url.Values{"email": {CRYPTO.encrypt("test@example.com")}, "submit": {"Get"}}.Encode(), nil))
        })

        // Add the user and try again
        email, _ := NewEmailAddrFromString("test@example.com")
        userID := CRYPTO.UserIDfromEmail(email)
        h.database.AddUser(userID)

        t.Run("Existing user should exist", func(t *testing.T) {
            testString(t, "This user is currently approved. Approving them again will resend the log-in link.",
                httptest.NewRequest("GET", "http://example.com/auth/approve?"+url.Values{"email": {CRYPTO.encrypt("test@example.com")}, "submit": {"Get"}}.Encode(), nil))
        })
        h.database.DelUser(userID)
    })

    t.Run("Confirmation form correctly handles non-ASCII addresses", func(t *testing.T) {
        t.Run("Non-ASCII domain should be punycoded", func(t *testing.T) {
            testString(t, "xn--example-tfb.com",
                httptest.NewRequest("GET", "http://example.com/auth/approve?"+url.Values{"email": {CRYPTO.encrypt("test@exaımple.com")}, "submit": {"Get"}}.Encode(), nil))
        })

        t.Run("Non-ASCII local part should give a warning", func(t *testing.T) {
            testString(t, "This e-mail address contains non-ascii characters.",
                httptest.NewRequest("GET", "http://example.com/auth/approve?"+url.Values{"email": {CRYPTO.encrypt("teıst@example.com")}, "submit": {"Get"}}.Encode(), nil))
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
