package authbyemail

import (
	"net/http/httptest"
	"testing"
)

func TestServeHTTPWait(t *testing.T) {
	h := NewTestHandler()
	userID := CRYPTO.UserIDfromEmail(h.config.MailerFrom)
	h.database.AddUser(userID)

	t.Run("Correct request (not logged in)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/auth/wait", nil)
		w := httptest.NewRecorder()
		statusCode, _ := h.ServeHTTP(w, req)
		if statusCode != 0 || w.Result().StatusCode != 200 {
			t.Errorf("Request of auth/wait with no cookie should be Ok but was %v. %#v", w.Result().StatusCode, w.Result())
		}
	})

	t.Run("Correct request (not validated)", func(t *testing.T) {
		cookie, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: false, BrowserContext: ""})
		req := httptest.NewRequest("GET", "http://example.com/auth/wait", nil)
		req.Header.Add("Cookie", "authByEmailToken="+cookie)
		w := httptest.NewRecorder()
		statusCode, _ := h.ServeHTTP(w, req)
		if statusCode != 0 || w.Result().StatusCode != 200 {
			t.Errorf("Request of auth/wait with a cookie should be Ok but was %v. %#v", w.Result().StatusCode, w.Result())
		}
	})

	t.Run("Correct request (logged in)", func(t *testing.T) {
		cookie, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: true, BrowserContext: ""})
		req := httptest.NewRequest("GET", "http://example.com/auth/wait", nil)
		req.Header.Add("Cookie", "authByEmailToken="+cookie)
		w := httptest.NewRecorder()
		statusCode, _ := h.ServeHTTP(w, req)
		if statusCode != 0 || w.Result().StatusCode != 303 {
			t.Errorf("Request of auth/wait with a cookie should be Redirect but was %v. %#v", w.Result().StatusCode, w.Result())
		}
	})
}
