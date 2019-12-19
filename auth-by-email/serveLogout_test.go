package authbyemail

import (
	"net/http/httptest"
	"testing"
)

func TestServeHTTPLogout(t *testing.T) {
	h := NewTestHandler()
	userID := CRYPTO.UserIDfromEmail(h.config.MailerFrom)
	h.database.AddUser(userID)

	t.Run("Correct request (not logged in)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/auth/logout", nil)
		w := httptest.NewRecorder()
		statusCode, _ := h.ServeHTTP(w, req)
		if statusCode != 0 || w.Result().StatusCode != 200 {
			t.Errorf("Request of auth/logout with no cookie should be Ok but was %v. %#v", w.Result().StatusCode, w.Result())
		}
	})

	t.Run("Correct request (logged in)", func(t *testing.T) {
		cookie, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: true, BrowserContext: ""})
		req := httptest.NewRequest("GET", "http://example.com/auth/logout", nil)
		req.Header.Add("Cookie", "authByEmailToken="+cookie)
		w := httptest.NewRecorder()
		statusCode, _ := h.ServeHTTP(w, req)
		if statusCode != 0 || w.Result().StatusCode != 200 {
			t.Errorf("Request of auth/logout with a cookie should be Ok but was %v. %#v", w.Result().StatusCode, w.Result())
		}
		if h.database.GetCookieToken(cookie) != nil {
			t.Error("Cookie still exists in db after logging out")
		}
	})
}
