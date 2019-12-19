package authbyemail

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeHTTPDelete(t *testing.T) {
	h := NewTestHandler()
	// Setup: a user with two cookies and a link token
	userID := CRYPTO.UserIDfromEmail(h.config.MailerFrom)
	h.database.AddUser(userID)

	// Standard GET request
	test := func(t *testing.T, desiredStatus int, req *http.Request) *http.Response {
		w := httptest.NewRecorder()
		statusCode, _ := h.ServeHTTP(w, req)
		if statusCode != 0 || w.Result().StatusCode != desiredStatus {
			t.Errorf("Status code should be %v but was %v. %#v", desiredStatus, w.Result().StatusCode, w.Result())
		}
		return w.Result()
	}

	t.Run("GET request", func(t *testing.T) {
		t.Run("Malformed request (no cookie)", func(t *testing.T) {
			test(t, 403, httptest.NewRequest("GET", "http://example.com/auth/delete", nil))
			if !h.database.IsKnownUser(userID) {
				t.Error("Deleted user before confirmation")
			}
		})

		t.Run("Malformed request (bad cookie)", func(t *testing.T) {
			cookie, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: false, BrowserContext: "def"})
			req := httptest.NewRequest("GET", "http://example.com/auth/delete", nil)
			req.Header.Add("Cookie", "authByEmailToken="+cookie)
			test(t, 403, req)
			if !h.database.IsKnownUser(userID) {
				t.Error("Deleted user before confirmation")
			}
		})

		t.Run("Correct request", func(t *testing.T) {
			cookie, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: true, BrowserContext: "def"})
			req := httptest.NewRequest("GET", "http://example.com/auth/delete", nil)
			req.Header.Add("Cookie", "authByEmailToken="+cookie)
			test(t, 200, req)
			if !h.database.IsKnownUser(userID) {
				t.Error("Deleted user before confirmation")
			}
		})
	})

	// Standard POST request
	test = func(t *testing.T, desiredStatus int, req *http.Request) *http.Response {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		statusCode, _ := h.ServeHTTP(w, req)
		if statusCode != 0 || w.Result().StatusCode != desiredStatus {
			t.Errorf("Status code should be %v but was %v. %#v", desiredStatus, w.Result().StatusCode, w.Result())
		}
		return w.Result()
	}

	t.Run("POST request", func(t *testing.T) {
		t.Run("Malformed request (no cookie)", func(t *testing.T) {
			test(t, 403, httptest.NewRequest("POST", "http://example.com/auth/delete", nil))
			if !h.database.IsKnownUser(userID) {
				t.Error("Deleted user before confirmation")
			}
		})

		t.Run("Malformed request (bad cookie)", func(t *testing.T) {
			cookie, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: false, BrowserContext: "def"})
			req := httptest.NewRequest("POST", "http://example.com/auth/delete", nil)
			req.Header.Add("Cookie", "authByEmailToken="+cookie)
			test(t, 403, req)
			if !h.database.IsKnownUser(userID) {
				t.Error("Deleted user before confirmation")
			}
		})

		h.config.Admins = []*EmailAddr{h.config.MailerFrom}

		t.Run("Malformed request (delete admin)", func(t *testing.T) {
			cookie, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: true, BrowserContext: "def"})
			req := httptest.NewRequest("POST", "http://example.com/auth/delete", nil)
			req.Header.Add("Cookie", "authByEmailToken="+cookie)
			test(t, 400, req)
			if !h.database.IsKnownUser(userID) {
				t.Error("Admin deleted")
			}
		})

		h.config.Admins = nil

		t.Run("Correct request", func(t *testing.T) {
			cookie, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: true, BrowserContext: "def"})
			req := httptest.NewRequest("POST", "http://example.com/auth/delete", nil)
			req.Header.Add("Cookie", "authByEmailToken="+cookie)
			test(t, 303, req)
			if h.database.IsKnownUser(userID) {
				t.Error("User not deleted")
			}
			if ct := h.database.GetCookieToken(cookie); ct != nil {
				t.Errorf("Cookie not deleted, but %+v", ct)
			}
		})
	})
}
