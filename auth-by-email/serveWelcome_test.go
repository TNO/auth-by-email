package authbyemail

import (
    "net/http"
    "net/http/httptest"
    "net/url"
    "strings"
    "testing"
    "time"
)

func TestServeHTTPWelcome(t *testing.T) {
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

    t.Run("Click link, same device", func(t *testing.T) {
        // All these tests are done with no cookie associated to the link
        link, _ := h.database.NewLinkToken(LinkToken{UserID: userID, CorrespondingCookie: ""}, time.Hour)

        t.Run("Correct request (no cookie)", func(t *testing.T) {
            rsp := test(t, 303, httptest.NewRequest("GET", "http://example.com/auth/welcome?"+url.Values{"token": {link}}.Encode(), nil))
            cookie := GetResponseCookie(rsp)
            if cookie == nil {
                t.Errorf("No cookie in response")
            } else if ct := h.database.GetCookieToken(cookie.Value); ct == nil || !ct.IsValidated {
                t.Errorf("Response cookie not valid, but %+v", ct)
            }
        })

        t.Run("Correct request (unknown cookie)", func(t *testing.T) {
            cookie := "problem"
            req := httptest.NewRequest("GET", "http://example.com/auth/welcome?"+url.Values{"token": {link}}.Encode(), nil)
            req.Header.Add("Cookie", "authByEmailToken="+cookie)
            rsp := test(t, 303, req)
            cookieRsp := GetResponseCookie(rsp)
            if cookieRsp == nil {
                t.Errorf("No cookie in response")
            } else if ct := h.database.GetCookieToken(cookieRsp.Value); ct == nil || !ct.IsValidated {
                t.Errorf("Response cookie not valid, but %+v", ct)
            }
        })

        t.Run("Correct request (unvalidated cookie)", func(t *testing.T) {
            cookie, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: false, BrowserContext: "def"})
            req := httptest.NewRequest("GET", "http://example.com/auth/welcome?"+url.Values{"token": {link}}.Encode(), nil)
            req.Header.Add("Cookie", "authByEmailToken="+cookie)
            test(t, 303, req)
            if ct := h.database.GetCookieToken(cookie); ct == nil || !ct.IsValidated {
                t.Errorf("Request cookie not validated, but %+v", ct)
            }
        })

        t.Run("Correct request (validated cookie)", func(t *testing.T) {
            cookie, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: true, BrowserContext: "def"})
            req := httptest.NewRequest("GET", "http://example.com/auth/welcome?"+url.Values{"token": {link}}.Encode(), nil)
            req.Header.Add("Cookie", "authByEmailToken="+cookie)
            test(t, 303, req)
            if ct := h.database.GetCookieToken(cookie); ct == nil || !ct.IsValidated {
                t.Errorf("Request cookie somehow invalidated?! %+v", ct)
            }
        })

        // The malformed requests are done with an invalidated cookie, which should still be invalid afterwards
        cookie, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: false, BrowserContext: "evil"})

        t.Run("Malformed request (no data)", func(t *testing.T) {
            req := httptest.NewRequest("GET", "http://example.com/auth/welcome", nil)
            req.Header.Add("Cookie", "authByEmailToken="+cookie)
            rsp := test(t, 400, req)
            if ct := h.database.GetCookieToken(cookie); ct == nil || ct.IsValidated {
                t.Errorf("Request cookie changed, should still be unvalidated but is %+v", ct)
            }
            cookieRsp := GetResponseCookie(rsp)
            if cookieRsp != nil {
                t.Errorf("Cookie given in response to malformed request: %+v", cookieRsp)
            }
        })

        t.Run("Malformed request (bad encryption)", func(t *testing.T) {
            req := httptest.NewRequest("GET", "http://example.com/auth/welcome?"+url.Values{"token": {"problem"}}.Encode(), nil)
            req.Header.Add("Cookie", "authByEmailToken="+cookie)
            rsp := test(t, 403, req)
            if ct := h.database.GetCookieToken(cookie); ct == nil || ct.IsValidated {
                t.Errorf("Request cookie changed, should still be unvalidated but is %+v", ct)
            }
            cookieRsp := GetResponseCookie(rsp)
            if cookieRsp != nil {
                t.Errorf("Cookie given in response to malformed request: %+v", cookieRsp)
            }
        })

        t.Run("Malformed request (bad method)", func(t *testing.T) {
            req := httptest.NewRequest("POST", "http://example.com/auth/welcome",
                strings.NewReader(url.Values{"token": {"problem"}}.Encode()))
            req.Header.Add("Cookie", "authByEmailToken="+cookie)
            req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
            rsp := test(t, 403, req)
            if ct := h.database.GetCookieToken(cookie); ct == nil || ct.IsValidated {
                t.Errorf("Request cookie changed, should still be unvalidated but is %+v", ct)
            }
            cookieRsp := GetResponseCookie(rsp)
            if cookieRsp != nil {
                t.Errorf("Cookie given in response to malformed request: %+v", cookieRsp)
            }
        })

        t.Run("Malformed request (expired token)", func(t *testing.T) {
            token := CRYPTO.serialize(linkTokenInternal{
                LinkToken:  LinkToken{UserID: userID, CorrespondingCookie: ""},
                ValidUntil: time.Now().Add(-time.Minute),
            })
            req := httptest.NewRequest("GET", "http://example.com/auth/welcome?"+url.Values{"token": {token}}.Encode(), nil)
            req.Header.Add("Cookie", "authByEmailToken="+cookie)
            rsp := test(t, 403, req)
            if ct := h.database.GetCookieToken(cookie); ct == nil || ct.IsValidated {
                t.Errorf("Request cookie changed, should still be unvalidated but is %+v", ct)
            }
            cookieRsp := GetResponseCookie(rsp)
            if cookieRsp != nil {
                t.Errorf("Cookie given in response to malformed request: %+v", cookieRsp)
            }
        })

        t.Run("Malformed request (bad user)", func(t *testing.T) {
            token := CRYPTO.serialize(linkTokenInternal{
                LinkToken:  LinkToken{UserID: UserID("problem"), CorrespondingCookie: ""},
                ValidUntil: time.Now().Add(time.Minute),
            })
            req := httptest.NewRequest("GET", "http://example.com/auth/welcome?"+url.Values{"token": {token}}.Encode(), nil)
            req.Header.Add("Cookie", "authByEmailToken="+cookie)
            rsp := test(t, 403, req)
            if ct := h.database.GetCookieToken(cookie); ct == nil || ct.IsValidated {
                t.Errorf("Request cookie changed, should still be unvalidated but is %+v", ct)
            }
            cookieRsp := GetResponseCookie(rsp)
            if cookieRsp != nil {
                t.Errorf("Cookie given in response to malformed request: %+v", cookieRsp)
            }
        })
    })

    t.Run("Click link, different device", func(t *testing.T) {
        // All these tests are done with the requesting device logged in (like the last test of Same Device)
        cookieLoggedIn, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: true, BrowserContext: "def"})

        t.Run("Correct request (link has no cookie)", func(t *testing.T) {
            // PASS: This is the same as the previous test
        })

        t.Run("Correct request (link has unknown cookie)", func(t *testing.T) {
            link, _ := h.database.NewLinkToken(LinkToken{UserID: userID, CorrespondingCookie: "problem"}, time.Hour)
            req := httptest.NewRequest("GET", "http://example.com/auth/welcome?"+url.Values{"token": {link}}.Encode(), nil)
            req.Header.Add("Cookie", "authByEmailToken="+cookieLoggedIn)
            test(t, 303, req)
        })

        t.Run("Correct request (link has unvalidated cookie)", func(t *testing.T) {
            cookieKiosk, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: false, BrowserContext: "def"})
            link, _ := h.database.NewLinkToken(LinkToken{UserID: userID, CorrespondingCookie: cookieKiosk}, time.Hour)
            req := httptest.NewRequest("GET", "http://example.com/auth/welcome?"+url.Values{"token": {link}}.Encode(), nil)
            req.Header.Add("Cookie", "authByEmailToken="+cookieLoggedIn)
            test(t, 200, req) // This outputs the template
        })

        t.Run("Correct request (link has validated cookie)", func(t *testing.T) {
            cookieKiosk, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: true, BrowserContext: "def"})
            link, _ := h.database.NewLinkToken(LinkToken{UserID: userID, CorrespondingCookie: cookieKiosk}, time.Hour)
            req := httptest.NewRequest("GET", "http://example.com/auth/welcome?"+url.Values{"token": {link}}.Encode(), nil)
            req.Header.Add("Cookie", "authByEmailToken="+cookieLoggedIn)
            test(t, 303, req)
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

    t.Run("Submitted form", func(t *testing.T) {
        // Correct requests should be posted by a logged-in user
        cookieLoggedIn, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: true, BrowserContext: "abc"})

        t.Run("Correct request (approval)", func(t *testing.T) {
            cookieKiosk, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: false, BrowserContext: "def"})

            req := httptest.NewRequest("POST", "http://example.com/auth/welcome",
                strings.NewReader(url.Values{"kioskCookie": {cookieKiosk}, "action": {"approve"}, "submit": {"Get"}}.Encode()))
            req.Header.Add("Cookie", "authByEmailToken="+cookieLoggedIn)
            test(t, 303, req)

            if ct := h.database.GetCookieToken(cookieKiosk); ct == nil || !ct.IsValidated {
                t.Errorf("Kiosk cookie is not validated, but is %+v", ct)
            }
        })

        t.Run("Correct request (revocation)", func(t *testing.T) {
            cookieKiosk, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: false, BrowserContext: "def"})

            req := httptest.NewRequest("POST", "http://example.com/auth/welcome",
                strings.NewReader(url.Values{"kioskCookie": {cookieKiosk}, "action": {"revoke"}, "submit": {"Get"}}.Encode()))
            req.Header.Add("Cookie", "authByEmailToken="+cookieLoggedIn)
            test(t, 303, req)

            if ct := h.database.GetCookieToken(cookieKiosk); ct != nil {
                t.Errorf("Kiosk cookie is not deleted, but is %+v", ct)
            }
        })

        t.Run("Correct request (revocation after validation)", func(t *testing.T) {
            cookieKiosk, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: true, BrowserContext: "def"})

            req := httptest.NewRequest("POST", "http://example.com/auth/welcome",
                strings.NewReader(url.Values{"kioskCookie": {cookieKiosk}, "action": {"revoke"}, "submit": {"Get"}}.Encode()))
            req.Header.Add("Cookie", "authByEmailToken="+cookieLoggedIn)
            test(t, 303, req)

            if ct := h.database.GetCookieToken(cookieKiosk); ct != nil {
                t.Errorf("Kiosk cookie is not deleted, but is %+v", ct)
            }
        })

        t.Run("Malformed request (no data)", func(t *testing.T) {
            req := httptest.NewRequest("POST", "http://example.com/auth/welcome", nil)
            req.Header.Add("Cookie", "authByEmailToken="+cookieLoggedIn)
            test(t, 400, req)
        })

        t.Run("Malformed request (second approval)", func(t *testing.T) {
            cookieKiosk, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: true, BrowserContext: "def"})

            req := httptest.NewRequest("POST", "http://example.com/auth/welcome",
                strings.NewReader(url.Values{"kioskCookie": {cookieKiosk}, "action": {"approve"}, "submit": {"Get"}}.Encode()))
            req.Header.Add("Cookie", "authByEmailToken="+cookieLoggedIn)
            test(t, 400, req)
        })

        t.Run("Malformed request (bad kiosk cookie)", func(t *testing.T) {
            req := httptest.NewRequest("POST", "http://example.com/auth/welcome",
                strings.NewReader(url.Values{"kioskCookie": {"problem"}, "action": {"approve"}, "submit": {"Get"}}.Encode()))
            req.Header.Add("Cookie", "authByEmailToken="+cookieLoggedIn)
            test(t, 400, req)
        })

        // Try to approve a kiosk cookie, but as a bad user
        cookieNotLoggedIn, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: false, BrowserContext: "abc"})

        t.Run("Malformed request (approval from unvalidated user)", func(t *testing.T) {
            cookieKiosk, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: false, BrowserContext: "def"})

            req := httptest.NewRequest("POST", "http://example.com/auth/welcome",
                strings.NewReader(url.Values{"kioskCookie": {cookieKiosk}, "action": {"approve"}, "submit": {"Get"}}.Encode()))
            req.Header.Add("Cookie", "authByEmailToken="+cookieNotLoggedIn)
            test(t, 403, req)

            if ct := h.database.GetCookieToken(cookieKiosk); ct == nil || ct.IsValidated {
                t.Errorf("Kiosk cookie was affected by bad user, and is %+v", ct)
            }
            if ct := h.database.GetCookieToken(cookieNotLoggedIn); ct == nil || ct.IsValidated {
                t.Errorf("Own cookie was affected by bad user, and is %+v", ct)
            }
        })

        t.Run("Malformed request (approval from same user)", func(t *testing.T) {
            req := httptest.NewRequest("POST", "http://example.com/auth/welcome",
                strings.NewReader(url.Values{"kioskCookie": {cookieNotLoggedIn}, "action": {"approve"}, "submit": {"Get"}}.Encode()))
            req.Header.Add("Cookie", "authByEmailToken="+cookieNotLoggedIn)
            test(t, 403, req)

            if ct := h.database.GetCookieToken(cookieNotLoggedIn); ct == nil || ct.IsValidated {
                t.Errorf("Kiosk cookie was affected by bad user, and is %+v", ct)
            }
        })

        t.Run("Malformed request (approval from bad login)", func(t *testing.T) {
            cookieKiosk, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: false, BrowserContext: "def"})

            req := httptest.NewRequest("POST", "http://example.com/auth/welcome",
                strings.NewReader(url.Values{"kioskCookie": {cookieNotLoggedIn}, "action": {"approve"}, "submit": {"Get"}}.Encode()))
            req.Header.Add("Cookie", "authByEmailToken="+"problem")
            test(t, 403, req)

            if ct := h.database.GetCookieToken(cookieKiosk); ct == nil || ct.IsValidated {
                t.Errorf("Kiosk cookie was affected by bad user, and is %+v", ct)
            }
            if ct := h.database.GetCookieToken(cookieNotLoggedIn); ct == nil || ct.IsValidated {
                t.Errorf("Own cookie was affected by bad user, and is %+v", ct)
            }
        })

        t.Run("Malformed request (approval from no login)", func(t *testing.T) {
            cookieKiosk, _ := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: false, BrowserContext: "def"})

            req := httptest.NewRequest("POST", "http://example.com/auth/welcome",
                strings.NewReader(url.Values{"kioskCookie": {cookieNotLoggedIn}, "action": {"approve"}, "submit": {"Get"}}.Encode()))
            test(t, 403, req)

            if ct := h.database.GetCookieToken(cookieKiosk); ct == nil || ct.IsValidated {
                t.Errorf("Kiosk cookie was affected by bad user, and is %+v", ct)
            }
            if ct := h.database.GetCookieToken(cookieNotLoggedIn); ct == nil || ct.IsValidated {
                t.Errorf("Own cookie was affected by bad user, and is %+v", ct)
            }
        })
    })
}
