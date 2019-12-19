package authbyemail

import (
    "net/http"
    "time"
)

// serveLogin is called when a user fills their e-mail address in the landing page.
// It checks if the user has been approved; if so, it sends them a login link.
// If not, an admin is asked for approval.
func (h AuthByEmailHandler) serveLogin(w http.ResponseWriter, r *http.Request) (int, error) {
    // Parse the form data in the request body
    r.ParseForm()

    if len(r.PostForm["email"]) == 0 {
        return h.serveBadRequest(w)
    }

    email, err := NewEmailAddrFromString(r.PostForm["email"][0])
    if err != nil {
        return h.serveBadRequest(w)
    }

	userID := CRYPTO.UserIDfromEmail(email)

	// If the user is new but from a whitelisted domain, they should be added before being sent a link
	if h.config.IsDomainWhitelisted(email.Domain) && !h.database.IsKnownUser(userID) {
		// If the user is not known, but should be automatically approved, we add them to the database
		// and then send the e-mail.
		h.database.AddUser(userID)
	}

	// Send the appropriate email
	if h.database.IsKnownUser(userID) {
		// If the user is known, we support a kiosk login by giving this browser an invalid
		// cookie that can later be validated.
		cookie, err := h.database.NewCookieToken(CookieToken{UserID: userID, IsValidated: false, BrowserContext: GetBrowserContext(r)})
		if err != nil {
			h.logger.Printf("Database error trying to set cookie for an existing user, %v\n", err)
			return 500, err
		}

		token, err := h.database.NewLinkToken(LinkToken{UserID: userID, CorrespondingCookie: cookie}, time.Hour)
		if err != nil {
			h.logger.Printf("Database error trying to log in an existing user, %v\n", err)
			return 500, err
		}

		err = h.mailer.SendLoginLink(email, token)
		if err != nil {
			h.logger.Printf("Error mailing user %v a login link, %v", email.String(), err)
			return 500, err
		}

		// Everything worked, give the cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "authByEmailToken",
			Path:     "/",
			Value:    cookie,
			MaxAge:   int(h.config.CookieValidity.Seconds()), // seconds
			Secure:   r.URL.Scheme == "https",
			HttpOnly: true,
		})
	} else {
		// For unknown users, make an admin request. Given the timescale, setting an unvalidated
		// cookie is not necessary (kiosk login is not supported).
		err := h.mailer.SendAdminLoginRequest(email)
		if err != nil {
			h.logger.Printf("Error mailing user %v's admin an approval link, %v", email.String(), err)
			return 500, err
		}

		// We still make and give a cookie, though it is not tracked. This is necessary to prevent
		// users from using this interface to test if a certain e-mail address is known to us.
		http.SetCookie(w, &http.Cookie{
			Name:     "authByEmailToken",
			Path:     "/",
			Value:    newRandom(),
			MaxAge:   int(h.config.CookieValidity.Seconds()), // seconds
			Secure:   r.URL.Scheme == "https",
			HttpOnly: true,
		})
	}

	return h.serveRedirect(w, "/auth/wait")
}
