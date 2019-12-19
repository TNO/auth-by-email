package authbyemail

import (
	"net/http"
)

// serveLogin is called when a user visits the auth/logout endpoint (for example
// from a link on the website).
func (h AuthByEmailHandler) serveLogout(w http.ResponseWriter, r *http.Request) (int, error) {
	if cookie := GetCookie(r); cookie != "" {
		// Delete the cookie. Ignore errors, because it's fine if it wasn't a valid cookie
		// to begin with
		h.database.DeleteCookieToken(GetCookie(r))
	}

	// Show a login page
	return h.serveStaticPage(w, r, 200, TplLogin)
}
