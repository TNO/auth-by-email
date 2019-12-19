package authbyemail

import (
	"net/http"
)

// serveWait is the page you see after logging in. If you approve the login from your
// phone and F5 this page, you will be logged in.
func (h AuthByEmailHandler) serveWait(w http.ResponseWriter, r *http.Request) (int, error) {
	if !h.isCookieValid(r) {
		return h.serveStaticPage(w, r, 200, TplAckLogin)
	}

	return h.serveRedirect(w, h.config.Redirect)
}
