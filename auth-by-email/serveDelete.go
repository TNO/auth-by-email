package authbyemail

import (
	"net/http"
)

// serveDelete allows users to delete themselves.
func (h AuthByEmailHandler) serveDelete(w http.ResponseWriter, r *http.Request) (int, error) {
	if !h.isCookieValid(r) {
		return h.serveNotAuthenticated(w)
	}

	// If GET, ask if they're sure
	if r.Method == "GET" {
		return h.serveStaticPage(w, r, 200, TplDelete)
	}

	// If POST, they are. Delete them.
	cookie := GetCookie(r)
	token := h.database.GetCookieToken(cookie)
	if token == nil {
		// This can not occur given the implementation of isCookieValid
		return h.serveBadRequest(w)
	}

	// Check if the user is not an admin
	for _, adminEmail := range h.config.Admins {
		if CRYPTO.UserIDfromEmail(adminEmail) == token.UserID {
			h.logger.Printf("Can not delete admin %v", adminEmail)
			return h.serveBadRequest(w)
		}
	}

	err := h.database.DelUser(token.UserID)
	if err != nil {
		h.logger.Printf("Could not delete a user, %v", err)
		return 500, err
	}

	// Redirect to the root
	return h.serveRedirect(w, "/")
}
