package authbyemail

import (
	"net/http"
	"strings"
)

// checkAuthentication checks if a given (sanitised) url can be accessed without
// a valid cookie, and if not, if a valid cookie is present. If neither is true,
// false is returned.
func (h AuthByEmailHandler) checkAuthentication(url string, r *http.Request) bool {
	if h.isUnprotectedPath(url) {
		return true
	}

	return h.isCookieValid(r)
}

// isCookieValid checks if the request comes with a validated cookie
func (h AuthByEmailHandler) isCookieValid(r *http.Request) bool {
	cookie := GetCookie(r)
	if cookie == "" {
		return false
	}

	token := h.database.GetCookieToken(cookie)
	return token != nil && token.IsValidated
}

// isUnprotectedPath checks whether the given sanitised url is configured to be
// accessible without authentication. The wildcard '*' is supported as the last
// character of an 'unprotected' path.
func (h AuthByEmailHandler) isUnprotectedPath(url string) bool {
	for _, p := range h.config.UnprotectedPaths {
		if p[len(p)-1] == '*' {
			if strings.HasPrefix(url, p[:(len(p)-1)]) {
				return true
			}
		} else {
			if p == url {
				return true
			}
		}
	}

	return false
}

// GetCookie returns our cookie from this request, if applicable.
func GetCookie(r *http.Request) string {
	// Check the cookie. First we have to find our cookie. Each cookie header is of the form
	// Cookie: name=value; name=value
	// with one or more name-value pairs.
	for _, cookieheader := range r.Header["Cookie"] {
		for _, cookie := range strings.Split(cookieheader, "; ") {
			if strings.HasPrefix(cookie, "authByEmailToken=") {
				return cookie[17:]
			}
		}
	}
	return ""
}
