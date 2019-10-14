package authbyemail

import (
	"errors"
	"net/http"
)

func (h AuthByEmailHandler) serveBadRequest(w http.ResponseWriter) (int, error) {
	h.logger.Println("Serving a 400")
	w.WriteHeader(400)
	return 0, errors.New("Bad request")
}

func (h AuthByEmailHandler) serveNotAuthenticated(w http.ResponseWriter) (int, error) {
	h.logger.Println("Serving a 403")
	w.WriteHeader(403)
	return 0, errors.New("Not authenticated")
}

func (h AuthByEmailHandler) serveNotFound(w http.ResponseWriter) (int, error) {
	h.logger.Println("Serving a 404")
	w.WriteHeader(404)
	return 0, errors.New("Not found")
}

func (h AuthByEmailHandler) serveRedirect(w http.ResponseWriter, location string) (int, error) {
	w.Header().Add("Location", location)
	w.WriteHeader(303) // "See Other"
	return 0, nil
}
