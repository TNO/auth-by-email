package authbyemail

import (
    "net/http"
)

// serveWelcome is called when a user clicks a login link in their e-mail.
// It checks whether the link token is valid, and if so, sets a new cookie and
// forwards the request to the Next handler.
func (h AuthByEmailHandler) serveWelcome(w http.ResponseWriter, r *http.Request) (int, error) {
    // Find out if post, call servekioskwelcome
    if r.Method == "POST" {
        return h.serveKioskWelcome(w, r)
    }

    // First, find out if the link was valid
    r.ParseForm()

    if len(r.Form["token"]) == 0 {
        return h.serveBadRequest(w)
    }

    linkToken := h.database.GetLinkToken(r.Form["token"][0])
    if linkToken == nil {
        h.logger.Printf("Link token %v not found in database\n", r.Form["token"][0])
        return h.serveNotAuthenticated(w)
    }

    // Second, check the current browser's cookie, and validate if needed
    currentCookie := GetCookie(r)
    currentCookieToken := h.database.GetCookieToken(currentCookie)
    if currentCookieToken == nil {
        err := h.makeAndSendNewCookie(w, r, linkToken.UserID)
        if err != nil {
            return 500, err
        }
    } else if !currentCookieToken.IsValidated {
        err := h.database.ValidateCookieToken(currentCookie)
        if err != nil {
            h.logger.Printf("Database error trying to validate a cookie, %v\n", err)
            return 500, err
        }
    }

    // Third, check the associated cookie of the link token, and if different and not logged in,
    // serve the "would you like to log in the other device as well?" page
    if linkToken.CorrespondingCookie != "" && currentCookie != linkToken.CorrespondingCookie {
        linkCorrespondingCookieToken := h.database.GetCookieToken(linkToken.CorrespondingCookie)
        if linkCorrespondingCookieToken != nil && !linkCorrespondingCookieToken.IsValidated {
            // Output the kiosk template.
            data := struct{ Browser, Cookie string }{
                Browser: linkCorrespondingCookieToken.BrowserContext,
                Cookie:  linkToken.CorrespondingCookie,
            }

            return h.serveTemplate(w, TplKiosk, &data)
        }
    }

    return h.serveRedirect(w, h.config.Redirect)
}

// serveKioskWelcome receives the form response form serveWelcome, in case the browser that logged in
// is not the same as the browser that opens the link in the e-mail.
func (h AuthByEmailHandler) serveKioskWelcome(w http.ResponseWriter, r *http.Request) (int, error) {
    // This form should only be posted by logged-in users who want to log themselves in elsewhere
    if !h.isCookieValid(r) {
        return h.serveNotAuthenticated(w)
    }

    // Check if the form was filled correctly i.e. all fields are present
    r.ParseForm()
    if len(r.PostForm["kioskCookie"]) == 0 || len(r.PostForm["action"]) == 0 {
        return h.serveBadRequest(w)
    }
    kioskCookie := r.PostForm["kioskCookie"][0]

    // If the user wants to approve the associated/kiosk cookie, we will validate it.
    if r.PostForm["action"][0] == "approve" {
        // Abort if the cookie was already validated
        kioskCookieToken := h.database.GetCookieToken(kioskCookie)
        if kioskCookieToken == nil || kioskCookieToken.IsValidated {
            return h.serveBadRequest(w)
        }

        // Validate the kiosk cookie
        err := h.database.ValidateCookieToken(kioskCookie)
        if err != nil {
            h.logger.Printf("Database error trying to validate a cookie, %v\n", err)
            return 500, err
        }
    } else {
        // Delete the kiosk cookie from the database, making it useless
        err := h.database.DeleteCookieToken(kioskCookie)
        if err != nil {
            h.logger.Printf("Database error trying to delete a cookie, %v\n", err)
            return 500, err
        }
    }

    // Set the request to the redirect page (this is the site root if not configured)
    return h.serveRedirect(w, h.config.Redirect)
}

// makeAndSendNewCookie creates a new validated cookie for user u and sends it to the browser
func (h AuthByEmailHandler) makeAndSendNewCookie(w http.ResponseWriter, r *http.Request, u UserID) error {
    cookie, err := h.database.NewCookieToken(CookieToken{UserID: u, IsValidated: true, BrowserContext: GetBrowserContext(r)})
    if err != nil {
        h.logger.Printf("Database error trying to create a new cookie for an existing user, %v\n", err)
        return err
    }

    http.SetCookie(w, &http.Cookie{
        Name:     "authByEmailToken",
        Path:     "/",
        Value:    cookie,
        MaxAge:   int(h.config.CookieValidity.Seconds()), // seconds
        Secure:   r.URL.Scheme == "https",
        HttpOnly: true,
    })

    return nil
}
