package authbyemail

import (
    "net/http"
    "time"
)

// serveApprove is called when an admin clicks an approval link in their e-mail.
// Depending on the action (approve/revoke), the user database is updated.
func (h AuthByEmailHandler) serveApprove(w http.ResponseWriter, r *http.Request) (int, error) {
    // Parse the form data in the request body
    r.ParseForm()

    if r.Method == "POST" {
        // The admin confirmed the form
        return h.serveApproveByExecutingAction(w, r)
    } else {
        // The admin clicked the link in their e-mail
        return h.serveApproveByAskingConfirmation(w, r)
    }

}

// serveApproveByAskingConfirmation is called when an admin clicks an approval link
// in their e-mail. This results in a small page asing the admin to approve the user
// or to revoke their access to the underlying website.
func (h AuthByEmailHandler) serveApproveByAskingConfirmation(w http.ResponseWriter, r *http.Request) (int, error) {
    // Check sanity of the request
    if len(r.Form["email"]) == 0 {
        h.logger.Printf("Approve-confirm attempted with missing email data, %v", r.URL)
        return h.serveBadRequest(w)
    }

    // Decrypt the e-mail given in the link
    email, err := h.mailer.DecryptEmail(r.Form["email"][0])
    if err != nil {
        h.logger.Printf("Could not decrypt email %v. Error %v", r.Form["email"][0], err)
        return h.serveBadRequest(w)
    }

    // Have all the data, output a page
    data := struct{ User, EncEmail string }{
        User:     email.String(),
        EncEmail: r.Form["email"][0],
    }

    return h.serveTemplate(w, TplApprove, &data)
}

// serveApproveByExecutingAction is called when an admin confirms what should happen
// to a user by submitting a form. This executes the chosen action (approve/delete).
func (h AuthByEmailHandler) serveApproveByExecutingAction(w http.ResponseWriter, r *http.Request) (int, error) {
    // Check sanity of the request
    if len(r.PostForm["action"]) == 0 || len(r.PostForm["email"]) == 0 {
        h.logger.Printf("Approve-execute attempted with missing action or email data")
        return h.serveBadRequest(w)
    }

    // Decrypt the e-mail given in the link
    email, err := h.mailer.DecryptEmail(r.PostForm["email"][0])
    if err != nil {
        h.logger.Printf("Could not decrypt email %v. Error %v", r.PostForm["email"][0], err)
        return h.serveBadRequest(w)
    }

    userID := CRYPTO.UserIDfromEmail(email)

    switch r.PostForm["action"][0] {
    case "approve":
        // Add user to the database
        h.database.AddUser(userID)
        // Send user a login link
        token, err := h.database.NewLinkToken(LinkToken{UserID: userID, CorrespondingCookie: ""}, 48*time.Hour)
        if err != nil {
            h.logger.Printf("Database error trying to approve a user from an admin link, %v", err)
            return 500, err
        }

        err = h.mailer.SendLoginLink(email, token)
        if err != nil {
            h.logger.Printf("Error mailing user %v a login link, %v", email.String(), err)
            return 500, err
        }

        return h.serveStaticPage(w, r, 200, TplAckApprove)

    case "revoke":
        // Delete user and invalidate all links and cookies
        h.database.DelUser(userID)
        return h.serveStaticPage(w, r, 200, TplAckRemove)

    default:
        return h.serveBadRequest(w)
    }
}
