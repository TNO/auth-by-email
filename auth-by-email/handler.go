package authbyemail

import (
    "github.com/mholt/caddy/caddyhttp/httpserver"
    "log"
    "net/http"
    "os"
    "runtime/debug"
    "strings"
)

type AuthByEmailHandler struct {
    Next     httpserver.Handler
    config   *Config
    database Database
    mailer   Mailer
    logger   *log.Logger
}

// NewHandler initialises the package's various parts and returns the new Handler.
//
// All errors cause a panic, since we can not run if some of the parts don't work.
// This may happen if it is impossible to initialize the cryptographic functions
// (for example because the cryptographic key is not present in the environment),
// if the database can not be initialised (for example because a location for the file
// was given, but can not be written to), or if the mailer can not be initialised
// (for example because the SendInBlue API key is not present in the environment).
func NewHandler(next httpserver.Handler, config *Config) AuthByEmailHandler {
    InitializeCrypto()

    logger := log.New(os.Stderr, "(AuthByEmail) ", log.LstdFlags)

    logger.Printf("Initializing new handler with configuration %#v", *config)

    var database Database
    if config.Database == "" {
        database = NewMapBasedDatabase()
    } else {
        database = NewDiskBackedDatabase(config, logger)
    }

    return AuthByEmailHandler{
        Next:     next,
        config:   config,
        database: database,
        mailer:   NewRealMailer(config, logger),
        logger:   logger,
    }
}

// ServeHTTP serves a response in response to an HTTP request.
// The AuthByEmail handler will check whether the user is sufficiently authorized
// before passing the request on to the "next" handler, and if not, will instead serve
// an appropriate authorization interface.
//
// The authentication module exposes a virtual directory /auth/, as in example.com/auth/.
// In it, the following endpoints exist:
//
// auth/login - can be POSTed to with an email= field.
// This will initiate a Login check: if the email is approved, send a login email, if not,
// send email to an admin asking for access.
//
// auth/wait - will wait after "login" in case the user approves the cookie elsewhere.
//
// auth/logout - will log out a logged in user by removing their cookie from the database.
//
// auth/welcome - can be GETted with a token, which if correct, sets a cookie, and forwards
// the request to the Next handler.
//
// auth/approve - can be GETted with an e-mail, and will produce a form for an admin to decide
// whether to accept or refuse membership to that user. A POST request to the same endpoint
// executes that decision.
//
// auth/delete - can be GETed, in which case it will ask for confirmation. A POST request
// to the same endpoint deletes the logged-in user from the database.
func (h AuthByEmailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
    // Caddy swallows all panics we allow to bubble up, so we have to handle them here.
    defer func() {
        if r := recover(); r != nil {
            h.logger.Printf("Recovered from a panic! %v. Stack: %v", r, string(debug.Stack()))
        }
    }()

    sanitizedUrl := strings.ToLower(r.URL.Path)
    for strings.HasPrefix(sanitizedUrl, "/") {
        sanitizedUrl = sanitizedUrl[1:]
    }

    // Log all requests
    h.logger.Printf("Received a request for `%v`", sanitizedUrl)

    // If the request URI starts with auth/, it is definitely ours.
    if strings.HasPrefix(sanitizedUrl, "auth/") {
        h.logger.Printf("This request will be handled by us: %v", sanitizedUrl)

        // Execute the appropriate method (login, welcome, ...)
        switch sanitizedUrl[5:] {
        case "login":
            return h.serveLogin(w, r)

        case "wait":
            return h.serveWait(w, r)

        case "welcome":
            return h.serveWelcome(w, r)

        case "approve":
            return h.serveApprove(w, r)

        case "logout":
            return h.serveLogout(w, r)

        case "delete":
            return h.serveDelete(w, r)

        default:
            return h.serveNotFound(w)
        }
    }

    // Otherwise, this is a request for the underlying website, and we should see if it has a
    // proper cookie set. If not, we send the log-in form.
    if !h.checkAuthentication(sanitizedUrl, r) {
        return h.serveStaticPage(w, r, 403, TplLogin)
    }

    // The default action is to have the next handler serve the request
    // (i.e., the handler that actually serves a web page).
    h.logger.Printf("This request was forwarded to the next handler: %v", sanitizedUrl)
    return h.Next.ServeHTTP(w, r)
}

// GetBrowserContext gives a deterministic but human-readable representation of the
// browser that sent the request, like "Firefox/5.0 (Windows) at 12.13.14.1".
func GetBrowserContext(r *http.Request) string {
    return r.Header.Get("User-Agent") + " at " + r.RemoteAddr
}
