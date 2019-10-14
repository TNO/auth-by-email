package authbyemail

import (
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

// outputTemplate outputs the contents of a html page template to the Writer,
// replacing any {{.Tags}} by the data in the struct passed as 'data'.
// The fields of the struct should be the same as those in the template's tags
// (given the example tag above, data := struct{Tags string}{...}).
//
// Remember to use template.URL et al for fields containing non-text data.
func outputTemplate(config *Config, w io.Writer, tid TemplateID, data interface{}) {
	var filedata string
	if filedata_bytes, err := ioutil.ReadFile(filepath.Join(config.FilesystemRoot, Templates[tid].Filename)); err == nil {
		filedata = string(filedata_bytes)
	} else {
		filedata = Templates[tid].DefaultText
	}

	t, err := template.New("page").Parse(filedata)
	if err != nil {
		log.Panicf("Can not parse template file (template %v): %v", t, err)
	}

	err = t.Execute(w, data)
	if err != nil {
		log.Panicf("Can not execute template file (template %v): %v", t, err)
	}
}

// serveTemplate outputs the contents of a html page template to the ResponseWriter,
// replacing any {{.Tags}} by the data in the struct passed as 'data'.
// The fields of the struct should be the same as those in the template's tags
// (given the example tag above, data := struct{Tags string}{...}).
//
// Remember to use template.URL et al for fields containing non-text data.
func (h AuthByEmailHandler) serveTemplate(w http.ResponseWriter, tid TemplateID, data interface{}) (int, error) {
	// This is a wrapper for outputTemplate, suitable for sending to a browser;
	// this requires setting a content-type.
	w.Header().Add("Content-Type", "text/html; charset=utf-8")

	outputTemplate(h.config, w, tid, data)
	return 0, nil
}

// serveStaticPage is a shorthand that serves a static page in a template variable
// to the responseWriter with the status code given as an argument.
func (h AuthByEmailHandler) serveStaticPage(w http.ResponseWriter, r *http.Request, responseStatus int, tid TemplateID) (int, error) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(responseStatus)

	file, err := os.Open(filepath.Join(h.config.FilesystemRoot, Templates[tid].Filename))
	if err == nil {
		io.Copy(w, file)
		file.Close()
	} else {
		io.WriteString(w, Templates[tid].DefaultText)
	}

	return 0, nil
}

// HtmlTemplate is the pair of custom and default file contents for each template
type HtmlTemplate struct {
	Filename    string
	DefaultText string
}

type TemplateID uint

// This is an enum listing the possible HTML templates used in this package.
// They are associated with a filename and default data in the Templates map.
const (
	TplLogin TemplateID = iota
	TplApprove
	TplKiosk
	TplDelete
	TplAckLogin
	TplAckApprove
	TplAckRemove
	TplMailLogin
	TplMailApprove
)

// This is a mapping from TemplateIDs to HTML templates used in this package.
var Templates = map[TemplateID]HtmlTemplate{
	TplLogin: {
		Filename:    "auth/login.html",
		DefaultText: PAGEDATA_LOGIN,
	},
	TplApprove: {
		Filename:    "auth/approve.html",
		DefaultText: PAGEDATA_APPROVE,
	},
	TplKiosk: {
		Filename:    "auth/kiosk.html",
		DefaultText: PAGEDATA_KIOSK,
	},
	TplDelete: {
		Filename:    "auth/delete.html",
		DefaultText: PAGEDATA_DELETE,
	},
	TplAckLogin: {
		Filename:    "auth/ack_login.html",
		DefaultText: PAGEDATA_ACK_LOGIN,
	},
	TplAckApprove: {
		Filename:    "auth/ack_approve.html",
		DefaultText: PAGEDATA_ACK_APPROVE,
	},
	TplAckRemove: {
		Filename:    "auth/ack_remove.html",
		DefaultText: PAGEDATA_ACK_REMOVE,
	},
	TplMailLogin: {
		Filename:    "auth/mail_login.html",
		DefaultText: MAILDATA_LOGIN,
	},
	TplMailApprove: {
		Filename:    "auth/mail_approve.html",
		DefaultText: MAILDATA_APPROVE,
	},
}

// This page is shown to any non-logged in user when they try to access a protected
// resource. You can replace this page with your own by putting a file called
// `login.html` in the `auth` subdirectory of your website root.
const PAGEDATA_LOGIN = `<!DOCTYPE html>
<html lang="en">
<head>
    <title>Login to the site</title>
</head>
<body>
<h1>You must login to see the contents</h1>
<form action="/auth/login" method="post">
    <p>
        <label for="email">Email</label>
        <input type="text" id="email" name="email" placeholder="you@example.com" />
        <input type="submit" name="submit" value="Get login link">
    </p>
</form>
</body>
</html>
`

// This page is shown to a website administrator when they follow a link in an e-mail
// to approve or reject a new user. You can replace this page with your own by putting
// a file called `approve.html` in the `auth` subdirectory of your website root.
//
// When supplying your own template, take care to include the fields {{.User}} and
// {{.EncEmail}} as shown below.
const PAGEDATA_APPROVE = `<!DOCTYPE html>
<html lang="en">
<head>
	<title>Auth-by-email: New user approval</title>
</head>
<body>
	<p>Hi administrator,</p>
	<p>Would you like to allow {{.User}} to access this website?</p>
	<form method="post" action="/auth/approve">
	<p>
		<input type="hidden" name="email" value="{{.EncEmail}}" />
		<input type="radio" name="action" value="approve" id="action-approve" />
			<label for="action-approve">Yes, approve</label> <br />
		<input type="radio" name="action" value="revoke"  id="action-revoke" />
			<label for="action-revoke">No, revoke</label> <br />
		<input type="submit" value="Submit" />
	</p>
	</form>
	<p>You can always revisit this page from your e-mail to change your decision.</p>
</body>
</html>
`

// This page is shown to a user when they log in using a link that was created on
// another device than the one they're on. This may happen if they are e.g. in an
// internet kiosk, but receive mail on their phone.
//
// The user is asked whether they want to log in the "remote" (kiosk) computer.
//
// When supplying your own template, take care to include the fields {{.Browser}}
// and {{.Cookie}} as shown below.
const PAGEDATA_KIOSK = `<!DOCTYPE html>
<html lang="en">
<head>
	<title>Auth-by-email: Remote log-in</title>
</head>
<body>
	<p>Hi,</p>
	<p>You are logging in using a link created on another device:</p>
	<p style="margin-left: 10px;">{{.Browser}}</p>
	<p>If you recognise this device, and would like to log it in as well, you may indicate so below.</p>
	<form method="post" action="/auth/welcome">
	<p>
		<input type="hidden" name="kioskCookie" value="{{.Cookie}}" />
		<input type="radio" name="action" value="revoke" id="action-revoke" />
			<label for="action-revoke">Just log in on this device</label> <br />
		<input type="radio" name="action" value="approve"  id="action-approve" />
			<label for="action-approve">I recognise the other device, log it in as well</label> <br />
		<input type="submit" value="Submit" />
	</p>
	</form>
</body>
</html>
`

// This page is shown to a user when they visit the /auth/delete endpoint with a GET request.
// It should ask them if they're sure.
const PAGEDATA_DELETE = `<!DOCTYPE html>
<html lang="en">
<head>
	<title>Auth-by-email: Delete account</title>
</head>
<body>
	<p>Are you sure you wish to delete your account?</p>
	<p>You will have to be re-approved if you want to log back in after this.</p>
	<form method="post" action="/auth/delete">
	<p><input type="submit" value="Yes" /></p>
	</form>
</body>
</html>
`

// This page is shown to any non-logged in user when they log in by entering their e-mail
// address, and are recognised as an existing user. You can replace this page with your own
// by putting a file called `ack_login.html` in the `auth` subdirectory of your website root.
const PAGEDATA_ACK_LOGIN = `<!DOCTYPE html>
<html lang="en">
<head>
	<title>Auth-by-email: You have been sent a log-in link</title>
	<meta http-equiv="refresh" content="30; url=/">
</head>
<body>
	<p>If and when you are given access, you will receive e-mail.</p>
</body>
</html>
`

// This page is shown to an administrator when they approve a user (by filling out the form in the
// `approve` template. You can replace this page with your own by putting a file called
// `ack_approve.html` in the `auth` subdirectory of your website root.
const PAGEDATA_ACK_APPROVE = `<!DOCTYPE html>
<html lang="en">
<head>
	<title>Auth-by-email: User approved</title>
</head>
<body>
	<p>User has been added, and has been sent a log-in e-mail.</p>
</body>
</html>
`

// This page is shown to an administrator when they reject or delete a user (by filling out the
// form in the `approve` template. You can replace this page with your own by putting a file called
// `ack_remove.html` in the `auth` subdirectory of your website root.
const PAGEDATA_ACK_REMOVE = `<!DOCTYPE html>
<html lang="en">
<head>
	<title>Auth-by-email: User removed</title>
</head>
<body>
	<p>User has been deleted.</p>
</body>
</html>
`

// This is an e-mail sent to a user that wishes to log in. You can replace this page with your own
// by putting a file called `mail_login.html` in the `auth` subdirectory of your website root.
//
// When supplying your own template, take care to include the fields {{.User}}, {{.SiteName}} and
// {{.Link}} as shown below. Be mindful of the fact that many e-mail clients block external resources.
const MAILDATA_LOGIN = `<!DOCTYPE html>
<html lang="en">
    <head>
    </head>
    <body>
        <p>Hi {{.User}},</p>
        <p>You requested a log-in link to {{.SiteName}}. Please click the following link to log in:<br />
        {{.Link}}</p>
        <p>Kind regards,</p>
        <p>{{.SiteName}} administration</p>
    </body>
</html>
`

// This is an e-mail sent to an administrator when a new user wants to log in. You can replace this
// page with your own by putting a file called `mail_login.html` in the `auth` subdirectory of your
// website root.
//
// When supplying your own template, take care to include the fields {{.Admin}}, {{.User}},
// {{.SiteName}} and {{.Link}} as shown below. Be mindful of the fact that many e-mail clients block
// external resources.
const MAILDATA_APPROVE = `<!DOCTYPE html>
<html lang="en">
    <head>
    </head>
    <body>
        <p>Hi {{.Admin}},</p>
        <p>A new user, {{.User}}, requested permission to log in to {{.SiteName}}. Please click the following link to approve or reject this request:<br />
        {{.Link}}</p>
        <p>You may also use this link at any time to revoke this user's access to {{.SiteName}}.</p>
        <p>Kind regards,</p>
        <p>{{.SiteName}} administration</p>
    </body>
</html>
`
