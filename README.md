# Authentication by e-mail

The goal of this project is to provide a web server module for Caddy that allows authenticated access to a website based on e-mail only.
That is, no account or password should be necessary for access.

## How does that work?

Suppose the administrator of the website `example.com` has used this Caddy module to protect their website.

During a first visit, you have to get yourself approved by the administrator.

1. You would like to visit `example.com`, which asks you to provide your e-mail address. You do so.
1. The administrator of `example.com` receives an e-mail, allowing them to grant or refuse access to you.
1. If they choose to grant access, you will get an e-mail with a unique login link.
1. Clicking the link sets a cookie in your browser that allows you to view `example.com` for e.g. a month.

When returning, the process is simplified. If you return from the same browser within a month of getting the cookie, you are immediately logged in as noted above.
Otherwise,

1. You visit `example.com`, which asks you to provide your e-mail address. You do so.
1. Noting that you have been approved already, the website immediately sends you an e-mail with a login link.
1. Clicking the link sets a cookie in your browser that allows you to view `example.com` for e.g. a month.

Additionally, we support the possibility of reading your e-mail on a device different from the one from which you are trying to log in (e.g. your phone and an internet kiosk respectively).
In that case,

1. You visit `example.com` on the kiosk computer, which asks you to provide your e-mail address. You do so.
1. The website immediately sends you an e-mail with a login link.
1. You open the link on your phone, which logs in your phone browser as usual.
1. The website notes that you are on a different device from the one you used in step 1, and asks if you would like to log that other device in as well.
1. If you click yes, and refresh the kiosk browser, you are logged in.

## Installing

We assume you have a working installation of `go`.

1. Set `export GO111MODULE=on` for your session. This project uses Go modules for dependency management.
1. After cloning the repository, go to the `caddy` subdirectory and type `go build`.
1. Check if the plugin was included in your newly built `caddy` by typing `./caddy -plugins | grep authbyemail` and confirming there is a line with `authbyemail`.

On success, move the newly generated file `caddy` to a sensible location on your `$PATH`.
Note that this new `caddy` should appear in your path before any other versions that do not include the plugin.
Verify with `which caddy` if needed.

Optionally, build the other tools by going to the `migrate` and `usermod` subdirectories and typing `go build`.

## Configuration

In your [Caddyfile](https://caddyserver.com/tutorial/caddyfile), you can use the directive `authbyemail` to supply configuration.
You may supply additional parameters as follows.
```
authbyemail {
    sitename My Cool Site
    admin sysadmin@example.com sysadmin@domain.org
    mailerfrom sysadmin@example.com
    database /var/caddy/database
    unprotected favicon.ico public/*
    redirect loggedin.html
    cookievalidity 1296000
}
```

<dl>
    <dt>sitename</dt>
    <dd>Specify the name of the website used in e.g. e-mails. This parameter is mandatory.</dd>
    <dt>admin</dt>
    <dd>Specify one or more e-mail addresses of site administrators. If you specify one, all user approval e-mails will be sent there. If you specify multiple (like in the example above), only the first admin belonging to the user's domain will be sent an approval e-mail, and none will be sent if the user does not belong to any admin's domain (so `sysadmin@domain.org` will be mailed if `lucy@domain.org` wants access, and `fred@acme.com` can not access the site because there is no admin for `acme.com`). If you specify no admins, no users can be approved.</dd>
    <dt>mailerfrom</dt>
    <dd>Specify one e-mail address from which e-mails should be sent. If you use an SMTP service, this will be the address linked to your account. This parameter is mandatory.</dd>
    <dt>database</dt>
    <dd>Specify one (existing) directory to use for a database of users. If you specify none, users will be forgotten when the server is reset.</dd>
    <dt>unprotected</dt>
    <dd>Specify any URIs (in lowercase) that can be accessed without logging in or having an account. If a URI ends in <code>*</code>, all URIs starting with that name will be unprotected.</dd>
    <dt>redirect</dt>
    <dd>After logging in by clicking an e-mail link, users are normally redirected to the site index. If you specify a URI here, they will be sent there instead.</dd>
    <dt>cookievalidity</dt>
    <dd>Specify the validity of the login cookie in seconds. Defaults to 30 days.</dd>
</dl>

### Custom template files
You can customise the log-in form and the administrator approval form by putting your own pages in your website root at `/auth/login.html` and `/auth/approve.html`. If these files exist, they will be served; otherwise, we will serve bare-bones forms for you. Likewise, `/auth/kiosk.html` may contain the template for a kiosk log-in confirmation.

You can also customise the acknowledgement pages served throughout the sign-up and log-in process. These should be placed at `/auth/ack_{login|signup|approve|remove}.html`.

If you would like to customise the e-mails sent by the system, you can also place your own files at `/auth/mail_{login|approve}.html`.

Some remarks are in order:
* All template files should be self-contained, or reference only external files in the "unprotected paths" configured in your Caddyfile. The e-mail templates should only use absolute references; please keep in mind that e-mail clients will probably block loading of external resources.
* Please insert tags to be replaced `{{like so}}`. See [templates.go](auth-by-email/templates.go) for examples of each template, and make sure to insert all necessary tags, otherwise your users may be unable to log in.

## Usage

This module defaults to using [SendInBlue](https://www.sendinblue.com/) for sending e-mails.
See [mailer.md](mailer.md) for guidance on writing your own mailer plugin.
If you will be using SendInBlue, make sure you have an account approved to send a small volume of e-mails.

Before running Caddy,

1. set the environment variable `AUTH_BY_EMAIL_KEY` with a 32-byte key for use in the cryptographic functions. It should be given as 64 hexadecimal digits, e.g. `AUTH_BY_EMAIL_KEY=1234abcd(...)6789cdef`;
1. if you are using the SendInBlue mailer (the default), set the environment variable `SENDINBLUE_API_KEY` with your SendInBlue api key as provided, e.g. `SENDINBLUE_API_KEY=xkeysib-1a3c-gHIj`.

### Pre-loading the database

It is also possible to use the bundled "usermod" tool to add users to the database, delete users, or log users out from their devices.
You can use it by creating a list of e-mail addresses in a file (for example `users.txt`), and running

```bash
usermod -mode add -database /path/to/database/used/in/Caddyfile < users.txt
usermod -mode delete -database /path/to/database/used/in/Caddyfile < users.txt
usermod -mode invalidate -database /path/to/database/used/in/Caddyfile < users.txt
```

respectively. Note that the variable `AUTH_BY_EMAIL_KEY` should also be set in order to use this command.

### Exporting and importing the database

Users in the database are stored only as a HMAC of their e-mail address, so exporting the list of users as a list of e-mail addresses is not possible.
Nevertheless, in case there is a need to transfer the database contents to e.g. a new format, the `migrate` tool can be used to export the table of user IDs as a text file, or to import such a text file into a new database.

Use the following commands to export (respectively import) the database to `fileofIDs.txt`.

```bash
migrate -out fileofIDs.txt -database /path/to/database/used/in/Caddyfile
migrate -in fileofIDs.txt -database /path/to/database/used/in/Caddyfile
```

Cookies are not preserved; all users will have to log in again if the server is initalised from a database created by this tool.
