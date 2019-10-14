package main

import (
	"github.com/mholt/caddy/caddy/caddymain"
	"github.com/mholt/caddy/caddyhttp/httpserver"

	// plug in plugins here, for example:
	_ "github.com/TNO/auth-by-email/auth-by-email"
)

func main() {
	// optional: disable telemetry
	// caddymain.EnableTelemetry = false

	// We register our plugin's config directive at the end of the list of directives.
	//
	// This is supposed to be "dev only", but no stable way is provided to deploy a plugin
	// short of editing the file yourself in $GOROOT/pkg every time you update anything.
	//
	// We believe this site-specific main() function, as opposed to the plugin repository,
	// is an appropriate place for this.
	//
	// Currently, this site forwards requests to a subdirectory to a different host using
	// httpserver's proxy directive. These should still be authenticated, so we place our
	// plugin before "proxy".
	httpserver.RegisterDevDirective("authbyemail", "proxy")

	// Start the server.
	caddymain.Run()
}
