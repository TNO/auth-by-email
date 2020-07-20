// The goal of this project is to provide a web server module for Caddy that allows authenticated access to a website based on e-mail only.
// That is, no account or password should be necessary for access.
//
// See README.md for general usage information.
package authbyemail

import (
	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

// init is called at Caddy's startup, and registers our plugin
func init() {
	caddy.RegisterPlugin("authbyemail", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup initialises our plugin. This entails parsing our block in the
// Caddyfile, and then registering our handler as "http middleware".
func setup(c *caddy.Controller) error {
	config, err := NewConfigFromCaddy(c)
	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return NewHandler(next, config)
	})

	return nil
}
