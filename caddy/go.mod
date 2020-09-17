module caddy

go 1.15

require (
	github.com/TNO/auth-by-email/auth-by-email v0.0.0
	github.com/caddyserver/caddy v1.0.5
	github.com/gorilla/websocket v1.4.2 // indirect
)

replace github.com/TNO/auth-by-email/auth-by-email v0.0.0 => ../auth-by-email

replace github.com/mholt/certmagic => github.com/caddyserver/certmagic v0.8.0
