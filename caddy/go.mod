module caddy

go 1.14

require (
	github.com/TNO/auth-by-email/auth-by-email v0.0.0
	github.com/caddyserver/caddy v1.0.5
	github.com/onsi/ginkgo v1.8.0 // indirect
	github.com/onsi/gomega v1.5.0 // indirect
)

replace github.com/TNO/auth-by-email/auth-by-email v0.0.0 => ../auth-by-email
