module caddy

go 1.12

require github.com/mholt/caddy v1.0.0

require github.com/TNO/auth-by-email/auth-by-email v0.0.0

replace github.com/TNO/auth-by-email/auth-by-email v0.0.0 => ../auth-by-email
