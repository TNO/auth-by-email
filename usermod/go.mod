module usermod

go 1.15

require github.com/TNO/auth-by-email/auth-by-email v0.0.0

replace github.com/TNO/auth-by-email/auth-by-email v0.0.0 => ../auth-by-email

replace github.com/mholt/certmagic => github.com/caddyserver/certmagic v0.8.0
