module github.com/TNO/auth-by-email/auth-by-email

go 1.15

require (
	github.com/caddyserver/caddy v1.0.5
	github.com/cenkalti/backoff/v4 v4.0.2 // indirect
	github.com/go-acme/lego/v3 v3.9.0 // indirect
	github.com/google/uuid v1.1.2 // indirect
	github.com/klauspost/cpuid v1.3.1 // indirect
	github.com/lucas-clemente/quic-go v0.18.0 // indirect
	github.com/marten-seemann/qtls-go1-15 v0.1.1 // indirect
	github.com/mattn/go-sqlite3 v1.14.3
	github.com/mholt/certmagic v0.11.2 // indirect
	github.com/miekg/dns v1.1.31 // indirect
	github.com/onsi/ginkgo v1.14.1 // indirect
	golang.org/x/net v0.7.0
	google.golang.org/protobuf v1.25.0 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1 // indirect
)

replace github.com/mholt/certmagic => github.com/caddyserver/certmagic v0.8.0
