module migrate

go 1.12

require (
	github.com/TNO/auth-by-email/auth-by-email v0.0.0
	github.com/mattn/go-sqlite3 v1.10.0
)

replace github.com/TNO/auth-by-email/auth-by-email v0.0.0 => ../auth-by-email
