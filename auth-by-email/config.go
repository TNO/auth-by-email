package authbyemail

import (
	"fmt"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"strconv"
	"strings"
	"time"
)

// The Config type contains parsed configuration information from the Caddyfile.
type Config struct {
	Admins           []*EmailAddr
	WhitelistDomains []string
	FilesystemRoot   string
	Database         string
	UnprotectedPaths []string
	Redirect         string
	CookieValidity   time.Duration
	SiteName         string
	SiteURL          string
	MailerFrom       *EmailAddr
}

// newConfig returns a Config with default values. Mandatory parameters may
// not be initialized, but for optional parameters, we provide sane defaults.
func newConfig() *Config {
	return &Config{
		CookieValidity: time.Duration(30*24) * time.Hour,
		Redirect:       "/",
	}
}

// NewConfigFromCaddy parses the caddyfile, and populates a new Config with
// values found there. It returns an error if these values are erroneous, or
// if mandatory parameters were not given.
func NewConfigFromCaddy(c *caddy.Controller) (*Config, error) {
	config := newConfig()

	// Initialise options we can find out by ourselves
	config.FilesystemRoot = httpserver.GetConfig(c).Root
	config.SiteURL = httpserver.GetConfig(c).Addr.String()

	// Check that mandatory parameters were found
	if config.FilesystemRoot == "" {
		return nil, c.Err("Error finding out the filesystem root from Caddy")
	}
	if config.SiteURL == "" {
		return nil, c.Err("Error finding out the site URL from Caddy")
	}

	// Process options from the Caddyfile
	c.Next() // Skip "authbyemail" literal

	if len(c.RemainingArgs()) > 1 {
		return nil, c.Err("Unexpected `" + c.Val() + "` after `authbyemail` keyword. Open a block {} instead.")
	}

	for c.NextBlock() {
		parameter := c.Val()
		args := c.RemainingArgs()

		switch parameter {

		case "admin":
			if len(args) == 0 {
				return nil, c.Err("No admin e-mail addresses given after `admin` keyword. Please give at least one")
			}
			config.Admins = make([]*EmailAddr, len(args))
			for i, str := range args {
				email, err := NewEmailAddrFromString(str)
				if err != nil {
					return nil, c.Err("Could not parse e-mail address " + str)
				}
				config.Admins[i] = email
			}

		case "whitelistdomains":
			if len(args) == 0 {
				return nil, c.Err("No domain names given after `whitelistdomains` keyword. Please give at least one")
			}
			config.WhitelistDomains = args

		case "sitename":
			if len(args) == 0 {
				return nil, c.Err("No name given after `sitename` keyword. Please give one")
			}
			config.SiteName = strings.Join(args, " ")

		case "database":
			if len(args) != 1 {
				return nil, c.Err("Please give one (1) database filename after 'database'")
			}
			config.Database = args[0]

		case "unprotected":
			if len(args) == 0 {
				return nil, c.Err("No paths given after `unprotected` keyword. Please give at least one")
			}
			config.UnprotectedPaths = args

		case "redirect":
			if len(args) != 1 {
				return nil, c.Err("Please give one (1) redirect location after 'redirect'")
			}
			config.Redirect = args[0]

		case "cookievalidity":
			if len(args) != 1 {
				return nil, c.Err("Please give one (1) amount of seconds after 'cookievalidity'")
			}
			if validity, err := strconv.ParseUint(args[0], 10, 32); err != nil {
				return nil, c.Err(fmt.Sprintf("Unable to convert you argument to cookievalidity (%v) to an integer; %v", args[0], err))
			} else if int(validity) <= 0 {
				return nil, c.Err("Your argument to cookievalidity was not positive when converted to a machine-sized integer")
			} else {
				config.CookieValidity = time.Duration(validity) * time.Second
			}

		case "mailerfrom":
			if len(args) != 1 {
				return nil, c.Err("Please give one (1) e-mail address after 'mailerfrom'")
			}
			email, err := NewEmailAddrFromString(args[0])
			if err != nil {
				return nil, c.Err("Could not parse e-mail address " + args[0])
			}
			config.MailerFrom = email

		default:
			return nil, c.Err("Unknown parameter in `authbyemail` block: " + parameter)
		}
	}

	// Check that mandatory parameters were given
	if config.SiteName == "" {
		return nil, c.Err("No SiteName was given in the Caddyfile.")
	}
	if config.MailerFrom == nil {
		return nil, c.Err("No MailerFrom was given in the Caddyfile.")
	}

	return config, nil
}

// The helper function adminEmailFromUserEmail returns the admin belonging
// to the user's domain. If there is only one admin, that one is always given.
// Else, if there is no admin for this user, nil is returned
func (c *Config) adminEmailFromUserEmail(e *EmailAddr) *EmailAddr {
	if len(c.Admins) == 1 {
		return c.Admins[0]
	}
	for _, ad := range c.Admins {
		if ad.Domain == e.Domain {
			return ad
		}
	}
	return nil
}

// The helper function IsDomainWhitelisted checks whether the given domain
// is whitelisted by checking all members of WhitelistDomains
func (c *Config) IsDomainWhitelisted(domain string) bool {
	for _, whitelisted_domain := range c.WhitelistDomains {
		if whitelisted_domain == domain {
			return true
		}
	}
	return false
}
