package authbyemail

import (
	"database/sql"
	"errors"
	sqlite "github.com/mattn/go-sqlite3"
	"log"
	"os"
	"sync"
	"time"
)

// A DiskBackedDatabase is an interface to an SQL database, which is disk-backed and therefore
// survives restarts of the webserver. This is the "canonical" database to use; the alternative
// (MapBasedDatabase) is used when no path to a database file is given and is intended for
// debugging or trial usage.
type DiskBackedDatabase struct {
	db     *sql.DB
	logger *log.Logger
	config *Config
}

var databaseRegistration sync.Once

// NewDiskBackedDatabase opens or creates the database file, and sets up the database
// struct that interacts with it. If the database file does not exist, one is created.
// If creating the database file is not possible, this function panics.
func NewDiskBackedDatabase(config *Config, logger *log.Logger) *DiskBackedDatabase {

	databaseRegistration.Do(func() {
		// once.Do, which we use to call this function, swallows panics. Can't have that.
		defer func() {
			if err := recover(); err != nil {
				log.Fatalf("Panic caught during database driver registration, aborting.\n%v", err)
			}
		}()

		// The function used to check if a timestamp in the database is in not expired.
		timeNotInPast := func(timestamp string) bool {
			validUntil, err := time.Parse("2006-01-02 15:04:05.9999999-07:00", timestamp)
			if err != nil {
				logger.Println("Could not parse database time", timestamp, "; this will likely lead to no cookies being valid;", err)
				return false // Fail safely by considering the timestamp expired
			}
			return validUntil.After(time.Now())
		}

		// Register our driver with the custom timestamp function.
		sql.Register("sqlite3_custom", &sqlite.SQLiteDriver{
			ConnectHook: func(conn *sqlite.SQLiteConn) error {
				if err := conn.RegisterFunc("timeNotInPast", timeNotInPast, false); err != nil {
					return err
				}
				return nil
			},
		})
	})

	// Check if the database exists
	makeNew := false
	if file, err := os.Open(config.Database); err != nil {
		makeNew = true
	} else {
		file.Close()
	}

	// Open the database, creating it if it doesn't exist
	db, err := sql.Open("sqlite3_custom", config.Database)
	if err != nil {
		logger.Panicf("Could not initialize database: %v", err)
	}

	// If it didn't exist, create the tables we need
	if makeNew {
		sqlStmt := `
            create table Users (userID text not null primary key);
            delete from Users;
            create table Cookies (cookieToken text not null primary key, userID text not null, validUntil datetime, isValidated bool, browser text);
            delete from Cookies;`
		_, err = db.Exec(sqlStmt)
		if err != nil {
			logger.Panicf("Could not make new tables, %v", err)
		}
	}

	return &DiskBackedDatabase{db, logger, config}
}

// GetCookieContents returns a given cookie if it exists and has not expired, nil otherwise.
func (d *DiskBackedDatabase) GetCookieToken(cookieText string) *CookieToken {
	result, err := d.db.Query(`select userID, isValidated, browser from Cookies where cookieToken = ? and timeNotInPast(validUntil);`, cookieText)
	if err != nil {
		d.logger.Printf("Could not execute sql statement for CheckCookieToken, %v", err)
		return nil
	}
	defer result.Close()

	if !result.Next() {
		return nil
	}

	var userID string
	var browser string
	var validated bool
	if err = result.Scan(&userID, &validated, &browser); err != nil {
		return nil
	}

	return &CookieToken{
		UserID:         UserID(userID),
		IsValidated:    validated,
		BrowserContext: browser,
	}
}

// GetLinkToken checks if the given string corresponds to a sent email
// and returns the result. If it does correspond to a valid user, that user's ID and
// the parsed link token are returned as well.
func (d *DiskBackedDatabase) GetLinkToken(linkText string) *LinkToken {
	var link linkTokenInternal
	if err := CRYPTO.deserialize(linkText, &link); err != nil {
		return nil
	}

	if !(d.IsKnownUser(link.UserID) && link.ValidUntil.After(time.Now())) {
		return nil
	}

	return &link.LinkToken
}

// IsKnownUser checks whether the UserID is valid
func (d *DiskBackedDatabase) IsKnownUser(user UserID) bool {
	result, err := d.db.Query(`select * from Users where userID = ?;`, string(user))
	if err != nil {
		d.logger.Printf("Could not execute sql statement for IsKnownUser, %v", err)
		return false
	}
	defer result.Close()

	return result.Next()
}

// NewCookieToken makes a fresh cookie token for the given user
func (d *DiskBackedDatabase) NewCookieToken(cookieToken CookieToken) (string, error) {
	if !d.IsKnownUser(cookieToken.UserID) {
		d.printDebugInfo()
		return "", errors.New("Tried to add a cookie token for non-existent user")
	}

	d.deleteExpiredCookies()

	newToken := newRandom()

	_, err := d.db.Exec(`insert into Cookies(cookieToken, userID, validUntil, isValidated, browser) values(?, ?, ?, ?, ?);`,
		newToken,
		string(cookieToken.UserID),
		time.Now().Add(d.config.CookieValidity),
		cookieToken.IsValidated,
		cookieToken.BrowserContext)

	if err != nil {
		return "", err
	}

	return newToken, nil
}

// ValidateCookieToken validates a cookie matching the given token
func (d *DiskBackedDatabase) ValidateCookieToken(cookieToken string) error {
	result, err := d.db.Exec(`update Cookies set isValidated = ? where cookieToken = ?;`,
		true,
		cookieToken)

	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows == 0 {
		return errors.New("ValidateCookietoken: No such cookie found in database")
	}

	return nil
}

// DeleteCookieToken validates a cookie matching the given token
func (d *DiskBackedDatabase) DeleteCookieToken(cookieToken string) error {
	result, err := d.db.Exec(`delete from Cookies where cookieToken = ?;`, cookieToken)

	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows == 0 {
		return errors.New("DeleteCookietoken: No such cookie found in database")
	}

	return nil
}

// NewLinkToken makes a fresh link token for the given user
func (d *DiskBackedDatabase) NewLinkToken(linkToken LinkToken, validityPeriod time.Duration) (string, error) {
	if !d.IsKnownUser(linkToken.UserID) {
		d.printDebugInfo()
		return "", errors.New("Tried to add a link token for non-existent user")
	}

	link := linkTokenInternal{
		LinkToken:  linkToken,
		ValidUntil: time.Now().Add(validityPeriod),
	}

	return CRYPTO.serialize(link), nil
}

// AddUser adds the given user to the database
func (d *DiskBackedDatabase) AddUser(user UserID) {
	if d.IsKnownUser(user) {
		d.logger.Printf("Tried to add existing user %v", user)
		return
	}

	d.db.Exec(`insert into Users(userID) values(?);`, string(user))
}

// DelUser removes a user from the database. Tokens corresponding to a non-existent user
// are invalid; if you re-add a user, tokens that were valid before deletion will become
// valid once more.
func (d *DiskBackedDatabase) DelUser(user UserID) error {
	if !d.IsKnownUser(user) {
		d.printDebugInfo()
		return errors.New("Tried to delete a non-existent user")
	}

	if _, err := d.db.Exec(`delete from Users where userID = ?;`, string(user)); err != nil {
		return err
	}
	if _, err := d.db.Exec(`delete from Cookies where userID = ?;`, string(user)); err != nil {
		return err
	}

	return nil
}

func (d *DiskBackedDatabase) printDebugInfo() {
	d.logger.Println("Dumping database")

	result, err := d.db.Query(`select * from Users;`)
	if err != nil {
		d.logger.Println("Can not get Users!", err)
		return
	}
	for result.Next() {
		var userID string
		if err = result.Scan(&userID); err != nil {
			d.logger.Print("Error getting record,", err)
			continue
		}
		d.logger.Printf("USERS uid %v", userID)
	}

	result, err = d.db.Query(`select * from Cookies;`)
	if err != nil {
		d.logger.Println("Can not get Cookies!", err)
		return
	}
	for result.Next() {
		var userID, cookieToken, browser string
		var validUntil time.Time
		var isValidated bool
		if err = result.Scan(&cookieToken, &userID, &validUntil, &isValidated, &browser); err != nil {
			d.logger.Print("Error getting record,", err)
			continue
		}
		d.logger.Printf("COOKIES uid %v cookie %v validity %v (%v) browser %v", userID, cookieToken, validUntil, isValidated, browser)
	}

	d.logger.Println("End of database dump")
}

func (d *DiskBackedDatabase) deleteExpiredCookies() {
	result, err := d.db.Exec("delete from Cookies where not timeNotInPast(validUntil);")
	if err != nil {
		d.logger.Printf("Error deleting expired cookies: %v", err)
		return
	}
	if rowsAffected, err := result.RowsAffected(); err != nil {
		d.logger.Printf("Purged expired cookies from the database, but could not find out how many; %v", err)
	} else {
		d.logger.Printf("Purged %v expired cookies from the database", rowsAffected)
	}
}
