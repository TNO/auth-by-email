package authbyemail

import (
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"
)

func TestDatabase(t *testing.T) {
	sql := testSetup()
	t.Run("Disk backed db", func(t *testing.T) { databaseTests(t, sql) })
	testTeardown(sql)

	t.Run("Map based db", func(t *testing.T) { databaseTests(t, NewMapBasedDatabase()) })
}

func testSetup() *DiskBackedDatabase {
	os.Remove("/tmp/abe_test_db")
	c := newConfig()
	c.Database = "/tmp/abe_test_db"
	return NewDiskBackedDatabase(c, log.New(ioutil.Discard, "(AuthByEmail) ", log.LstdFlags))
}

func testTeardown(db *DiskBackedDatabase) {
	db.db.Close()
	os.Remove("/tmp/abe_test_db")
}

func databaseTests(t *testing.T, db Database) {
	userID := UserID("test")

	t.Run("Add user", func(t *testing.T) {
		db.AddUser(userID)
		if !db.IsKnownUser(userID) {
			t.Error("User does not exist after being added")
		}

		// Adding a second time makes no sense, but should not panic
		db.AddUser(userID)

		db.DelUser(userID)
	})

	t.Run("Link token (properly)", func(t *testing.T) {
		db.AddUser(userID)

		proper := LinkToken{UserID: userID, CorrespondingCookie: "abc"}
		l, err := db.NewLinkToken(proper, time.Hour)
		lt := db.GetLinkToken(l)
		if err != nil || lt == nil || *lt != proper {
			t.Errorf("Link token in database does not match what was inserted, got %#v, expected %#v, error %v",
				lt,
				proper,
				err,
			)
		}

		db.DelUser(userID)
	})

	t.Run("Link token (erroneously)", func(t *testing.T) {
		lt := db.GetLinkToken("does not exist")
		if lt != nil {
			t.Errorf("Got non-existent link token from database, got %#v, expected nil", lt)
		}

		lt = db.GetLinkToken("does not exist, but is long enough to be encrypted data")
		if lt != nil {
			t.Errorf("Got non-existent link token from database, got %#v, expected nil", lt)
		}

		l, err := db.NewLinkToken(LinkToken{UserID: UserID("def"), CorrespondingCookie: "abc"}, time.Hour)
		lt = db.GetLinkToken(l)
		if err == nil || lt != nil {
			t.Errorf("Could get link token for non-existent user, got %#v with error %v, expected error", lt, err)
		}

		db.AddUser(userID)
		l, err = db.NewLinkToken(LinkToken{UserID: userID, CorrespondingCookie: "abc"}, 0)
		time.Sleep(time.Millisecond)
		lt = db.GetLinkToken(l)
		if lt != nil {
			t.Errorf("Could get expired link token, got %#v with error %v, expected error", lt, err)
		}
		db.DelUser(userID)
	})

	t.Run("Cookie token (properly)", func(t *testing.T) {
		db.AddUser(userID)

		proper := CookieToken{UserID: userID, IsValidated: true, BrowserContext: "cde"}
		c, err := db.NewCookieToken(proper)
		ct := db.GetCookieToken(c)
		if err != nil || ct == nil || *ct != proper {
			t.Errorf("Cookie token 1 in database does not match what was inserted, got %#v, expected %#v, error %v", ct, proper, err)
		}

		proper = CookieToken{UserID: userID, IsValidated: false, BrowserContext: "pqr"}
		c, err = db.NewCookieToken(proper)
		ct = db.GetCookieToken(c)
		if err != nil || ct == nil || *ct != proper {
			t.Errorf("Cookie token 2 in database does not match what was inserted, got %#v, expected %#v, error %v", ct, proper, err)
		}

		proper.IsValidated = true
		err = db.ValidateCookieToken(c)
		ct = db.GetCookieToken(c)
		if err != nil || ct == nil || *ct != proper {
			t.Errorf("Cookie token 3 (2, but validated) in database does not match what was inserted, got %#v, expected %#v, error %v", ct, proper, err)
		}

		err = db.DeleteCookieToken(c)
		ct = db.GetCookieToken(c)
		if err != nil || ct != nil {
			t.Errorf("Cookie token exists in database after deletion, got %#v, expected nil, error %v", ct, err)
		}

		db.DelUser(userID)
	})

	t.Run("Cookie token (erroneously)", func(t *testing.T) {
		ct := db.GetCookieToken("does not exist")
		if ct != nil {
			t.Errorf("Got non-existent cookie token from database, got %#v, expected nil", ct)
		}

		c, err := db.NewCookieToken(CookieToken{UserID: "jkl", IsValidated: true, BrowserContext: "cde"})
		ct = db.GetCookieToken(c)
		if err == nil || ct != nil {
			t.Errorf("Could get cookie token for non-existent user, got %#v with error %v, expected error", ct, err)
		}

		err = db.DeleteCookieToken("does not exist")
		if err == nil {
			t.Error("Was able to delete non-existent cookie")
		}

		err = db.ValidateCookieToken("does not exist")
		if err == nil {
			t.Errorf("Was able to validate non-existent cookie")
		}
	})

	t.Run("Delete user", func(t *testing.T) {
		db.AddUser(userID)
		l, _ := db.NewLinkToken(LinkToken{UserID: userID, CorrespondingCookie: "abc"}, time.Hour)
		c, _ := db.NewCookieToken(CookieToken{UserID: userID, IsValidated: true, BrowserContext: "cde"})
		err := db.DelUser(userID)
		if err != nil {
			t.Errorf("Deleting a user, got error %v", err)
		}

		if db.IsKnownUser(userID) {
			t.Error("User exists after being deleted")
		}
		if lt := db.GetLinkToken(l); lt != nil {
			t.Error("User link token exists after deletion of user")
		}
		if ct := db.GetCookieToken(c); ct != nil {
			t.Error("User cookie token exists after deletion of user")
		}

		err = db.DelUser(userID)
		if err == nil {
			t.Errorf("Deleting a non-existent user was ok, expected error")
		}
	})
}
