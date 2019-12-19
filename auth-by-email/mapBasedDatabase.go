package authbyemail

import (
	"errors"
	"sync"
	"time"
)

// A database type for AuthByEmail that naively implements all functions of Database using maps.
// Not very fast or good, but useful as a first implementation, and as a guide for designing
// more mature databases.
//
// See DiskBasedDatabase for function-level documentation.
type MapBasedDatabase struct {
	writeMutex   sync.Mutex
	users        map[UserID]bool
	linkTokens   map[string]*linkTokenInternal
	cookieTokens map[string]*cookieTokenInternal
}

func NewMapBasedDatabase() *MapBasedDatabase {
	return &MapBasedDatabase{
		users:        make(map[UserID]bool),
		linkTokens:   make(map[string]*linkTokenInternal),
		cookieTokens: make(map[string]*cookieTokenInternal),
	}
}

func (m *MapBasedDatabase) GetCookieToken(cookieText string) *CookieToken {
	c, ok := m.cookieTokens[cookieText]
	if ok && c.ValidUntil.After(time.Now()) {
		return &c.CookieToken
	}
	return nil
}

func (m *MapBasedDatabase) GetLinkToken(linkText string) *LinkToken {
	l, ok := m.linkTokens[linkText]
	if ok && l.ValidUntil.After(time.Now()) {
		return &l.LinkToken
	}
	return nil
}

// IsKnownUser checks whether the UserID is valid
func (m *MapBasedDatabase) IsKnownUser(user UserID) bool {
	return m.users[user]
}

// NewCookieToken makes a fresh cookie token for the given user
// and saves it to the database
func (m *MapBasedDatabase) NewCookieToken(cookieToken CookieToken) (string, error) {
	if !m.IsKnownUser(cookieToken.UserID) {
		return "", errors.New("Tried to add a cookie token for non-existent user")
	}

	newToken := newRandom()

	m.writeMutex.Lock()
	defer m.writeMutex.Unlock()

	m.cookieTokens[newToken] = &cookieTokenInternal{
		CookieToken: cookieToken,
		ValidUntil:  time.Now().Add(30 * 24 * time.Hour),
	}
	return newToken, nil
}

// ValidateCookieToken validates a cookie matching the given token
func (m *MapBasedDatabase) ValidateCookieToken(cookieText string) error {
	if _, ok := m.cookieTokens[cookieText]; !ok {
		return errors.New("Tried to validate a non-existent cookie token")
	}
	m.cookieTokens[cookieText].IsValidated = true
	return nil
}

// DeleteCookieToken validates a cookie matching the given token
func (m *MapBasedDatabase) DeleteCookieToken(cookieText string) error {
	if _, ok := m.cookieTokens[cookieText]; !ok {
		return errors.New("Tried to delete a non-existent cookie token")
	}
	delete(m.cookieTokens, cookieText)
	return nil
}

// NewLinkToken makes a fresh link token for the given user
// and saves it to the database
func (m *MapBasedDatabase) NewLinkToken(linkToken LinkToken, validityPeriod time.Duration) (string, error) {
	if !m.IsKnownUser(linkToken.UserID) {
		return "", errors.New("Tried to add a link token for non-existent user")
	}

	newToken := newRandom()

	m.writeMutex.Lock()
	defer m.writeMutex.Unlock()

	m.linkTokens[newToken] = &linkTokenInternal{
		LinkToken:  linkToken,
		ValidUntil: time.Now().Add(validityPeriod),
	}
	return newToken, nil
}

// AddUser adds the given user to the database
func (m *MapBasedDatabase) AddUser(user UserID) {
	m.writeMutex.Lock()
	defer m.writeMutex.Unlock()

	m.users[user] = true
}

// DelUser removes a user from the database and invalidates all corresponding tokens
func (m *MapBasedDatabase) DelUser(user UserID) error {
	if !m.IsKnownUser(user) {
		return errors.New("Tried to delete a non-existent user")
	}

	m.writeMutex.Lock()
	defer m.writeMutex.Unlock()

	for key, token := range m.cookieTokens {
		if token.UserID == user {
			delete(m.cookieTokens, key)
		}
	}

	for key, token := range m.linkTokens {
		if token.UserID == user {
			delete(m.linkTokens, key)
		}
	}

	delete(m.users, user)
	return nil
}
