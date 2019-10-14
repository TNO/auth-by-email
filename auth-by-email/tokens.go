package authbyemail

import (
    "errors"
    "time"
)

// A LinkToken contains all the information in a valid e-mail link
type LinkToken struct {
    // UserID corresponding to this token.
    UserID UserID

    // Cookie token set on the browser from which this link was sent.
    CorrespondingCookie string
}

// A CookieToken contains all the information in a valid cookie
type CookieToken struct {
    // UserID corresponding to this token.
    UserID UserID

    // Whether this token has been validated (i.e. the user generating it can access the e-mail address belonging to UserID)
    IsValidated bool

    // Information about the browser to which this cookie was sent, for the user to identify the session later on.
    BrowserContext string
}

type linkTokenInternal struct {
    LinkToken
    ValidUntil time.Time
}

func (lt *linkTokenInternal) MarshalBinary() []byte {
    var component, representation []byte
    component = []byte(lt.UserID)
    representation = append(append(representation, byte(len(component))), component...)
    component = []byte(lt.CorrespondingCookie)
    representation = append(append(representation, byte(len(component))), component...)
    component, _ = lt.ValidUntil.MarshalBinary()
    representation = append(append(representation, byte(len(component))), component...)

    return representation
}

func (lt *linkTokenInternal) UnmarshalBinary(data []byte) error {
    // The user ID
    if len(data) == 0 || len(data) < int(data[0])+1 {
        return errors.New("Link token data too short for user ID")
    }
    lt.UserID = UserID(data[1 : int(data[0])+1])
    data = data[int(data[0])+1:]

    // The corresponding cookie
    if len(data) == 0 || len(data) < int(data[0])+1 {
        return errors.New("Link token data too short for cookie")
    }
    lt.CorrespondingCookie = string(data[1 : int(data[0])+1])
    data = data[int(data[0])+1:]

    // The expiry date
    if len(data) == 0 || len(data) < int(data[0])+1 {
        return errors.New("Link token data too short for expiry date")
    }
    if len(data) > int(data[0])+1 {
        return errors.New("Link token data too long for expiry date")
    }
    lt.ValidUntil.UnmarshalBinary(data[1 : int(data[0])+1])

    return nil
}

type cookieTokenInternal struct {
    CookieToken
    ValidUntil time.Time
}
