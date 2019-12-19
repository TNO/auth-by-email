package authbyemail

import (
	"testing"
	"time"
)

// Test correct usage
func TestLinkTokenMarshal(t *testing.T) {
	// Make a token and marshal it to bytes
	token := linkTokenInternal{
		LinkToken:  LinkToken{UserID: UserID("test"), CorrespondingCookie: "bap"},
		ValidUntil: time.Now(),
	}
	b := token.MarshalBinary()
	if len(b) == 0 {
		t.Error("Got empty token from Marshal")
	}
	// Make a different token, unmarshal bytes into it, see that it works
	newToken := linkTokenInternal{
		LinkToken:  LinkToken{UserID: UserID("other"), CorrespondingCookie: "foo"},
		ValidUntil: time.Now().Add(time.Hour),
	}
	err := newToken.UnmarshalBinary(b)
	if err != nil || newToken.LinkToken != token.LinkToken || !token.ValidUntil.Equal(newToken.ValidUntil) {
		t.Errorf("Unmarshalled token is not the same as the original, got %#v (time %v), wanted %#v (time %v), error %v",
			newToken, newToken.ValidUntil.String(), token, token.ValidUntil.String(), err)
	}

	// Unmarshal a minimal correct array of bytes
	err = token.UnmarshalBinary([]byte{0, 0, 0})
	if err != nil {
		t.Errorf("Could not unmarshal the empty token, %v", err)
	}

}

// Test incorrect or malicious usage of unmarshal
func TestLinkTokenUnmarshalGarbage(t *testing.T) {
	token := linkTokenInternal{}

	test := func(data []byte) {
		if nil == token.UnmarshalBinary(data) {
			t.Errorf("Was able to unmarshal %v, and got %#v", data, token)
		}
	}

	// nil
	test(nil)
	// empty
	test([]byte{})

	// not enough fields
	test([]byte{0})
	test([]byte{0, 0})

	// trailing data
	test([]byte{0, 0, 0, 0})

	// bad length of first token
	test([]byte{1, 0, 0})  // too short (~= not enough fields)
	test([]byte{10, 0, 0}) // way too short

	// bad length of second token
	test([]byte{0, 1, 0})  // too short (~= not enough fields)
	test([]byte{0, 10, 0}) // way too short

	// bad length of third token
	test([]byte{0, 0, 1})
	test([]byte{0, 0, 10, 0})
}
