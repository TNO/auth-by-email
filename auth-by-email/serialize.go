package authbyemail

// Serialize takes an object, serializes it and encrypts the result.
func (c *Crypto) serialize(token linkTokenInternal) string {
	return c.encrypt(string(token.MarshalBinary()))
}

// Deserialize takes a ciphertext produced by Serialize, decrypts it
// and fills the object pointed to by `returner` with the values recovered.
// (Returner should be a pointer!)
func (c *Crypto) deserialize(ciphertext string, returner *linkTokenInternal) error {
	// Decrypt the token
	serialized, err := c.decrypt(ciphertext)
	if err != nil {
		return err
	}

	return returner.UnmarshalBinary([]byte(serialized))
}
