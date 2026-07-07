package crypto

// NoneBackend is the pass-through identity encryptor. It returns plaintext
// unchanged and contributes no suffix to key file names.
type NoneBackend struct{}

func (n *NoneBackend) Encrypt(plaintext []byte, _ string) ([]byte, error) {
	return plaintext, nil
}

func (n *NoneBackend) Suffix() string         { return "" }
func (n *NoneBackend) BackendName() string    { return "none" }
func (n *NoneBackend) RecipientsHash() string { return "" }
