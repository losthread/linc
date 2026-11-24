package identity

import (
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func TestEncryptPrivateKeyRoundTrip(t *testing.T) {
	key, err := generateAESKey()
	if err != nil {
		t.Fatal(err)
	}
	privateKey := nostr.GeneratePrivateKey()
	ciphertext, nonce, err := encryptPrivateKey(key, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := decryptPrivateKey(key, nonce, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != privateKey {
		t.Fatal("decrypted private key differs")
	}

	ciphertext[0] ^= 1
	if _, err := decryptPrivateKey(key, nonce, ciphertext); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
}

func TestValidateEncryptedIdentityRejectsMismatchedPublicKey(t *testing.T) {
	key, err := generateAESKey()
	if err != nil {
		t.Fatal(err)
	}
	privateKey := nostr.GeneratePrivateKey()
	ciphertext, nonce, err := encryptPrivateKey(key, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	otherPublicKey, err := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEncryptedIdentity(key, nonce, ciphertext, otherPublicKey); err == nil {
		t.Fatal("mismatched Nostr public key accepted")
	}
}
