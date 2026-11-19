package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// TestGenerateAESKey verifies generated AES keys have the required size.
func TestGenerateAESKey(t *testing.T) {
	first, err := generateAESKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateAESKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 || len(second) != 32 {
		t.Fatalf("key lengths = %d, %d", len(first), len(second))
	}
	if string(first) == string(second) {
		t.Fatal("generated duplicate AES keys")
	}
}

// TestEncryptPrivateKeyRoundTrip verifies AES-GCM encryption and decryption.
func TestEncryptPrivateKeyRoundTrip(t *testing.T) {
	key, err := generateAESKey()
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := encryptPrivateKey(key, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := decryptPrivateKey(key, nonce, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(privateKey) {
		t.Fatal("decrypted private key differs")
	}
}

// TestDecryptPrivateKeyRejectsTampering verifies AES-GCM authentication failures.
func TestDecryptPrivateKeyRejectsTampering(t *testing.T) {
	key, err := generateAESKey()
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := encryptPrivateKey(key, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 1
	if _, err := decryptPrivateKey(key, nonce, ciphertext); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
	if _, _, err := encryptPrivateKey(key[:31], privateKey); err == nil {
		t.Fatal("short AES key accepted")
	}
}

// TestValidateEncryptedIdentityRejectsMismatchedPeerID verifies identity binding.
func TestValidateEncryptedIdentityRejectsMismatchedPeerID(t *testing.T) {
	key, err := generateAESKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := encryptPrivateKey(key, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEncryptedIdentity(key, nonce, ciphertext, publicKey, make([]byte, 32)); err == nil {
		t.Fatal("mismatched peer ID accepted")
	}
}
