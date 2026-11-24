package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/nbd-wtf/go-nostr"
)

func generateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func encryptPrivateKey(key []byte, privateKey string) ([]byte, []byte, error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("identity encryption key must be 32 bytes")
	}
	if err := validatePrivateKey(privateKey); err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return aead.Seal(nil, nonce, []byte(privateKey), nil), nonce, nil
}

func decryptPrivateKey(key, nonce, ciphertext []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("identity encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != aead.NonceSize() {
		return "", fmt.Errorf("identity has invalid nonce")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("identity private key cannot be decrypted")
	}
	privateKey := string(plaintext)
	if err := validatePrivateKey(privateKey); err != nil {
		return "", fmt.Errorf("identity private key cannot be decrypted")
	}
	return privateKey, nil
}

func validatePrivateKey(privateKey string) error {
	if _, err := nostr.GetPublicKey(privateKey); err != nil {
		return fmt.Errorf("invalid Nostr private key: %w", err)
	}
	return nil
}

func validatePublicKey(publicKey string) error {
	if !nostr.IsValidPublicKey(publicKey) {
		return fmt.Errorf("invalid Nostr public key")
	}
	return nil
}

func validateEncryptedIdentity(key, nonce, ciphertext []byte, publicKey string) error {
	if err := validatePublicKey(publicKey); err != nil {
		return err
	}
	privateKey, err := decryptPrivateKey(key, nonce, ciphertext)
	if err != nil {
		return err
	}
	derivedPublicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(derivedPublicKey), []byte(publicKey)) != 1 {
		return fmt.Errorf("Nostr public key does not match private key")
	}
	return nil
}
