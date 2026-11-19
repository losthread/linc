package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// generateAESKey returns a random AES-256 key.
func generateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// encryptPrivateKey encrypts an Ed25519 private key with AES-GCM.
func encryptPrivateKey(key []byte, privateKey ed25519.PrivateKey) ([]byte, []byte, error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("identity key must be 32 bytes")
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
	return aead.Seal(nil, nonce, privateKey, nil), nonce, nil
}

// decryptPrivateKey decrypts an AES-GCM encrypted Ed25519 private key.
func decryptPrivateKey(key, nonce, ciphertext []byte) (ed25519.PrivateKey, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("identity key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("identity has invalid nonce")
	}
	privateKey, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("identity private key cannot be decrypted")
	}
	return ed25519.PrivateKey(privateKey), nil
}

// validateEncryptedIdentity verifies encrypted key material and its public identity.
func validateEncryptedIdentity(key, nonce, ciphertext, publicKey, peerID []byte) error {
	privateKey, err := decryptPrivateKey(key, nonce, ciphertext)
	if err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize || subtle.ConstantTimeCompare(privateKey.Public().(ed25519.PublicKey), publicKey) != 1 {
		return fmt.Errorf("public key does not match private key")
	}
	derivedPeerID := sha256.Sum256(publicKey)
	if len(peerID) != sha256.Size || subtle.ConstantTimeCompare(derivedPeerID[:], peerID) != 1 {
		return fmt.Errorf("peer ID does not match public key")
	}
	return nil
}
