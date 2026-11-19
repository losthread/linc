// File: shared/identity/identity.go
// Description: Stores and updates the user's local identity details.
// Author: Parth Naik
//
// Package identity stores the user's local identity details.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Identity contains the public local identity fields.
type Identity struct {
	Username string `json:"username"`
	PeerID []byte `json:"peer_id"`
	PublicKey []byte `json:"public_key"`
}

// Migrate moves legacy database encryption keys to the local key file.
func Migrate(db *sql.DB, keyPath string) error {
	rows, err := db.Query(`PRAGMA table_info(identity)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var id, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&id, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return err
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !columns["encryption_key"] && !columns["salt"] {
		return nil
	}
	if columns["encryption_key"] {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM identity`).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			var identity Identity
			var ciphertext, nonce, key []byte
			if err := db.QueryRow(`SELECT username, peer_id, public_key, encrypted_private_key, nonce, encryption_key FROM identity LIMIT 1`).Scan(&identity.Username, &identity.PeerID, &identity.PublicKey, &ciphertext, &nonce, &key); err != nil {
				return err
			}
			storedKey, err := os.ReadFile(keyPath)
			if os.IsNotExist(err) {
				if len(key) != 32 {
					return fmt.Errorf("legacy identity has no valid encryption key")
				}
				if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(keyPath, key, 0o600); err != nil {
					return err
				}
				storedKey = key
			} else if err != nil {
				return err
			}
			if err := validateEncryptedIdentity(storedKey, nonce, ciphertext, identity.PublicKey, identity.PeerID); err != nil {
				return fmt.Errorf("legacy identity cannot be decrypted: %w", err)
			}
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE identity_new (peer_id BLOB PRIMARY KEY, username TEXT NOT NULL DEFAULT 'anonymous', public_key BLOB NOT NULL, encrypted_private_key BLOB NOT NULL DEFAULT x'', nonce BLOB NOT NULL DEFAULT x'')`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO identity_new (peer_id, username, public_key, encrypted_private_key, nonce) SELECT peer_id, username, public_key, encrypted_private_key, nonce FROM identity`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE identity`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE identity_new RENAME TO identity`); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateIdentity creates and stores a local identity.
func CreateIdentity(db *sql.DB, username, keyPath string) error {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM identity`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	key, err := generateAESKey()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	ciphertext, nonce, err := encryptPrivateKey(key, privateKey)
	if err != nil {
		return err
	}
	peerID := sha256.Sum256(publicKey)
	if _, err := db.Exec(`INSERT INTO identity (peer_id, username, public_key, encrypted_private_key, nonce) VALUES (?, ?, ?, ?, ?)`, peerID[:], username, publicKey, ciphertext, nonce); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	return nil
}

// GetIdentity returns the stored public identity.
func GetIdentity(db *sql.DB) (Identity, error) {
	var identity Identity
	err := db.QueryRow(`SELECT username, peer_id, public_key FROM identity LIMIT 1`).Scan(&identity.Username, &identity.PeerID, &identity.PublicKey)
	return identity, err
}

// UpdateUsername validates and stores a trimmed username.
func UpdateUsername(db *sql.DB, username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	result, err := db.Exec(`UPDATE identity SET username = ?`, username)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("identity not found")
	}
	return nil
}

// DeleteIdentity removes the stored identity and its local AES key.
func DeleteIdentity(db *sql.DB, keyPath string) error {
	result, err := db.Exec(`DELETE FROM identity`)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("identity not found")
	}
	if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// PublicKeyText returns the public key as hexadecimal text.
func PublicKeyText(db *sql.DB) (string, error) {
	identity, err := GetIdentity(db)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(identity.PublicKey), nil
}

// ExportIdentity writes a validated encrypted identity backup with owner-only permissions.
func ExportIdentity(db *sql.DB, keyPath, backupPath string) error {
	var value struct {
		Username string `json:"username"`
		PeerID []byte `json:"peer_id"`
		PublicKey []byte `json:"public_key"`
		EncryptedPrivateKey []byte `json:"encrypted_private_key"`
		EncryptionKey []byte `json:"encryption_key"`
		Nonce []byte `json:"nonce"`
	}
	if err := db.QueryRow(`SELECT username, peer_id, public_key, encrypted_private_key, nonce FROM identity LIMIT 1`).Scan(&value.Username, &value.PeerID, &value.PublicKey, &value.EncryptedPrivateKey, &value.Nonce); err != nil {
		return err
	}
	var err error
	if value.EncryptionKey, err = os.ReadFile(keyPath); err != nil {
		return err
	}
	if strings.TrimSpace(value.Username) == "" || len(value.EncryptionKey) != 32 || len(value.EncryptedPrivateKey) == 0 {
		return fmt.Errorf("identity has no valid key material")
	}
	if err := validateEncryptedIdentity(value.EncryptionKey, value.Nonce, value.EncryptedPrivateKey, value.PublicKey, value.PeerID); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(backupPath, data, 0o600)
}

// ImportIdentity validates an encrypted identity backup and replaces the local identity.
func ImportIdentity(db *sql.DB, keyPath, backupPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	var value struct {
		Username string `json:"username"`
		PeerID []byte `json:"peer_id"`
		PublicKey []byte `json:"public_key"`
		EncryptedPrivateKey []byte `json:"encrypted_private_key"`
		EncryptionKey []byte `json:"encryption_key"`
		Nonce []byte `json:"nonce"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if strings.TrimSpace(value.Username) == "" || len(value.EncryptionKey) != 32 || len(value.EncryptedPrivateKey) == 0 {
		return fmt.Errorf("invalid identity backup")
	}
	if err := validateEncryptedIdentity(value.EncryptionKey, value.Nonce, value.EncryptedPrivateKey, value.PublicKey, value.PeerID); err != nil {
		return fmt.Errorf("invalid identity backup: %w", err)
	}
	oldKey, oldKeyErr := os.ReadFile(keyPath)
	if oldKeyErr != nil && !os.IsNotExist(oldKeyErr) {
		return oldKeyErr
	}
	if err := os.WriteFile(keyPath, value.EncryptionKey, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err == nil {
		_, err = tx.Exec(`DELETE FROM identity`)
	}
	if err == nil {
		_, err = tx.Exec(`INSERT INTO identity (peer_id, username, public_key, encrypted_private_key, nonce) VALUES (?, ?, ?, ?, ?)`, value.PeerID, strings.TrimSpace(value.Username), value.PublicKey, value.EncryptedPrivateKey, value.Nonce)
	}
	if err == nil {
		err = tx.Commit()
	} else {
		_ = tx.Rollback()
	}
	if err != nil {
		if oldKeyErr == nil {
			_ = os.WriteFile(keyPath, oldKey, 0o600)
		} else {
			_ = os.Remove(keyPath)
		}
	}
	return err
}
