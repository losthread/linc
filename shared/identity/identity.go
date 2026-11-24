// Package identity manages the user's persistent Nostr identity and local profile.
package identity

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// Identity contains public Nostr identity data and the separate local profile name.
type Identity struct {
	Username  string `json:"username"`
	PublicKey string `json:"nostr_public_key"`
}

type backup struct {
	Username            string `json:"username"`
	PublicKey           string `json:"nostr_public_key"`
	EncryptedPrivateKey []byte `json:"encrypted_nostr_private_key"`
	EncryptionKey       []byte `json:"encryption_key"`
	Nonce               []byte `json:"nonce"`
}

// Migrate replaces the obsolete Ed25519/peer-ID schema with one Nostr identity.
// Existing usernames survive; incompatible legacy cryptographic identities do not.
func Migrate(db *sql.DB, keyPath string) error {
	columns, err := tableColumns(db, "identity")
	if err != nil {
		return err
	}
	if !columns["peer_id"] && columns["public_key"] {
		return nil
	}

	username := "anonymous"
	if columns["username"] {
		var stored string
		if err := db.QueryRow(`SELECT username FROM identity LIMIT 1`).Scan(&stored); err == nil && strings.TrimSpace(stored) != "" {
			username = strings.TrimSpace(stored)
		} else if err != nil && err != sql.ErrNoRows {
			return err
		}
	}
	// Legacy key material was committed historically; rotate the AES key with the identity.
	oldKey, oldKeyErr := os.ReadFile(keyPath)
	if oldKeyErr != nil && !os.IsNotExist(oldKeyErr) {
		return oldKeyErr
	}
	key, err := generateAESKey()
	if err != nil {
		return err
	}
	privateKey := nostr.GeneratePrivateKey()
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return err
	}
	ciphertext, nonce, err := encryptPrivateKey(key, privateKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		return err
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if oldKeyErr == nil {
			_ = os.WriteFile(keyPath, oldKey, 0o600)
		} else {
			_ = os.Remove(keyPath)
		}
	}()

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE identity_new (public_key TEXT PRIMARY KEY, username TEXT NOT NULL DEFAULT 'anonymous', encrypted_private_key BLOB NOT NULL, nonce BLOB NOT NULL)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO identity_new (public_key, username, encrypted_private_key, nonce) VALUES (?, ?, ?, ?)`, publicKey, username, ciphertext, nonce); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE identity`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE identity_new RENAME TO identity`); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func tableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var id, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&id, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns[name] = true
	}
	return columns, rows.Err()
}

// CreateIdentity creates a random persistent Nostr keypair when none exists.
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
	key, created, err := loadOrCreateEncryptionKey(keyPath)
	if err != nil {
		return err
	}
	privateKey := nostr.GeneratePrivateKey()
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return err
	}
	ciphertext, nonce, err := encryptPrivateKey(key, privateKey)
	if err != nil {
		return err
	}
	if _, err := db.Exec(`INSERT INTO identity (public_key, username, encrypted_private_key, nonce) VALUES (?, ?, ?, ?)`, publicKey, username, ciphertext, nonce); err != nil {
		if created {
			_ = os.Remove(keyPath)
		}
		return err
	}
	return nil
}

func loadOrCreateEncryptionKey(keyPath string) ([]byte, bool, error) {
	key, err := os.ReadFile(keyPath)
	if err == nil {
		if len(key) != 32 {
			return nil, false, fmt.Errorf("identity encryption key must be 32 bytes")
		}
		if err := os.Chmod(keyPath, 0o600); err != nil {
			return nil, false, err
		}
		return key, false, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, err
	}
	key, err = generateAESKey()
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// GetIdentity returns the canonical Nostr public key and local username.
func GetIdentity(db *sql.DB) (Identity, error) {
	var identity Identity
	err := db.QueryRow(`SELECT username, public_key FROM identity LIMIT 1`).Scan(&identity.Username, &identity.PublicKey)
	if err == nil {
		err = validatePublicKey(identity.PublicKey)
	}
	return identity, err
}

// UpdateUsername stores a local profile name without changing cryptographic identity.
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

// DeleteIdentity removes the Nostr identity and its separately stored AES key.
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

// NPub returns the canonical public identity in standard NIP-19 form.
func NPub(db *sql.DB) (string, error) {
	identity, err := GetIdentity(db)
	if err != nil {
		return "", err
	}
	return nip19.EncodePublicKey(identity.PublicKey)
}

// SignEvent signs a NIP-01 event with the persistent Nostr identity.
func SignEvent(db *sql.DB, keyPath string, event *nostr.Event) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}
	var publicKey string
	var ciphertext, nonce []byte
	if err := db.QueryRow(`SELECT public_key, encrypted_private_key, nonce FROM identity LIMIT 1`).Scan(&publicKey, &ciphertext, &nonce); err != nil {
		return err
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	if err := validateEncryptedIdentity(key, nonce, ciphertext, publicKey); err != nil {
		return err
	}
	privateKey, err := decryptPrivateKey(key, nonce, ciphertext)
	if err != nil {
		return err
	}
	return event.Sign(privateKey)
}

// VerifyEvent verifies both the NIP-01 event ID and BIP-340 Schnorr signature.
func VerifyEvent(event nostr.Event) error {
	if event.ID != event.GetID() {
		return fmt.Errorf("Nostr event ID does not match content")
	}
	valid, err := event.CheckSignature()
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("invalid Nostr event signature")
	}
	return nil
}

// ExportIdentity writes an owner-readable encrypted identity backup.
func ExportIdentity(db *sql.DB, keyPath, backupPath string) error {
	var value backup
	if err := db.QueryRow(`SELECT username, public_key, encrypted_private_key, nonce FROM identity LIMIT 1`).Scan(&value.Username, &value.PublicKey, &value.EncryptedPrivateKey, &value.Nonce); err != nil {
		return err
	}
	var err error
	if value.EncryptionKey, err = os.ReadFile(keyPath); err != nil {
		return err
	}
	if strings.TrimSpace(value.Username) == "" || len(value.EncryptionKey) != 32 || len(value.EncryptedPrivateKey) == 0 {
		return fmt.Errorf("identity has no valid key material")
	}
	if err := validateEncryptedIdentity(value.EncryptionKey, value.Nonce, value.EncryptedPrivateKey, value.PublicKey); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(backupPath, data, 0o600)
}

// ImportIdentity validates a Nostr identity backup before replacing local state.
func ImportIdentity(db *sql.DB, keyPath, backupPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	var value backup
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	value.Username = strings.TrimSpace(value.Username)
	if value.Username == "" || len(value.EncryptionKey) != 32 || len(value.EncryptedPrivateKey) == 0 {
		return fmt.Errorf("invalid identity backup")
	}
	if err := validateEncryptedIdentity(value.EncryptionKey, value.Nonce, value.EncryptedPrivateKey, value.PublicKey); err != nil {
		return fmt.Errorf("invalid identity backup: %w", err)
	}
	oldKey, oldKeyErr := os.ReadFile(keyPath)
	if oldKeyErr != nil && !os.IsNotExist(oldKeyErr) {
		return oldKeyErr
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, value.EncryptionKey, 0o600); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err == nil {
		_, err = tx.Exec(`DELETE FROM identity`)
	}
	if err == nil {
		_, err = tx.Exec(`INSERT INTO identity (public_key, username, encrypted_private_key, nonce) VALUES (?, ?, ?, ?)`, value.PublicKey, value.Username, value.EncryptedPrivateKey, value.Nonce)
	}
	if err == nil {
		err = tx.Commit()
	} else if tx != nil {
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
