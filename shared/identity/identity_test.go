// File: shared/identity/identity_test.go
// Description: Tests local identity database operations.
// Author: Parth Naik

package identity

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// identityTestDB returns an in-memory database with the identity schema.
func identityTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE identity (peer_id BLOB PRIMARY KEY, username TEXT NOT NULL, public_key BLOB NOT NULL, encrypted_private_key BLOB NOT NULL, nonce BLOB NOT NULL)`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db
}

// identityKeyPath returns an isolated AES key path.
func identityKeyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "identity.key")
}

// TestCreateIdentityStoresEncryptedKey verifies creation and local key permissions.
func TestCreateIdentityStoresEncryptedKey(t *testing.T) {
	db := identityTestDB(t)
	defer db.Close()
	keyPath := identityKeyPath(t)
	if err := CreateIdentity(db, "  Alice  ", keyPath); err != nil {
		t.Fatal(err)
	}
	identity, err := GetIdentity(db)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Username != "Alice" {
		t.Fatalf("username = %q", identity.Username)
	}
	peerID := sha256.Sum256(identity.PublicKey)
	if string(peerID[:]) != string(identity.PeerID) {
		t.Fatal("peer ID does not match public key")
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 || info.Mode().Perm() != 0o600 {
		t.Fatalf("key length/mode = %d/%#o", len(key), info.Mode().Perm())
	}
	var ciphertext, nonce []byte
	if err := db.QueryRow(`SELECT encrypted_private_key, nonce FROM identity`).Scan(&ciphertext, &nonce); err != nil {
		t.Fatal(err)
	}
	if err := validateEncryptedIdentity(key, nonce, ciphertext, identity.PublicKey, identity.PeerID); err != nil {
		t.Fatal(err)
	}
}

// TestUpdateAndDeleteIdentity verifies identity mutation and removal.
func TestUpdateAndDeleteIdentity(t *testing.T) {
	db := identityTestDB(t)
	defer db.Close()
	keyPath := identityKeyPath(t)
	if err := CreateIdentity(db, "Alice", keyPath); err != nil {
		t.Fatal(err)
	}
	if err := UpdateUsername(db, "  Bob  "); err != nil {
		t.Fatal(err)
	}
	identity, err := GetIdentity(db)
	if err != nil || identity.Username != "Bob" {
		t.Fatalf("updated identity = %+v, %v", identity, err)
	}
	if err := UpdateUsername(db, " "); err == nil {
		t.Fatal("empty username accepted")
	}
	if err := DeleteIdentity(db, keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("key file remains: %v", err)
	}
	if _, err := GetIdentity(db); err == nil {
		t.Fatal("deleted identity returned")
	}
}

// TestExportImportIdentityRoundTrip verifies backup transfer across databases.
func TestExportImportIdentityRoundTrip(t *testing.T) {
	source := identityTestDB(t)
	defer source.Close()
	sourceKey := identityKeyPath(t)
	backupPath := filepath.Join(t.TempDir(), "identity.json")
	if err := CreateIdentity(source, "Alice", sourceKey); err != nil {
		t.Fatal(err)
	}
	if err := ExportIdentity(source, sourceKey, backupPath); err != nil {
		t.Fatal(err)
	}
	target := identityTestDB(t)
	defer target.Close()
	targetKey := identityKeyPath(t)
	if err := CreateIdentity(target, "Bob", targetKey); err != nil {
		t.Fatal(err)
	}
	if err := ImportIdentity(target, targetKey, backupPath); err != nil {
		t.Fatal(err)
	}
	got, err := GetIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	want, err := GetIdentity(source)
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != want.Username || string(got.PeerID) != string(want.PeerID) || string(got.PublicKey) != string(want.PublicKey) {
		t.Fatalf("imported identity = %+v, want %+v", got, want)
	}
	info, err := os.Stat(backupPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %#o, %v", info.Mode().Perm(), err)
	}
}

// TestImportIdentityRejectsTamperedBackup verifies identity validation before replacement.
func TestImportIdentityRejectsTamperedBackup(t *testing.T) {
	db := identityTestDB(t)
	defer db.Close()
	keyPath := identityKeyPath(t)
	backupPath := filepath.Join(t.TempDir(), "identity.json")
	if err := CreateIdentity(db, "Alice", keyPath); err != nil {
		t.Fatal(err)
	}
	if err := ExportIdentity(db, keyPath, backupPath); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	value["peer_id"] = "AQ=="
	data, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ImportIdentity(db, keyPath, backupPath); err == nil {
		t.Fatal("tampered backup imported")
	}
}
