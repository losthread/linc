package identity

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	_ "modernc.org/sqlite"
)

func identityTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE identity (public_key TEXT PRIMARY KEY, username TEXT NOT NULL, encrypted_private_key BLOB NOT NULL, nonce BLOB NOT NULL)`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db
}

func identityKeyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "identity.key")
}

func TestCreateIdentityStoresNostrKey(t *testing.T) {
	db := identityTestDB(t)
	defer db.Close()
	keyPath := identityKeyPath(t)
	if err := CreateIdentity(db, "  Alice  ", keyPath); err != nil {
		t.Fatal(err)
	}
	value, err := GetIdentity(db)
	if err != nil {
		t.Fatal(err)
	}
	if value.Username != "Alice" || len(value.PublicKey) != 64 {
		t.Fatalf("identity = %+v", value)
	}
	npub, err := NPub(db)
	if err != nil {
		t.Fatal(err)
	}
	prefix, decoded, err := nip19.Decode(npub)
	if err != nil || prefix != "npub" || decoded != value.PublicKey {
		t.Fatalf("npub = %q, %v, %v", npub, decoded, err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyPath)
	if err != nil || len(key) != 32 || info.Mode().Perm() != 0o600 {
		t.Fatalf("key length/mode = %d/%#o, %v", len(key), info.Mode().Perm(), err)
	}
	var ciphertext, nonce []byte
	if err := db.QueryRow(`SELECT encrypted_private_key, nonce FROM identity`).Scan(&ciphertext, &nonce); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ciphertext), value.PublicKey) {
		t.Fatal("private key ciphertext contains public identity")
	}
	if err := validateEncryptedIdentity(key, nonce, ciphertext, value.PublicKey); err != nil {
		t.Fatal(err)
	}
}

func TestSignAndVerifyEvent(t *testing.T) {
	db := identityTestDB(t)
	defer db.Close()
	keyPath := identityKeyPath(t)
	if err := CreateIdentity(db, "Alice", keyPath); err != nil {
		t.Fatal(err)
	}
	event := nostr.Event{CreatedAt: nostr.Timestamp(time.Now().Unix()), Kind: 1, Content: "hello"}
	if err := SignEvent(db, keyPath, &event); err != nil {
		t.Fatal(err)
	}
	identity, _ := GetIdentity(db)
	if event.PubKey != identity.PublicKey {
		t.Fatal("event signer differs from canonical identity")
	}
	if err := VerifyEvent(event); err != nil {
		t.Fatal(err)
	}
	event.Content = "tampered"
	if err := VerifyEvent(event); err == nil {
		t.Fatal("tampered event verified")
	}
}

func TestUpdateDeleteAndExportImport(t *testing.T) {
	source := identityTestDB(t)
	defer source.Close()
	sourceKey := identityKeyPath(t)
	if err := CreateIdentity(source, "Alice", sourceKey); err != nil {
		t.Fatal(err)
	}
	if err := UpdateUsername(source, "  Bob  "); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "identity.json")
	if err := ExportIdentity(source, sourceKey, backupPath); err != nil {
		t.Fatal(err)
	}
	target := identityTestDB(t)
	defer target.Close()
	targetKey := identityKeyPath(t)
	if err := CreateIdentity(target, "Other", targetKey); err != nil {
		t.Fatal(err)
	}
	if err := ImportIdentity(target, targetKey, backupPath); err != nil {
		t.Fatal(err)
	}
	got, _ := GetIdentity(target)
	want, _ := GetIdentity(source)
	if got != want {
		t.Fatalf("imported identity = %+v, want %+v", got, want)
	}
	if err := DeleteIdentity(target, targetKey); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(targetKey); !os.IsNotExist(err) {
		t.Fatalf("key file remains: %v", err)
	}
}

func TestImportRejectsTamperedPublicKey(t *testing.T) {
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
	data, _ := os.ReadFile(backupPath)
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	otherPublicKey, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	value["nostr_public_key"] = otherPublicKey
	data, _ = json.Marshal(value)
	if err := os.WriteFile(backupPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ImportIdentity(db, keyPath, backupPath); err == nil {
		t.Fatal("tampered backup imported")
	}
}

func TestMigrateRemovesLegacyIdentityAndPreservesUsername(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE identity (peer_id BLOB PRIMARY KEY, username TEXT NOT NULL, public_key BLOB NOT NULL, encrypted_private_key BLOB NOT NULL, nonce BLOB NOT NULL); INSERT INTO identity VALUES (x'01', 'Alice', x'02', x'03', x'04')`); err != nil {
		t.Fatal(err)
	}
	keyPath := identityKeyPath(t)
	if err := Migrate(db, keyPath); err != nil {
		t.Fatal(err)
	}
	value, err := GetIdentity(db)
	if err != nil || value.Username != "Alice" || len(value.PublicKey) != 64 {
		t.Fatalf("migrated identity = %+v, %v", value, err)
	}
	columns, err := tableColumns(db, "identity")
	if err != nil {
		t.Fatal(err)
	}
	if columns["peer_id"] || columns["encryption_key"] || columns["salt"] {
		t.Fatalf("legacy columns remain: %+v", columns)
	}
}
