// Copyright 2026 The go-crypto Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"bytes"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// rotatingKeyRing is a KeyRing whose backing entity set can be swapped
// between the point where ReadMessage snapshots it and the point where the
// signer is resolved. A correct implementation freezes the view once and
// serves every lookup of the same decryption transaction from that frozen
// generation.
type rotatingKeyRing struct {
	entities       EntityList
	generation     int
}

func (r *rotatingKeyRing) KeysById(id uint64) []Key {
	r.generation++
	return r.entities.KeysById(id)
}

func (r *rotatingKeyRing) KeysByIdUsage(id uint64, requiredUsage byte) []Key {
	r.generation++
	return r.entities.KeysByIdUsage(id, requiredUsage)
}

func (r *rotatingKeyRing) DecryptionKeys() []Key {
	r.generation++
	return r.entities.DecryptionKeys()
}

func newTestEntity(t *testing.T, name, email string) *Entity {
	t.Helper()
	config := &packet.Config{RSABits: 1024}
	entity, err := NewEntity(name, "", email, config)
	if err != nil {
		t.Fatalf("failed to create entity %s: %v", name, err)
	}
	return entity
}

func signAndEncryptForTest(t *testing.T, signer, recipient *Entity, plaintext string) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	w, err := Encrypt(buf, []*Entity{recipient}, signer, nil, nil)
	if err != nil {
		t.Fatalf("failed to create encrypted message: %v", err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		t.Fatalf("failed to write plaintext: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close encrypted message: %v", err)
	}
	return buf.Bytes()
}

func signOnlyForTest(t *testing.T, signer *Entity, plaintext string) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	w, err := Sign(buf, signer, nil, nil)
	if err != nil {
		t.Fatalf("failed to create signed message: %v", err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		t.Fatalf("failed to write plaintext: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close signed message: %v", err)
	}
	return buf.Bytes()
}

func detachedSignatureForTest(t *testing.T, signer *Entity, plaintext string) ([]byte, []byte) {
	t.Helper()
	message := []byte(plaintext)
	sigBuf := new(bytes.Buffer)
	if err := DetachSign(sigBuf, signer, bytes.NewReader(message), nil); err != nil {
		t.Fatalf("failed to create detached signature: %v", err)
	}
	return message, sigBuf.Bytes()
}

// TestKeyRingSnapshotCollidingKeyId verifies that when two entities expose a
// key with the same 64-bit key id, verification commits to the key that
// cryptographically verifies the signature instead of merely the first key
// returned by the keyring. Without the snapshot/candidate transaction the
// message would be attributed to the wrong entity.
func TestKeyRingSnapshotCollidingKeyId(t *testing.T) {
	alice := newTestEntity(t, "Alice", "alice@example.com")
	bob := newTestEntity(t, "Bob", "bob@example.com")

	// Force Bob's primary key into the same key id as Alice's primary key to
	// simulate a key-id collision across distinct entities.
	bob.PrimaryKey.KeyId = alice.PrimaryKey.KeyId
	if bytes.Equal(bob.PrimaryKey.Fingerprint, alice.PrimaryKey.Fingerprint) {
		t.Fatal("colliding key ids must still produce distinct fingerprints")
	}

	plaintext := "collision transaction\n"
	message := signOnlyForTest(t, alice, plaintext)

	// Bob is placed first so a naive "first key with the matching id" lookup
	// picks the wrong entity.
	keyring := EntityList{bob, alice}
	md, err := ReadMessage(bytes.NewReader(message), keyring, nil, nil)
	if err != nil {
		t.Fatalf("failed to read message: %v", err)
	}
	contents, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatalf("failed to read message body: %v", err)
	}
	if string(contents) != plaintext {
		t.Fatalf("bad plaintext: got %q want %q", contents, plaintext)
	}
	if md.SignatureError != nil {
		t.Fatalf("signature did not verify: %v", md.SignatureError)
	}
	if md.SignedBy == nil || md.SignedBy.Entity != alice {
		t.Fatalf("message attributed to the wrong entity: %+v", md.SignedBy)
	}
	if md.SignedBy.PublicKey != alice.PrimaryKey {
		t.Fatal("message must be attributed to Alice's actual signing key")
	}
}

// TestDetachedSignatureCollidingKeyId ensures detached signature
// verification also resolves the signer within one snapshot transaction and
// commits to the key that actually verifies.
func TestDetachedSignatureCollidingKeyId(t *testing.T) {
	alice := newTestEntity(t, "Alice Detached", "alice.detached@example.com")
	bob := newTestEntity(t, "Bob Detached", "bob.detached@example.com")
	bob.PrimaryKey.KeyId = alice.PrimaryKey.KeyId

	plaintext := "detached collision transaction\n"
	message, signature := detachedSignatureForTest(t, alice, plaintext)

	signer, err := CheckDetachedSignature(
		EntityList{bob, alice},
		bytes.NewReader(message),
		bytes.NewReader(signature),
		nil,
	)
	if err != nil {
		t.Fatalf("detached signature failed to verify: %v", err)
	}
	if signer != alice {
		t.Fatal("detached signature attributed to the wrong entity")
	}

	// The colliding entity alone must never verify Alice's signature.
	_, err = CheckDetachedSignature(
		EntityList{bob},
		bytes.NewReader(message),
		bytes.NewReader(signature),
		nil,
	)
	if err == nil {
		t.Fatal("foreign entity with colliding key id verified the signature")
	}
}

// TestKeyRingSnapshotFreezesEntityListGeneration reproduces the keyring
// retry / rotation scenario on an EntityList: a same-id subkey is added
// while a decryption transaction is in flight (inside the passphrase
// prompt). The signer reported in MessageDetails must still belong to the
// entity whose private key decrypted the message.
func TestKeyRingSnapshotFreezesEntityListGeneration(t *testing.T) {
	alice := newTestEntity(t, "Alice Rotation", "alice.rotation@example.com")
	bob := newTestEntity(t, "Bob Rotation", "bob.rotation@example.com")

	plaintext := "rotation transaction\n"
	// Write the message while Alice's private keys are still unlocked.
	message := signAndEncryptForTest(t, alice, alice, plaintext)

	// Bob receives an additional signing subkey whose key id collides with
	// Alice's signing primary key. A naive read that re-resolves the signer
	// after rotation would attribute Alice's message to Bob.
	if err := bob.AddSigningSubkey(nil); err != nil {
		t.Fatalf("failed to add signing subkey to Bob: %v", err)
	}
	collidingSubkey := &bob.Subkeys[len(bob.Subkeys)-1]
	collidingSubkey.PublicKey.KeyId = alice.PrimaryKey.KeyId
	collidingSubkey.PrivateKey.KeyId = alice.PrimaryKey.KeyId

	// Encrypt Alice's private key so the prompt callback becomes the retry
	// point at which the keyring can be rotated.
	if err := alice.PrivateKey.Encrypt([]byte("passphrase")); err != nil {
		t.Fatalf("failed to encrypt Alice's private key: %v", err)
	}
	for idx := range alice.Subkeys {
		if err := alice.Subkeys[idx].PrivateKey.Encrypt([]byte("passphrase")); err != nil {
			t.Fatalf("failed to encrypt Alice's subkey: %v", err)
		}
	}

	entities := EntityList{alice}
	prompt := func(keys []Key, symmetric bool) ([]byte, error) {
		// Rotation happens inside the decryption transaction, after the
		// snapshot has been taken but before signer resolution.
		entities = append(entities, bob)
		for _, key := range keys {
			if err := key.PrivateKey.Decrypt([]byte("passphrase")); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	md, err := ReadMessage(bytes.NewReader(message), entities, prompt, nil)
	if err != nil {
		t.Fatalf("failed to read message: %v", err)
	}

	contents, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatalf("failed to read message body: %v", err)
	}
	if string(contents) != plaintext {
		t.Fatalf("bad plaintext: got %q want %q", contents, plaintext)
	}
	if md.SignatureError != nil {
		t.Fatalf("signature did not verify: %v", md.SignatureError)
	}
	if md.SignedBy == nil || md.SignedBy.Entity != alice {
		t.Fatal("keyring rotation attributed the message to another entity")
	}
	if md.DecryptedWith.Entity != alice {
		t.Fatal("the decryption key must come from the snapshot's entity")
	}
}

// TestKeyRingSnapshotCustomKeyRing checks that a custom KeyRing keeps
// working through its own lookup methods and that the resolved identity
// stays consistent across the whole read.
func TestKeyRingSnapshotCustomKeyRing(t *testing.T) {
	alice := newTestEntity(t, "Alice Custom", "alice.custom@example.com")

	plaintext := "custom keyring transaction\n"
	message := signAndEncryptForTest(t, alice, alice, plaintext)

	keyring := &rotatingKeyRing{entities: EntityList{alice}}
	md, err := ReadMessage(bytes.NewReader(message), keyring, nil, nil)
	if err != nil {
		t.Fatalf("failed to read message: %v", err)
	}
	contents, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatalf("failed to read message body: %v", err)
	}
	if string(contents) != plaintext {
		t.Fatalf("bad plaintext: got %q want %q", contents, plaintext)
	}
	if md.SignatureError != nil {
		t.Fatalf("signature did not verify: %v", md.SignatureError)
	}
	if md.SignedBy == nil || md.SignedBy.Entity != alice {
		t.Fatalf("custom keyring message attributed wrongly: %+v", md.SignedBy)
	}
	if keyring.generation == 0 {
		t.Fatal("snapshot must probe the keyring through its public interface")
	}
}

// TestSnapshotKeyRingIsStable ensures two lookups performed against the
// snapshot return the same frozen keys even if the underlying EntityList is
// mutated in between, and that fingerprints participate in the filtering.
func TestSnapshotKeyRingIsStable(t *testing.T) {
	alice := newTestEntity(t, "Alice Snapshot", "alice.snapshot@example.com")
	bob := newTestEntity(t, "Bob Snapshot", "bob.snapshot@example.com")

	entities := EntityList{alice}
	snapshot := snapshotKeyRing(entities)

	first := snapshot.KeysById(alice.PrimaryKey.KeyId)
	if len(first) != 1 || first[0].Entity != alice {
		t.Fatalf("unexpected initial lookup result: %+v", first)
	}

	// Mutate the live keyring after the snapshot was taken.
	bob.PrimaryKey.KeyId = alice.PrimaryKey.KeyId
	entities = append(entities, bob)

	second := snapshot.KeysById(alice.PrimaryKey.KeyId)
	if len(second) != 1 || second[0].Entity != alice {
		t.Fatalf("snapshot observed a keyring mutation: %+v", second)
	}

	// Fingerprint filtering must reject the colliding key.
	filtered := signingKeysByIdUsage(snapshot, alice.PrimaryKey.KeyId, alice.PrimaryKey.Fingerprint, packet.KeyFlagSign)
	if len(filtered) != 1 || filtered[0].Entity != alice {
		t.Fatalf("fingerprint filtering returned the wrong key: %+v", filtered)
	}

	// A foreign fingerprint must not resolve any candidate.
	foreign := signingKeysByIdUsage(snapshot, alice.PrimaryKey.KeyId, bob.PrimaryKey.Fingerprint, packet.KeyFlagSign)
	if len(foreign) != 0 {
		t.Fatalf("foreign fingerprint resolved a candidate: %+v", foreign)
	}

	if snapshotKeyRing(nil) != nil {
		t.Fatal("snapshotting a nil keyring must return nil")
	}
}
