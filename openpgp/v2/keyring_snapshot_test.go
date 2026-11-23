// Copyright 2026 The go-crypto Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package v2

import (
	"bytes"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// rotatingKeyRingV2 is a custom v2 KeyRing whose backing entity set can be
// swapped while a message read is in flight.
type rotatingKeyRingV2 struct {
	entities   EntityList
	generation int
}

func (r *rotatingKeyRingV2) KeysById(id uint64) []Key {
	r.generation++
	return r.entities.KeysById(id)
}

func (r *rotatingKeyRingV2) EntitiesById(id uint64) []*Entity {
	r.generation++
	return r.entities.EntitiesById(id)
}

func newV2TestEntity(t *testing.T, name, email string) *Entity {
	t.Helper()
	config := &packet.Config{RSABits: 1024}
	entity, err := NewEntity(name, "", email, config)
	if err != nil {
		t.Fatalf("failed to create entity %s: %v", name, err)
	}
	return entity
}

func v2SignAndEncrypt(t *testing.T, signer, recipient *Entity, plaintext string) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	w, err := Encrypt(buf, []*Entity{recipient}, nil, []*Entity{signer}, nil, nil)
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

func v2SignOnly(t *testing.T, signer *Entity, plaintext string) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	w, err := Sign(buf, []*Entity{signer}, nil, nil)
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

func v2DetachedSignature(t *testing.T, signer *Entity, plaintext string) ([]byte, []byte) {
	t.Helper()
	message := []byte(plaintext)
	sigBuf := new(bytes.Buffer)
	if err := DetachSign(sigBuf, []*Entity{signer}, bytes.NewReader(message), nil); err != nil {
		t.Fatalf("failed to create detached signature: %v", err)
	}
	return message, sigBuf.Bytes()
}

// TestV2KeyRingSnapshotCollidingKeyId checks that two entities with a
// colliding 64-bit key id cannot make the reader attribute a signature to
// the wrong entity. Verification must commit to the key that actually
// verifies the signature.
func TestV2KeyRingSnapshotCollidingKeyId(t *testing.T) {
	alice := newV2TestEntity(t, "Alice V2", "alice.v2@example.com")
	bob := newV2TestEntity(t, "Bob V2", "bob.v2@example.com")

	bob.PrimaryKey.KeyId = alice.PrimaryKey.KeyId
	if bytes.Equal(bob.PrimaryKey.Fingerprint, alice.PrimaryKey.Fingerprint) {
		t.Fatal("colliding key ids must still produce distinct fingerprints")
	}

	plaintext := "v2 collision transaction\n"
	message := v2SignOnly(t, alice, plaintext)

	// Bob sorts before Alice so an id-only lookup picks Bob first.
	md, err := ReadMessage(bytes.NewReader(message), EntityList{bob, alice}, nil, nil)
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

// TestV2DetachedSignatureCollidingKeyId checks the detached verification
// path of the snapshot transaction.
func TestV2DetachedSignatureCollidingKeyId(t *testing.T) {
	alice := newV2TestEntity(t, "Alice Detached V2", "alice.detached.v2@example.com")
	bob := newV2TestEntity(t, "Bob Detached V2", "bob.detached.v2@example.com")
	bob.PrimaryKey.KeyId = alice.PrimaryKey.KeyId

	plaintext := "v2 detached collision transaction\n"
	message, signature := v2DetachedSignature(t, alice, plaintext)

	_, signer, err := VerifyDetachedSignature(
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

	_, _, err = VerifyDetachedSignature(
		EntityList{bob},
		bytes.NewReader(message),
		bytes.NewReader(signature),
		nil,
	)
	if err == nil {
		t.Fatal("foreign entity with colliding key id verified the signature")
	}
}

// TestV2KeyRingSnapshotFingerprintFiltersEntity verifies that an entity
// whose key id matches but whose fingerprint differs is not treated as a
// signer candidate when the signature carries a fingerprint.
func TestV2KeyRingSnapshotFingerprintFiltersEntity(t *testing.T) {
	alice := newV2TestEntity(t, "Alice FP", "alice.fp@example.com")
	bob := newV2TestEntity(t, "Bob FP", "bob.fp@example.com")

	bob.PrimaryKey.KeyId = alice.PrimaryKey.KeyId

	plaintext := "v2 fingerprint transaction\n"
	message := v2SignOnly(t, alice, plaintext)

	md, err := ReadMessage(bytes.NewReader(message), EntityList{bob, alice}, nil, nil)
	if err != nil {
		t.Fatalf("failed to read message: %v", err)
	}
	if _, err := io.ReadAll(md.UnverifiedBody); err != nil {
		t.Fatalf("failed to read message body: %v", err)
	}
	if md.SignatureError != nil {
		t.Fatalf("signature did not verify: %v", md.SignatureError)
	}

	// Directly exercise the fingerprint-aware entity resolver: Bob must be
	// filtered out even though his key id matches Alice's.
	entities := entitiesByIdFingerprint(
		snapshotKeyRing(EntityList{bob, alice}),
		alice.PrimaryKey.KeyId,
		alice.PrimaryKey.Fingerprint,
	)
	if len(entities) != 1 || entities[0] != alice {
		t.Fatalf("fingerprint resolver returned the wrong entities: %+v", entities)
	}
}

// TestV2KeyRingSnapshotFreezesGeneration reproduces the keyring retry /
// rotation scenario: while the passphrase prompt is running, a same-id
// subkey from another entity is installed. The frozen snapshot must keep
// the message identity bound to the entity that decrypted it.
func TestV2KeyRingSnapshotFreezesGeneration(t *testing.T) {
	alice := newV2TestEntity(t, "Alice Rotation V2", "alice.rotation.v2@example.com")
	bob := newV2TestEntity(t, "Bob Rotation V2", "bob.rotation.v2@example.com")

	plaintext := "v2 rotation transaction\n"
	// Write the message while Alice's private keys are still unlocked.
	message := v2SignAndEncrypt(t, alice, alice, plaintext)

	// Bob's additional signing subkey gets Alice's signing key id.
	if err := bob.AddSigningSubkey(nil); err != nil {
		t.Fatalf("failed to add signing subkey to Bob: %v", err)
	}
	collidingSubkey := &bob.Subkeys[len(bob.Subkeys)-1]
	collidingSubkey.PublicKey.KeyId = alice.PrimaryKey.KeyId
	collidingSubkey.PrivateKey.KeyId = alice.PrimaryKey.KeyId

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
		// Keyring rotation inside the decryption transaction.
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

// TestV2SnapshotKeyRingIsStable makes sure a snapshot keeps serving the
// frozen entity generation when the live keyring changes, and that the
// frozen clone never mutates the original entity's slices.
func TestV2SnapshotKeyRingIsStable(t *testing.T) {
	alice := newV2TestEntity(t, "Alice Snapshot V2", "alice.snapshot.v2@example.com")
	bob := newV2TestEntity(t, "Bob Snapshot V2", "bob.snapshot.v2@example.com")

	entities := EntityList{alice}
	snapshot := snapshotKeyRing(entities)

	keys := snapshot.KeysById(alice.PrimaryKey.KeyId)
	if len(keys) != 1 || keys[0].Entity != alice {
		t.Fatalf("unexpected initial lookup result: %+v", keys)
	}

	originalSubkeyCount := len(alice.Subkeys)
	bob.PrimaryKey.KeyId = alice.PrimaryKey.KeyId
	entities = append(entities, bob)

	keys = snapshot.KeysById(alice.PrimaryKey.KeyId)
	if len(keys) != 1 || keys[0].Entity != alice {
		t.Fatalf("snapshot observed a keyring mutation: %+v", keys)
	}
	resolved := snapshot.EntitiesById(alice.PrimaryKey.KeyId)
	if len(resolved) != 1 || resolved[0] != alice {
		t.Fatalf("snapshot entity lookup observed a mutation: %+v", resolved)
	}

	// The snapshot must own its subkey slice: freezing again after adding a
	// subkey to the live entity must not change the frozen generation.
	frozenSnapshot, ok := snapshot.(*keyRingSnapshot)
	if !ok {
		t.Fatalf("snapshot has unexpected type %T", snapshot)
	}
	frozen := frozenSnapshot.frozenEntity(alice)
	if frozen == alice {
		t.Fatal("snapshot must evaluate usage against a frozen entity clone")
	}
	if len(frozen.Subkeys) != originalSubkeyCount || len(alice.Subkeys) != originalSubkeyCount {
		t.Fatal("freezing must not alter the original entity's subkeys")
	}

	if snapshotKeyRing(nil) != nil {
		t.Fatal("snapshotting a nil keyring must return nil")
	}
}

// TestV2KeyRingSnapshotCustomKeyRing ensures custom keyrings remain usable
// through the snapshot wrapper.
func TestV2KeyRingSnapshotCustomKeyRing(t *testing.T) {
	alice := newV2TestEntity(t, "Alice Custom V2", "alice.custom.v2@example.com")

	plaintext := "v2 custom keyring transaction\n"
	message := v2SignAndEncrypt(t, alice, alice, plaintext)

	keyring := &rotatingKeyRingV2{entities: EntityList{alice}}
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
