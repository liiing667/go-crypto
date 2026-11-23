// Copyright 2024 The Proton AG. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package v2

import (
	"bytes"
	"crypto"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// failAfterReader returns up to limit bytes of deterministic data and then
// fails every subsequent read.
type failAfterReader struct {
	remaining int
}

func (r *failAfterReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = byte(i)
	}
	r.remaining -= n
	return n, nil
}

func newTransactionTestEntity(t *testing.T) *Entity {
	t.Helper()
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.AddEncryptionSubkey(nil); err != nil {
		t.Fatal(err)
	}
	if err := entity.AddEncryptionSubkey(nil); err != nil {
		t.Fatal(err)
	}
	return entity
}

func entityPrivateKeys(entity *Entity) []*packet.PrivateKey {
	keys := []*packet.PrivateKey{entity.PrivateKey}
	for i := range entity.Subkeys {
		keys = append(keys, entity.Subkeys[i].PrivateKey)
	}
	return keys
}

func assertAllKeysEncrypted(t *testing.T, entity *Entity) {
	t.Helper()
	for _, key := range entityPrivateKeys(entity) {
		if !key.Encrypted {
			t.Fatal("expected encrypted private key")
		}
		if key.PrivateKey != nil {
			t.Fatal("expected no private key material on encrypted key")
		}
	}
}

func assertAllKeysUnencrypted(t *testing.T, entity *Entity) {
	t.Helper()
	for _, key := range entityPrivateKeys(entity) {
		if key.Encrypted {
			t.Fatal("expected unencrypted private key")
		}
		if key.PrivateKey == nil {
			t.Fatal("expected private key material on unencrypted key")
		}
	}
}

func selfSignatureBytes(t *testing.T, entity *Entity) [][]byte {
	t.Helper()
	var sigs []*packet.Signature
	for _, ident := range entity.Identities {
		for _, selfCertification := range ident.SelfCertifications {
			sigs = append(sigs, selfCertification.Packet)
		}
	}
	for i := range entity.Subkeys {
		for _, binding := range entity.Subkeys[i].Bindings {
			sigs = append(sigs, binding.Packet)
		}
	}
	serialized := make([][]byte, 0, len(sigs))
	for _, sig := range sigs {
		buf := bytes.NewBuffer(nil)
		if err := sig.Serialize(buf); err != nil {
			t.Fatal(err)
		}
		serialized = append(serialized, buf.Bytes())
	}
	return serialized
}

func TestEncryptPrivateKeysRollbackOnFailure(t *testing.T) {
	entity := newTransactionTestEntity(t)
	passphrase := []byte("password")

	// Allow enough randomness for the s2k salt (8 bytes) and the primary
	// key's IV (16 bytes), then fail: the subkeys can no longer be
	// encrypted.
	config := &packet.Config{
		Rand: &failAfterReader{remaining: 24},
	}
	if err := entity.EncryptPrivateKeys(passphrase, config); err == nil {
		t.Fatal("expected encryption to fail")
	}

	// The failed migration must not leave the entity half-encrypted.
	assertAllKeysUnencrypted(t, entity)

	// The entity must still be fully usable: retrying the migration with a
	// working randomness source succeeds.
	if err := entity.EncryptPrivateKeys(passphrase, nil); err != nil {
		t.Fatal(err)
	}
	assertAllKeysEncrypted(t, entity)
	if err := entity.DecryptPrivateKeys(passphrase); err != nil {
		t.Fatal(err)
	}
	assertAllKeysUnencrypted(t, entity)
}

func TestDecryptPrivateKeysRollbackOnFailure(t *testing.T) {
	entity := newTransactionTestEntity(t)
	primaryPassphrase := []byte("primary-password")
	subkeyPassphrase := []byte("subkey-password")

	// Encrypt the primary key and the subkeys with different passphrases.
	if err := entity.PrivateKey.EncryptWithConfig(primaryPassphrase, nil); err != nil {
		t.Fatal(err)
	}
	for i := range entity.Subkeys {
		if err := entity.Subkeys[i].PrivateKey.EncryptWithConfig(subkeyPassphrase, nil); err != nil {
			t.Fatal(err)
		}
	}

	// Decrypting with the primary key's passphrase decrypts the primary key
	// but fails on the first subkey.
	if err := entity.DecryptPrivateKeys(primaryPassphrase); err == nil {
		t.Fatal("expected decryption to fail")
	}

	// The failed migration must not leave the entity half-decrypted.
	assertAllKeysEncrypted(t, entity)

	// Each key must still be decryptable with its own passphrase.
	if err := entity.PrivateKey.Decrypt(primaryPassphrase); err != nil {
		t.Fatal(err)
	}
	for i := range entity.Subkeys {
		if err := entity.Subkeys[i].PrivateKey.Decrypt(subkeyPassphrase); err != nil {
			t.Fatal(err)
		}
	}
	assertAllKeysUnencrypted(t, entity)
}

func TestSerializePrivateRollbackOnFailure(t *testing.T) {
	entity := newTransactionTestEntity(t)

	// Snapshot the current self-signatures.
	before := selfSignatureBytes(t, entity)

	// Make re-signing the second subkey fail, after the identity and the
	// first subkey have already been re-signed.
	entity.Subkeys[1].Bindings[0].Packet.Hash = crypto.Hash(0)

	buf := bytes.NewBuffer(nil)
	if err := entity.SerializePrivate(buf, nil); err == nil {
		t.Fatal("expected serialization to fail")
	}
	if buf.Len() != 0 {
		t.Fatal("expected no output on failed serialization")
	}

	// The failed migration must not leave the entity with a mix of old and
	// new self-signatures.
	after := selfSignatureBytes(t, entity)
	if len(before) != len(after) {
		t.Fatal("unexpected number of self-signatures")
	}
	for i := range before {
		if !bytes.Equal(before[i], after[i]) {
			t.Fatalf("self-signature %d changed despite failed migration", i)
		}
	}

	// A later serialization (e.g. after a restart) still emits the
	// consistent, original self-signatures.
	out := bytes.NewBuffer(nil)
	if err := entity.SerializePrivateWithoutSigning(out, nil); err != nil {
		t.Fatal(err)
	}
	parsed, err := ReadEntity(packet.NewReader(bytes.NewReader(out.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	reparsed := selfSignatureBytes(t, parsed)
	for i := range before {
		if !bytes.Equal(before[i], reparsed[i]) {
			t.Fatalf("self-signature %d of reparsed entity changed despite failed migration", i)
		}
	}
}
