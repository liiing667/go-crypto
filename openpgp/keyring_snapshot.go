// Copyright 2026 The go-crypto Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import "github.com/ProtonMail/go-crypto/openpgp/packet"

// keyRingSnapshot is an immutable view of the key material that was visible
// when a message read started.
//
// A single ReadMessage call performs several key lookups: it resolves the
// recipient keys for the session-key packets, and later it resolves the key
// and entity that signed the decrypted contents. Those lookups have to use
// the same keyring generation. Otherwise a keyring retry or rotation can
// decrypt with one entity's private key while attributing the message to a
// different entity that happens to use the same key id.
type keyRingSnapshot struct {
	entities        EntityList
	keys            []Key
	decryptionKeys  []Key
	fallback        KeyRing
	complete        bool
	snapshotStarted bool
}

// snapshotKeyRing freezes the key material available through keyring.
//
// Built-in EntityList keyrings are fully materialized. Custom keyrings are
// probed through their public lookup methods so that implementations that
// expose all entities (for example EntityList-backed wrappers) are frozen as
// well. If a custom keyring cannot be enumerated, it is kept as a fallback
// for ids that were not captured by the probes.
func snapshotKeyRing(keyring KeyRing) KeyRing {
	if keyring == nil {
		return nil
	}

	snapshot := &keyRingSnapshot{fallback: keyring}
	switch entities := keyring.(type) {
	case EntityList:
		snapshot.entities = append(EntityList(nil), entities...)
		snapshot.complete = true
	case *EntityList:
		if entities == nil {
			return nil
		}
		snapshot.entities = append(EntityList(nil), (*entities)...)
		snapshot.complete = true
	}

	if len(snapshot.entities) == 0 && !snapshot.complete {
		// The v2 keyring interface exposes EntitiesById(0) as the complete
		// entity set. Some v1 keyrings implement the same convention as an
		// extension, so use it when it is available.
		if provider, ok := keyring.(interface {
			EntitiesById(uint64) []*Entity
		}); ok {
			snapshot.addEntities(provider.EntitiesById(0))
			snapshot.complete = len(snapshot.entities) > 0
		}
	}

	if len(snapshot.entities) == 0 && !snapshot.complete {
		// A custom keyring may expose all keys through the conventional id
		// zero lookup used by the v2 EntityList implementation.
		snapshot.addKeys(keyring.KeysById(0))
		if len(snapshot.entities) == 0 && len(snapshot.keys) == 0 {
			snapshot.addKeys(keyring.KeysByIdUsage(0, 0))
		}
	}

	// DecryptionKeys is part of the v1 KeyRing interface. Probing it captures
	// entities whose private key material has to stay stable across a prompt
	// or a retry, even for custom keyrings without an entity enumerator.
	snapshot.addKeys(keyring.DecryptionKeys())

	if len(snapshot.entities) == 0 && len(snapshot.keys) == 0 {
		// Nothing could be enumerated. Keep the original implementation so its
		// own lookup semantics remain available.
		return keyring
	}
	snapshot.materialize()
	return snapshot
}

func (s *keyRingSnapshot) addEntities(entities []*Entity) {
	for _, entity := range entities {
		if entity == nil {
			continue
		}
		if !containsEntity(s.entities, entity) {
			s.entities = append(s.entities, entity)
		}
	}
}

func (s *keyRingSnapshot) addKeys(keys []Key) {
	for _, key := range keys {
		if key.Entity != nil && !containsEntity(s.entities, key.Entity) {
			s.entities = append(s.entities, key.Entity)
		}
		if key.PublicKey == nil {
			continue
		}
		if !containsKey(s.keys, key) {
			s.keys = append(s.keys, key)
		}
	}
}

func (s *keyRingSnapshot) materialize() {
	if s.snapshotStarted {
		return
	}
	s.snapshotStarted = true

	for _, entity := range s.entities {
		primarySelfSignature, _ := entity.PrimarySelfSignature()
		s.addKeys([]Key{{
			Entity:        entity,
			PublicKey:     entity.PrimaryKey,
			PrivateKey:    entity.PrivateKey,
			SelfSignature: primarySelfSignature,
			Revocations:   entity.Revocations,
		}})
		for index := range entity.Subkeys {
			subkey := &entity.Subkeys[index]
			s.addKeys([]Key{{
				Entity:        entity,
				PublicKey:     subkey.PublicKey,
				PrivateKey:    subkey.PrivateKey,
				SelfSignature: subkey.Sig,
				Revocations:   subkey.Revocations,
			}})
		}
	}

	s.decryptionKeys = nil
	for _, key := range s.keys {
		if key.Entity == nil || key.PublicKey == nil || key.PrivateKey == nil {
			continue
		}
		// EntityList.DecryptionKeys historically returns encryption subkeys,
		// not the primary key.
		if key.PublicKey == key.Entity.PrimaryKey {
			continue
		}
		if key.SelfSignature == nil || !key.SelfSignature.FlagsValid {
			continue
		}
		if key.SelfSignature.FlagEncryptStorage || key.SelfSignature.FlagEncryptCommunications {
			s.decryptionKeys = append(s.decryptionKeys, key)
		}
	}
}

func (s *keyRingSnapshot) KeysById(id uint64) []Key {
	s.materialize()
	var keys []Key
	for _, key := range s.keys {
		if key.PublicKey != nil && key.PublicKey.KeyId == id {
			keys = append(keys, key)
		}
	}
	if len(keys) > 0 || s.complete || s.fallback == nil {
		return keys
	}
	return s.fallback.KeysById(id)
}

func (s *keyRingSnapshot) KeysByIdUsage(id uint64, requiredUsage byte) []Key {
	s.materialize()
	var keys []Key
	for _, key := range s.keys {
		if key.PublicKey == nil || key.PublicKey.KeyId != id {
			continue
		}
		if keyMatchesUsage(key.SelfSignature, requiredUsage) {
			keys = append(keys, key)
		}
	}
	if len(keys) > 0 || s.complete || s.fallback == nil {
		return keys
	}
	return s.fallback.KeysByIdUsage(id, requiredUsage)
}

func (s *keyRingSnapshot) DecryptionKeys() []Key {
	s.materialize()
	return append([]Key(nil), s.decryptionKeys...)
}

func keyMatchesUsage(selfSignature *packet.Signature, requiredUsage byte) bool {
	if requiredUsage == 0 {
		return true
	}
	if selfSignature == nil || !selfSignature.FlagsValid {
		return false
	}
	var usage byte
	if selfSignature.FlagCertify {
		usage |= packet.KeyFlagCertify
	}
	if selfSignature.FlagSign {
		usage |= packet.KeyFlagSign
	}
	if selfSignature.FlagEncryptCommunications {
		usage |= packet.KeyFlagEncryptCommunications
	}
	if selfSignature.FlagEncryptStorage {
		usage |= packet.KeyFlagEncryptStorage
	}
	return usage&requiredUsage == requiredUsage
}

func containsEntity(entities EntityList, entity *Entity) bool {
	for _, existing := range entities {
		if existing == entity {
			return true
		}
	}
	return false
}

func containsKey(keys []Key, key Key) bool {
	for _, existing := range keys {
		if existing.Entity == key.Entity && existing.PublicKey == key.PublicKey {
			return true
		}
	}
	return false
}

// signingKeysByIdUsage resolves all signing keys for an issuer in one
// transaction and, when the signature carries a fingerprint, requires that
// exact fingerprint. Returning every matching key lets the verifier commit to
// the key that actually produced the signature instead of merely the first
// key with a colliding key id.
func signingKeysByIdUsage(keyring KeyRing, id uint64, fingerprint []byte, requiredUsage byte) []Key {
	if keyring == nil {
		return nil
	}
	keys := keyring.KeysByIdUsage(id, requiredUsage)
	if len(fingerprint) == 0 {
		return keys
	}
	filtered := make([]Key, 0, 1)
	for _, key := range keys {
		if key.PublicKey != nil && equalFingerprints(key.PublicKey.Fingerprint, fingerprint) {
			filtered = append(filtered, key)
		}
	}
	return filtered
}

func equalFingerprints(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
