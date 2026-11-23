// Copyright 2026 The go-crypto Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package v2

import (
	"bytes"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// keyRingSnapshot is an immutable view of the keyring used by one message
// read. Both the recipient lookup and the later signer lookup must resolve
// against this same view. A retry or key rotation cannot otherwise decrypt
// with one entity's private key and then report another entity as the signer
// merely because both keys share a 64-bit key id.
type keyRingSnapshot struct {
	entities EntityList
	frozen   map[*Entity]*Entity
	keys     []Key
	fallback KeyRing
	complete bool
}

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
	default:
		// EntityById(0) is the "all entities" convention implemented by
		// EntityList, and is also implemented by EntityList-backed custom
		// keyrings.
		snapshot.addEntities(keyring.EntitiesById(0))
		snapshot.complete = len(snapshot.entities) > 0
		if !snapshot.complete {
			// Some custom keyrings expose all keys through KeysById(0) even
			// if they do not implement the entity extension.
			snapshot.addKeys(keyring.KeysById(0))
		}
	}

	if len(snapshot.entities) == 0 && len(snapshot.keys) == 0 {
		return keyring
	}
	snapshot.materialize()
	return snapshot
}

func (s *keyRingSnapshot) addEntities(entities []*Entity) {
	for _, entity := range entities {
		if entity == nil || containsEntity(s.entities, entity) {
			continue
		}
		s.entities = append(s.entities, entity)
	}
}

func (s *keyRingSnapshot) addKeys(keys []Key) {
	for _, key := range keys {
		if key.Entity != nil && !containsEntity(s.entities, key.Entity) {
			s.entities = append(s.entities, key.Entity)
		}
		if key.PublicKey == nil || containsKey(s.keys, key) {
			continue
		}
		s.keys = append(s.keys, key)
	}
}

func (s *keyRingSnapshot) materialize() {
	if len(s.keys) > 0 && s.frozen != nil {
		return
	}
	if s.frozen == nil {
		s.frozen = make(map[*Entity]*Entity, len(s.entities))
	}
	for _, entity := range s.entities {
		if _, ok := s.frozen[entity]; !ok {
			s.frozen[entity] = cloneEntityForSnapshot(entity)
		}
		s.addKeys([]Key{{
			Entity:     entity,
			PublicKey:  entity.PrimaryKey,
			PrivateKey: entity.PrivateKey,
		}})
		for index := range entity.Subkeys {
			subkey := &entity.Subkeys[index]
			s.addKeys([]Key{{
				Entity:     entity,
				PublicKey:  subkey.PublicKey,
				PrivateKey: subkey.PrivateKey,
			}})
		}
	}
}

func (s *keyRingSnapshot) KeysById(id uint64) []Key {
	s.materialize()
	var keys []Key
	for _, key := range s.keys {
		if key.PublicKey != nil && (id == 0 || key.PublicKey.KeyId == id) {
			keys = append(keys, key)
		}
	}
	if len(keys) > 0 || s.complete || s.fallback == nil {
		return keys
	}
	return s.fallback.KeysById(id)
}

func (s *keyRingSnapshot) EntitiesById(id uint64) []*Entity {
	s.materialize()
	var entities []*Entity
	for _, entity := range s.entities {
		if id == 0 || s.entityHasSnapshotKeyId(entity, id) {
			if !containsEntity(entities, entity) {
				entities = append(entities, entity)
			}
		}
	}
	if len(entities) > 0 || s.complete || s.fallback == nil {
		return entities
	}
	return s.fallback.EntitiesById(id)
}

func (s *keyRingSnapshot) entityHasSnapshotKeyId(entity *Entity, id uint64) bool {
	for _, key := range s.keys {
		if key.Entity == entity && key.PublicKey != nil && key.PublicKey.KeyId == id {
			return true
		}
	}
	return false
}

func (s *keyRingSnapshot) entityHasSnapshotFingerprint(entity *Entity, fingerprint []byte) bool {
	for _, key := range s.keys {
		if key.Entity == entity && key.PublicKey != nil && bytes.Equal(key.PublicKey.Fingerprint, fingerprint) {
			return true
		}
	}
	return false
}

func (s *keyRingSnapshot) frozenEntity(entity *Entity) *Entity {
	s.materialize()
	if frozen := s.frozen[entity]; frozen != nil {
		return frozen
	}
	return entity
}

// cloneEntityForSnapshot freezes the key-selection inputs of an entity while
// preserving the original entity pointer for MessageDetails. The clone shares
// immutable packet key material, but owns its subkey, identity and revocation
// slices so a later keyring retry cannot add a same-id subkey halfway through
// verification.
func cloneEntityForSnapshot(entity *Entity) *Entity {
	if entity == nil {
		return nil
	}
	clone := *entity
	clone.Revocations = append(clone.Revocations[:0:0], entity.Revocations...)
	clone.DirectSignatures = append(clone.DirectSignatures[:0:0], entity.DirectSignatures...)
	clone.Identities = make(map[string]*Identity, len(entity.Identities))
	for name, identity := range entity.Identities {
		clone.Identities[name] = identity
	}
	clone.Subkeys = make([]Subkey, len(entity.Subkeys))
	copy(clone.Subkeys, entity.Subkeys)
	for index := range clone.Subkeys {
		clone.Subkeys[index].Primary = &clone
		clone.Subkeys[index].Bindings = append(
			clone.Subkeys[index].Bindings[:0:0],
			entity.Subkeys[index].Bindings...,
		)
		clone.Subkeys[index].Revocations = append(
			clone.Subkeys[index].Revocations[:0:0],
			entity.Subkeys[index].Revocations...,
		)
	}
	return &clone
}

func entityHasKeyId(entity *Entity, id uint64) bool {
	if entity == nil || entity.PrimaryKey == nil {
		return false
	}
	if entity.PrimaryKey.KeyId == id {
		return true
	}
	for index := range entity.Subkeys {
		subkey := &entity.Subkeys[index]
		if subkey.PublicKey != nil && subkey.PublicKey.KeyId == id {
			return true
		}
	}
	return false
}

func entityHasFingerprint(entity *Entity, fingerprint []byte) bool {
	if entity == nil || entity.PrimaryKey == nil {
		return false
	}
	if bytes.Equal(entity.PrimaryKey.Fingerprint, fingerprint) {
		return true
	}
	for index := range entity.Subkeys {
		subkey := &entity.Subkeys[index]
		if subkey.PublicKey != nil && bytes.Equal(subkey.PublicKey.Fingerprint, fingerprint) {
			return true
		}
	}
	return false
}

// entitiesByIdFingerprint resolves signer entities for an issuer. A key id is
// not an identity when a v6 signature supplies a fingerprint: entities with a
// colliding id but a different fingerprint are not candidates.
func entitiesByIdFingerprint(keyring KeyRing, id uint64, fingerprint []byte) []*Entity {
	if keyring == nil {
		return nil
	}
	entities := keyring.EntitiesById(id)
	if len(fingerprint) == 0 {
		return entities
	}
	filtered := make([]*Entity, 0, 1)
	for _, entity := range entities {
		if snapshot, ok := keyring.(*keyRingSnapshot); ok {
			if snapshot.entityHasSnapshotFingerprint(entity, fingerprint) {
				filtered = append(filtered, entity)
			}
			continue
		}
		if entityHasFingerprint(entity, fingerprint) {
			filtered = append(filtered, entity)
		}
	}
	return filtered
}

func fingerprintMatches(actual, expected []byte) bool {
	return len(expected) == 0 || bytes.Equal(actual, expected)
}

// signingKeysForEntity evaluates key usage, time and revocation against the
// frozen entity view while keeping the returned Key.Entity pointing at the
// original entity exposed through MessageDetails.
func signingKeysForEntity(keyring KeyRing, entity *Entity, now time.Time, id uint64, flags int, fingerprint []byte, config *packet.Config) ([]Key, error) {
	if entity == nil {
		return nil, errors.InvalidArgumentError("keyring snapshot contains no entity")
	}
	if snapshot, ok := keyring.(*keyRingSnapshot); ok {
		frozen := snapshot.frozenEntity(entity)
		keys, err := frozen.signingKeysByIdUsage(now, id, flags, fingerprint, config)
		for index := range keys {
			keys[index].Entity = entity
		}
		return keys, err
	}
	return entity.signingKeysByIdUsage(now, id, flags, fingerprint, config)
}

func containsEntity(entities []*Entity, entity *Entity) bool {
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
