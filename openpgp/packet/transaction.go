// Copyright 2024 The Proton AG. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
)

// KeyTransaction is a migration transaction for private key entities.
//
// Migrating a private key entity (e.g. changing its passphrase or refreshing
// its self-signatures) involves several mutating steps: decrypting the key
// material, re-signing the self-signatures, re-encrypting the key material,
// and serializing the result. If any of these steps fails midway, the entity
// must not be left behind half-encrypted or with a mix of old and new
// self-signatures: a later serialization (e.g. after a restart) would
// otherwise emit an inconsistent key.
//
// KeyTransaction snapshots the mutable state of the private keys and
// signatures taking part in such a migration. Consumers (private key
// decryption, re-signing, encryption, and serialization) snapshot the state
// they are about to mutate, and either Commit the transaction on success or
// Rollback to restore the snapshotted state on failure.
//
// A KeyTransaction is not safe for concurrent use.
type KeyTransaction struct {
	keys []privateKeyBackup
	sigs []signatureBackup
	done bool
}

// privateKeyBackup records the mutable encryption-related state of a
// PrivateKey so that it can be restored on rollback.
type privateKeyBackup struct {
	key           *PrivateKey
	encrypted     bool
	encryptedData []byte
	cipher        CipherFunction
	s2k           func(out, in []byte)
	aead          AEADMode
	privateKey    interface{}
	iv            []byte
	s2kType       S2KType
	s2kParams     *s2k.Params
}

// signatureBackup records a deep copy of a Signature so that its contents
// can be restored in place on rollback. The contents are restored in place
// (rather than swapping pointers) because other structures may hold
// references to the mutated Signature.
type signatureBackup struct {
	sig  *Signature
	copy *Signature
}

// NewKeyTransaction returns an empty migration transaction.
func NewKeyTransaction() *KeyTransaction {
	return &KeyTransaction{}
}

// SnapshotKeys records the current encryption state of the given private
// keys, so that a later Rollback restores it. Nil keys are ignored.
func (t *KeyTransaction) SnapshotKeys(keys ...*PrivateKey) {
	if t.done {
		return
	}
	for _, key := range keys {
		if key == nil {
			continue
		}
		t.keys = append(t.keys, privateKeyBackup{
			key:           key,
			encrypted:     key.Encrypted,
			encryptedData: key.encryptedData,
			cipher:        key.cipher,
			s2k:           key.s2k,
			aead:          key.aead,
			privateKey:    key.PrivateKey,
			iv:            key.iv,
			s2kType:       key.s2kType,
			s2kParams:     key.s2kParams,
		})
	}
}

// SnapshotSignatures records deep copies of the given signatures, so that a
// later Rollback restores their contents in place. Nil signatures are
// ignored.
func (t *KeyTransaction) SnapshotSignatures(sigs ...*Signature) {
	if t.done {
		return
	}
	for _, sig := range sigs {
		if sig == nil {
			continue
		}
		t.sigs = append(t.sigs, signatureBackup{
			sig:  sig,
			copy: sig.clone(),
		})
	}
}

// Commit marks the migration as successful and discards all snapshots.
// A subsequent Rollback is a no-op.
func (t *KeyTransaction) Commit() {
	t.done = true
	t.keys = nil
	t.sigs = nil
}

// Rollback restores all snapshotted state, undoing any mutation performed
// since the snapshots were taken. It is a no-op if the transaction was
// already committed or rolled back.
func (t *KeyTransaction) Rollback() {
	if t.done {
		return
	}
	t.done = true
	for _, backup := range t.keys {
		key := backup.key
		key.Encrypted = backup.encrypted
		key.encryptedData = backup.encryptedData
		key.cipher = backup.cipher
		key.s2k = backup.s2k
		key.aead = backup.aead
		key.PrivateKey = backup.privateKey
		key.iv = backup.iv
		key.s2kType = backup.s2kType
		key.s2kParams = backup.s2kParams
	}
	for _, backup := range t.sigs {
		*backup.sig = *backup.copy
	}
	t.keys = nil
	t.sigs = nil
}

// clone returns a deep copy of the signature. Immutable fields (such as the
// encoded MPIs of the signature values) are shared with the original.
func (sig *Signature) clone() *Signature {
	if sig == nil {
		return nil
	}
	c := *sig
	c.salt = cloneBytes(sig.salt)
	c.HashSuffix = cloneBytes(sig.HashSuffix)
	c.EdSig = cloneBytes(sig.EdSig)
	c.MldsaSig = cloneBytes(sig.MldsaSig)
	c.SlhdsaSig = cloneBytes(sig.SlhdsaSig)
	c.rawSubpackets = cloneOutputSubpackets(sig.rawSubpackets)
	c.outSubpackets = cloneOutputSubpackets(sig.outSubpackets)
	if sig.SigLifetimeSecs != nil {
		v := *sig.SigLifetimeSecs
		c.SigLifetimeSecs = &v
	}
	if sig.KeyLifetimeSecs != nil {
		v := *sig.KeyLifetimeSecs
		c.KeyLifetimeSecs = &v
	}
	c.PreferredSymmetric = cloneBytes(sig.PreferredSymmetric)
	c.PreferredHash = cloneBytes(sig.PreferredHash)
	c.PreferredCompression = cloneBytes(sig.PreferredCompression)
	if sig.PreferredCipherSuites != nil {
		c.PreferredCipherSuites = make([][2]uint8, len(sig.PreferredCipherSuites))
		copy(c.PreferredCipherSuites, sig.PreferredCipherSuites)
	}
	if sig.IssuerKeyId != nil {
		v := *sig.IssuerKeyId
		c.IssuerKeyId = &v
	}
	c.IssuerFingerprint = cloneBytes(sig.IssuerFingerprint)
	if sig.SignerUserId != nil {
		v := *sig.SignerUserId
		c.SignerUserId = &v
	}
	if sig.IsPrimaryId != nil {
		v := *sig.IsPrimaryId
		c.IsPrimaryId = &v
	}
	if sig.Notations != nil {
		c.Notations = make([]*Notation, len(sig.Notations))
		for i, notation := range sig.Notations {
			if notation == nil {
				continue
			}
			n := *notation
			n.Value = cloneBytes(notation.Value)
			c.Notations[i] = &n
		}
	}
	if sig.IntendedRecipients != nil {
		c.IntendedRecipients = make([]*Recipient, len(sig.IntendedRecipients))
		for i, recipient := range sig.IntendedRecipients {
			if recipient == nil {
				continue
			}
			r := *recipient
			r.Fingerprint = cloneBytes(recipient.Fingerprint)
			c.IntendedRecipients[i] = &r
		}
	}
	if sig.TrustRegularExpression != nil {
		v := *sig.TrustRegularExpression
		c.TrustRegularExpression = &v
	}
	if sig.RevocationReason != nil {
		v := *sig.RevocationReason
		c.RevocationReason = &v
	}
	c.EmbeddedSignature = sig.EmbeddedSignature.clone()
	return &c
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

func cloneOutputSubpackets(subpackets []outputSubpacket) []outputSubpacket {
	if subpackets == nil {
		return nil
	}
	c := make([]outputSubpacket, len(subpackets))
	for i, subpacket := range subpackets {
		c[i] = subpacket
		c[i].contents = cloneBytes(subpacket.contents)
	}
	return c
}
