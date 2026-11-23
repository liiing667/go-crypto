// Copyright (C) 2026 Proton AG. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"context"
	"sync"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
)

// privateKeyUnlockMu serializes mutations of private key packets. A failed
// batch restore must not roll back a key that another concurrent retry has
// already decrypted successfully.
var privateKeyUnlockMu sync.Mutex

// privateKeyState is an exact snapshot of the mutable state of a PrivateKey.
// A batch unlock restores these snapshots if any key fails, so an entity is
// never left half-decrypted after a bad passphrase or a cancellation.
type privateKeyState struct {
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

func (pk *PrivateKey) snapshot() privateKeyState {
	return privateKeyState{
		encrypted:     pk.Encrypted,
		encryptedData: append([]byte(nil), pk.encryptedData...),
		cipher:        pk.cipher,
		s2k:           pk.s2k,
		aead:          pk.aead,
		privateKey:    pk.PrivateKey,
		iv:            append([]byte(nil), pk.iv...),
		s2kType:       pk.s2kType,
		s2kParams:     pk.s2kParams,
	}
}

func (pk *PrivateKey) restore(state privateKeyState) {
	pk.Encrypted = state.encrypted
	pk.encryptedData = state.encryptedData
	pk.cipher = state.cipher
	pk.s2k = state.s2k
	pk.aead = state.aead
	pk.PrivateKey = state.privateKey
	pk.iv = state.iv
	pk.s2kType = state.s2kType
	pk.s2kParams = state.s2kParams
}

type privateKeySnapshot struct {
	key   *PrivateKey
	state privateKeyState
}

func restorePrivateKeys(snapshots []privateKeySnapshot) {
	for _, snapshot := range snapshots {
		snapshot.key.restore(snapshot.state)
	}
}

// decryptWithTransaction derives the S2K key inside tx and installs the
// decrypted private key only after the packet checksum and the public/private
// key identity checks have succeeded.
func (pk *PrivateKey) decryptWithTransaction(tx *s2k.UnlockTransaction, passphrase []byte) error {
	if pk.Dummy() {
		return errors.ErrDummyPrivateKey("dummy key found")
	}
	if !pk.Encrypted {
		return nil
	}
	if pk.s2kParams == nil {
		return errors.StructuralError("missing s2k parameters")
	}

	key, err := tx.DeriveKey(passphrase, pk.s2kParams, pk.cipher.KeySize())
	if err != nil {
		return err
	}
	if pk.s2kType == S2KAEAD {
		key = pk.applyHKDF(key)
	}
	return pk.decrypt(key)
}

// Decrypt decrypts an encrypted private key using a passphrase.
func (pk *PrivateKey) Decrypt(passphrase []byte) error {
	return pk.DecryptWithContext(context.Background(), passphrase)
}

// DecryptWithContext decrypts an encrypted private key using a passphrase.
// The S2K derivation observes ctx and is constrained by the default S2K
// budget. Cancellation or a budget failure leaves the key untouched.
func (pk *PrivateKey) DecryptWithContext(ctx context.Context, passphrase []byte) error {
	return pk.DecryptWithConfig(ctx, passphrase, nil)
}

// DecryptWithBudget decrypts a private key using the given S2K budget.
func (pk *PrivateKey) DecryptWithBudget(ctx context.Context, passphrase []byte, budget *s2k.Budget) error {
	return pk.DecryptWithConfig(ctx, passphrase, &Config{S2KUnlockBudget: budget})
}

// DecryptWithConfig decrypts an encrypted private key using a passphrase and
// the S2K unlock budget from config. The key is only modified if the complete
// derivation and identity checks succeed.
func (pk *PrivateKey) DecryptWithConfig(ctx context.Context, passphrase []byte, config *Config) error {
	if pk.Dummy() {
		return errors.ErrDummyPrivateKey("dummy key found")
	}
	if !pk.Encrypted {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	privateKeyUnlockMu.Lock()
	defer privateKeyUnlockMu.Unlock()

	cache := &s2k.Cache{}
	tx := cache.BeginTransaction(ctx, *config.UnlockBudget())
	state := pk.snapshot()
	if err := pk.decryptWithTransaction(tx, passphrase); err != nil {
		tx.Abort(err)
		pk.restore(state)
		return err
	}
	if err := ctx.Err(); err != nil {
		tx.Abort(err)
		pk.restore(state)
		return err
	}
	if err := tx.Commit(); err != nil {
		pk.restore(state)
		return err
	}
	return nil
}

// decryptWithCache decrypts a key using a shared S2K cache. It is kept for
// compatibility with the previous internal API; use a transaction when several
// keys should share one budget and cancellation state.
func (pk *PrivateKey) decryptWithCache(passphrase []byte, keyCache *s2k.Cache) error {
	if pk.Dummy() {
		return errors.ErrDummyPrivateKey("dummy key found")
	}
	if !pk.Encrypted {
		return nil
	}
	if keyCache == nil {
		keyCache = &s2k.Cache{}
	}
	privateKeyUnlockMu.Lock()
	defer privateKeyUnlockMu.Unlock()

	state := pk.snapshot()
	key, err := keyCache.GetOrComputeDerivedKey(passphrase, pk.s2kParams, pk.cipher.KeySize())
	if err != nil {
		pk.restore(state)
		return err
	}
	if pk.s2kType == S2KAEAD {
		key = pk.applyHKDF(key)
	}
	if err := pk.decrypt(key); err != nil {
		keyCache.Invalidate()
		pk.restore(state)
		return err
	}
	return nil
}

// DecryptPrivateKeys decrypts all encrypted keys with the given passphrase.
// Avoids recomputation of similar s2k key derivations.
//
// The batch is one unlock transaction: all keys see the same S2K budget and
// cache generation. If any key fails (including a cancellation), every key is
// rolled back to its previous state and the cache is invalidated, so a later
// retry or another entity cannot observe a partially derived or partially
// decrypted result.
func DecryptPrivateKeys(keys []*PrivateKey, passphrase []byte) error {
	return DecryptPrivateKeysWithContext(context.Background(), keys, passphrase)
}

// DecryptPrivateKeysWithContext is like DecryptPrivateKeys but observes ctx.
func DecryptPrivateKeysWithContext(ctx context.Context, keys []*PrivateKey, passphrase []byte) error {
	return DecryptPrivateKeysWithConfig(ctx, keys, passphrase, nil)
}

// DecryptPrivateKeysWithBudget decrypts all encrypted keys using the given S2K
// budget as one unlock transaction.
func DecryptPrivateKeysWithBudget(ctx context.Context, keys []*PrivateKey, passphrase []byte, budget *s2k.Budget) error {
	return DecryptPrivateKeysWithConfig(ctx, keys, passphrase, &Config{S2KUnlockBudget: budget})
}

// DecryptPrivateKeysWithConfig decrypts all encrypted keys with the given
// passphrase and S2K unlock budget. Dummy and unencrypted keys are ignored.
func DecryptPrivateKeysWithConfig(ctx context.Context, keys []*PrivateKey, passphrase []byte, config *Config) error {
	return decryptPrivateKeys(ctx, keys, passphrase, &s2k.Cache{}, *config.UnlockBudget())
}

// DecryptPrivateKeysWithCache decrypts all encrypted keys with the given
// passphrase using cache as the unlock transaction's cache. The cache's
// generation is advanced on entry and again on failure, so callers can observe
// that a failed batch left no reusable derivation behind.
func DecryptPrivateKeysWithCache(ctx context.Context, keys []*PrivateKey, passphrase []byte, cache *s2k.Cache) error {
	return decryptPrivateKeys(ctx, keys, passphrase, cache, s2k.DefaultUnlockBudget())
}

// DecryptPrivateKeysWithCacheAndBudget is the fully configurable batch unlock
// entry point: it uses cache for the transaction and budget for the S2K
// parameter limits.
func DecryptPrivateKeysWithCacheAndBudget(ctx context.Context, keys []*PrivateKey, passphrase []byte, cache *s2k.Cache, budget *s2k.Budget) error {
	effective := s2k.DefaultUnlockBudget()
	if budget != nil {
		effective = *budget
	}
	return decryptPrivateKeys(ctx, keys, passphrase, cache, effective)
}

func decryptPrivateKeys(ctx context.Context, keys []*PrivateKey, passphrase []byte, cache *s2k.Cache, budget s2k.Budget) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if cache == nil {
		cache = &s2k.Cache{}
	}

	privateKeyUnlockMu.Lock()
	defer privateKeyUnlockMu.Unlock()

	var snapshots []privateKeySnapshot
	for _, key := range keys {
		if key == nil || key.Dummy() || !key.Encrypted {
			continue
		}
		snapshots = append(snapshots, privateKeySnapshot{key: key, state: key.snapshot()})
	}

	tx := cache.BeginTransaction(ctx, budget)
	for _, snapshot := range snapshots {
		if err := ctx.Err(); err != nil {
			tx.Abort(err)
			restorePrivateKeys(snapshots)
			return err
		}
		if err := snapshot.key.decryptWithTransaction(tx, passphrase); err != nil {
			tx.Abort(err)
			restorePrivateKeys(snapshots)
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		tx.Abort(err)
		restorePrivateKeys(snapshots)
		return err
	}
	if err := tx.Commit(); err != nil {
		restorePrivateKeys(snapshots)
		return err
	}
	return nil
}
