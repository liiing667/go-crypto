// Copyright (C) 2026 Proton AG. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	goerrors "errors"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/internal/ecc"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
)

func unlockTestConfig() *Config {
	return &Config{
		DefaultCipher: CipherAES128,
		S2KConfig: &s2k.Config{
			S2KMode:  s2k.IteratedSaltedS2K,
			Hash:     crypto.SHA256,
			S2KCount: 65536,
		},
	}
}

func makeUnlockTestKeys(t *testing.T) []*PrivateKey {
	t.Helper()

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPriv, err := ecdsa.GenerateKey(rand.Reader, ecc.NewGenericCurve(elliptic.P256()))
	if err != nil {
		t.Fatal(err)
	}
	eddsaPriv, err := eddsa.GenerateKey(rand.Reader, ecc.NewEd25519())
	if err != nil {
		t.Fatal(err)
	}

	return []*PrivateKey{
		NewRSAPrivateKey(time.Now(), rsaPriv),
		NewECDSAPrivateKey(time.Now(), ecdsaPriv),
		NewEdDSAPrivateKey(time.Now(), eddsaPriv),
	}
}

func encryptUnlockTestKeys(t *testing.T, keys []*PrivateKey, passphrase []byte) {
	t.Helper()
	config := unlockTestConfig()
	for _, key := range keys {
		if err := key.EncryptWithConfig(passphrase, config); err != nil {
			t.Fatal(err)
		}
	}
}

func assertKeysEncrypted(t *testing.T, keys []*PrivateKey, fingerprints [][]byte) {
	t.Helper()
	for i, key := range keys {
		if !key.Encrypted {
			t.Fatalf("key %d is not encrypted", i)
		}
		if key.PrivateKey != nil {
			t.Fatalf("key %d exposes private material after a failed unlock", i)
		}
		if !bytes.Equal(key.Fingerprint, fingerprints[i]) {
			t.Fatalf("key %d changed identity after a failed unlock", i)
		}
	}
}

func assertKeysDecryptedAndValid(t *testing.T, keys []*PrivateKey) {
	t.Helper()
	for i, key := range keys {
		if key.Encrypted {
			t.Fatalf("key %d is still encrypted", i)
		}
		switch priv := key.PrivateKey.(type) {
		case *rsa.PrivateKey:
			if err := priv.Validate(); err != nil {
				t.Fatalf("key %d has invalid RSA material: %v", i, err)
			}
		case *ecdsa.PrivateKey:
			if err := ecdsa.Validate(priv); err != nil {
				t.Fatalf("key %d has invalid ECDSA material: %v", i, err)
			}
		case *eddsa.PrivateKey:
			if err := eddsa.Validate(priv); err != nil {
				t.Fatalf("key %d has invalid EdDSA material: %v", i, err)
			}
		default:
			t.Fatalf("key %d has unexpected private key type %T", i, key.PrivateKey)
		}
	}
}

func TestDecryptPrivateKeysRollsBackOnBadPassphrase(t *testing.T) {
	keys := makeUnlockTestKeys(t)
	passphrase := []byte("correct passphrase")
	encryptUnlockTestKeys(t, keys, passphrase)

	fingerprints := make([][]byte, len(keys))
	for i, key := range keys {
		fingerprints[i] = append([]byte(nil), key.Fingerprint...)
	}

	if err := DecryptPrivateKeys(keys, []byte("wrong passphrase")); err == nil {
		t.Fatal("batch decrypt with a wrong passphrase succeeded")
	}
	assertKeysEncrypted(t, keys, fingerprints)

	if err := DecryptPrivateKeys(keys, passphrase); err != nil {
		t.Fatal(err)
	}
	assertKeysDecryptedAndValid(t, keys)
	for i, key := range keys {
		if !bytes.Equal(key.Fingerprint, fingerprints[i]) {
			t.Fatalf("key %d changed identity after a successful unlock", i)
		}
	}
}

func TestDecryptPrivateKeysRollsBackEarlierSuccesses(t *testing.T) {
	keys := makeUnlockTestKeys(t)[:2]
	config := unlockTestConfig()
	if err := keys[0].EncryptWithConfig([]byte("first passphrase"), config); err != nil {
		t.Fatal(err)
	}
	if err := keys[1].EncryptWithConfig([]byte("second passphrase"), config); err != nil {
		t.Fatal(err)
	}

	fingerprints := make([][]byte, len(keys))
	for i, key := range keys {
		fingerprints[i] = append([]byte(nil), key.Fingerprint...)
	}

	// The first key decrypts before the second one fails. The whole batch must
	// still roll back, including the first key.
	if err := DecryptPrivateKeys(keys, []byte("first passphrase")); err == nil {
		t.Fatal("batch decrypt succeeded even though the second key has a different passphrase")
	}
	assertKeysEncrypted(t, keys, fingerprints)

	if err := DecryptPrivateKeys(keys[:1], []byte("first passphrase")); err != nil {
		t.Fatal(err)
	}
	if err := DecryptPrivateKeys(keys[1:], []byte("second passphrase")); err != nil {
		t.Fatal(err)
	}
	assertKeysDecryptedAndValid(t, keys)
}

func TestDecryptPrivateKeysCanceledContextLeavesKeysEncrypted(t *testing.T) {
	keys := makeUnlockTestKeys(t)
	passphrase := []byte("correct passphrase")
	encryptUnlockTestKeys(t, keys, passphrase)

	fingerprints := make([][]byte, len(keys))
	for i, key := range keys {
		fingerprints[i] = append([]byte(nil), key.Fingerprint...)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := DecryptPrivateKeysWithContext(ctx, keys, passphrase); !goerrors.Is(err, context.Canceled) {
		t.Fatalf("DecryptPrivateKeysWithContext error = %v, want context.Canceled", err)
	}
	assertKeysEncrypted(t, keys, fingerprints)

	// A later retry must not observe a cached key from the canceled attempt.
	if err := DecryptPrivateKeys(keys, passphrase); err != nil {
		t.Fatal(err)
	}
	assertKeysDecryptedAndValid(t, keys)
}

func TestDecryptPrivateKeysBudgetFailureAndRetry(t *testing.T) {
	keys := makeUnlockTestKeys(t)
	passphrase := []byte("correct passphrase")
	encryptUnlockTestKeys(t, keys, passphrase)

	fingerprints := make([][]byte, len(keys))
	for i, key := range keys {
		fingerprints[i] = append([]byte(nil), key.Fingerprint...)
	}

	config := &Config{
		S2KUnlockBudget: &s2k.Budget{MaxIterations: 1024},
	}
	err := DecryptPrivateKeysWithConfig(context.Background(), keys, passphrase, config)
	if !goerrors.Is(err, s2k.ErrS2KBudgetExceeded) {
		t.Fatalf("budget failure error = %v, want ErrS2KBudgetExceeded", err)
	}
	assertKeysEncrypted(t, keys, fingerprints)

	if err := DecryptPrivateKeysWithConfig(context.Background(), keys, passphrase, nil); err != nil {
		t.Fatal(err)
	}
	assertKeysDecryptedAndValid(t, keys)
}

func TestDecryptWithCacheInvalidatesFailedDerivation(t *testing.T) {
	keys := makeUnlockTestKeys(t)
	passphrase := []byte("correct passphrase")
	encryptUnlockTestKeys(t, keys, passphrase)
	key := keys[0]

	cache := &s2k.Cache{}
	generation := cache.Generation()
	if err := key.decryptWithCache([]byte("wrong passphrase"), cache); err == nil {
		t.Fatal("decryption with a wrong passphrase succeeded")
	}
	if !key.Encrypted || key.PrivateKey != nil {
		t.Fatal("failed decryption modified the key")
	}
	if cache.Len() != 0 {
		t.Fatalf("failed decryption left %d cache entries", cache.Len())
	}
	if cache.Generation() == generation {
		t.Fatal("failed decryption did not advance the cache generation")
	}

	if err := key.decryptWithCache(passphrase, cache); err != nil {
		t.Fatal(err)
	}
	if key.Encrypted || key.PrivateKey == nil {
		t.Fatal("retry with the correct passphrase did not decrypt the key")
	}
}

func TestDecryptPrivateKeysWithCacheObservesGenerationAndIdentity(t *testing.T) {
	keys := makeUnlockTestKeys(t)
	passphrase := []byte("correct passphrase")
	if err := EncryptPrivateKeys(keys, passphrase, unlockTestConfig()); err != nil {
		t.Fatal(err)
	}

	fingerprints := make([][]byte, len(keys))
	for i, key := range keys {
		fingerprints[i] = append([]byte(nil), key.Fingerprint...)
	}

	cache := &s2k.Cache{}
	generation := cache.Generation()
	if err := DecryptPrivateKeysWithCache(context.Background(), keys, []byte("wrong passphrase"), cache); err == nil {
		t.Fatal("batch decrypt with a wrong passphrase succeeded")
	}
	if cache.Len() != 0 {
		t.Fatalf("failed batch left %d cache entries", cache.Len())
	}
	if cache.Generation() == generation {
		t.Fatal("failed batch did not advance the cache generation")
	}
	assertKeysEncrypted(t, keys, fingerprints)

	if err := DecryptPrivateKeysWithCache(context.Background(), keys, passphrase, cache); err != nil {
		t.Fatal(err)
	}
	assertKeysDecryptedAndValid(t, keys)
	// EncryptPrivateKeys uses one S2K parameter set for the whole batch, so
	// the successful unlock should have derived exactly one key.
	if got := cache.Len(); got != 1 {
		t.Fatalf("successful batch cached %d derivations, want 1", got)
	}
}

func TestDecryptPrivateKeysOldKeysRemainSupported(t *testing.T) {
	for i, test := range privateKeyTests {
		packet, err := Read(readerFromHex(test.privateKeyHex))
		if err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
		key := packet.(*PrivateKey)

		if err := DecryptPrivateKeys([]*PrivateKey{key}, []byte("wrong password")); err == nil {
			t.Fatalf("key %d: decrypted with a wrong passphrase", i)
		}
		if !key.Encrypted || key.PrivateKey != nil {
			t.Fatalf("key %d: failed unlock modified the key", i)
		}

		if err := DecryptPrivateKeys([]*PrivateKey{key}, []byte("testing")); err != nil {
			t.Fatalf("key %d: failed to decrypt old key: %v", i, err)
		}
		if key.Encrypted || key.PrivateKey == nil {
			t.Fatalf("key %d: old key was not decrypted", i)
		}
	}
}

func TestDecryptPrivateKeysIgnoresDummyKeys(t *testing.T) {
	params, err := s2k.ParseIntoParams(bytes.NewReader([]byte{101, 2, 'G', 'N', 'U', 1}))
	if err != nil {
		t.Fatal(err)
	}
	dummy := &PrivateKey{Encrypted: true, s2kParams: params}
	if !dummy.Dummy() {
		t.Fatal("parsed S2K parameters are not a dummy key")
	}

	if err := DecryptPrivateKeys([]*PrivateKey{dummy}, []byte("passphrase")); err != nil {
		t.Fatalf("batch unlock treated a dummy key as an error: %v", err)
	}
	if !dummy.Encrypted || dummy.PrivateKey != nil {
		t.Fatal("dummy key was modified by a batch unlock")
	}
	if err := dummy.Decrypt([]byte("passphrase")); err == nil {
		t.Fatal("direct decryption of a dummy key succeeded")
	}
}
