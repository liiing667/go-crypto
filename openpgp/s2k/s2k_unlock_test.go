// Copyright (C) 2026 Proton AG. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package s2k

import (
	"bytes"
	"context"
	goerrors "errors"
	"sync"
	"testing"
)

func testIteratedParams(countByte byte) *Params {
	return &Params{
		mode:      IteratedSaltedS2K,
		hashId:    2, // SHA-1
		countByte: countByte,
	}
}

func directDerivedKey(t *testing.T, params *Params, passphrase []byte, size int) []byte {
	t.Helper()
	out := make([]byte, size)
	if err := params.Derive(context.Background(), out, passphrase); err != nil {
		t.Fatalf("direct derivation failed: %v", err)
	}
	return out
}

func TestS2KCacheSeparatesPassphrases(t *testing.T) {
	params := testIteratedParams(96)
	cache := &Cache{}

	first, err := cache.GetOrComputeDerivedKey([]byte("first"), params, 16)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cache.GetOrComputeDerivedKey([]byte("second"), params, 16)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("different passphrases reused the same derived key")
	}
	if got := cache.Len(); got != 2 {
		t.Fatalf("cache has %d entries, want 2", got)
	}

	// The original cache bug stored the lookup variable instead of the
	// derived key. Asking again must return the complete derivation.
	again, err := cache.GetOrComputeDerivedKey([]byte("first"), params, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, again) {
		t.Fatal("cache did not preserve the complete derived key")
	}
	want := directDerivedKey(t, params, []byte("first"), 16)
	if !bytes.Equal(first, want) {
		t.Fatalf("cached key %x does not match direct derivation %x", first, want)
	}
}

type cancelAfterChecksContext struct {
	context.Context
	remaining int
}

func (c *cancelAfterChecksContext) Err() error {
	if c.remaining <= 0 {
		return context.Canceled
	}
	c.remaining--
	return nil
}

func TestS2KCacheDoesNotPublishCanceledDerivation(t *testing.T) {
	params := testIteratedParams(224) // 16 MiB, large enough to check cancellation mid-derivation
	cache := &Cache{}
	ctx := &cancelAfterChecksContext{
		Context:   context.Background(),
		remaining: 5,
	}
	tx := cache.BeginTransaction(ctx, Budget{})

	if _, err := tx.DeriveKey([]byte("passphrase"), params, 16); !goerrors.Is(err, context.Canceled) {
		t.Fatalf("DeriveKey error = %v, want context.Canceled", err)
	}
	if tx.Committed() {
		t.Fatal("canceled transaction reported itself as committed")
	}
	if got := cache.Len(); got != 0 {
		t.Fatalf("canceled derivation left %d cache entries", got)
	}
	if cache.Generation() == tx.Generation() {
		t.Fatal("abort did not advance the cache generation")
	}

	// A retry with a live transaction must derive the key from scratch.
	retry := cache.BeginTransaction(context.Background(), DefaultUnlockBudget())
	key, err := retry.DeriveKey([]byte("passphrase"), params, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := retry.Commit(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, directDerivedKey(t, params, []byte("passphrase"), 16)) {
		t.Fatal("retry derived a different key")
	}
}

func TestS2KCacheContextCancellationOnLegacyEntryPoint(t *testing.T) {
	params := testIteratedParams(96)
	cache := &Cache{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := cache.GetOrComputeDerivedKeyWithContext(ctx, []byte("passphrase"), params, 16, nil); !goerrors.Is(err, context.Canceled) {
		t.Fatalf("GetOrComputeDerivedKeyWithContext error = %v, want context.Canceled", err)
	}
	if cache.Len() != 0 {
		t.Fatalf("canceled derivation left %d cache entries", cache.Len())
	}
}

func TestS2KBudgetRejectsBeforeDerivationAndRetrySucceeds(t *testing.T) {
	params := testIteratedParams(224) // a high, but common, iteration count
	cache := &Cache{}

	tooSmall := Budget{MaxIterations: 1024}
	tx := cache.BeginTransaction(context.Background(), tooSmall)
	if _, err := tx.DeriveKey([]byte("passphrase"), params, 16); !goerrors.Is(err, ErrS2KBudgetExceeded) {
		t.Fatalf("DeriveKey error = %v, want ErrS2KBudgetExceeded", err)
	}
	if got := cache.Len(); got != 0 {
		t.Fatalf("budget failure left %d cache entries", got)
	}

	// A new transaction gets a new budget and generation, so the rejected
	// derivation cannot poison the retry.
	retry := cache.BeginTransaction(context.Background(), DefaultUnlockBudget())
	key, err := retry.DeriveKey([]byte("passphrase"), params, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := retry.Commit(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, directDerivedKey(t, params, []byte("passphrase"), 16)) {
		t.Fatal("retry derived a different key")
	}
}

func TestS2KBudgetLimitsArgon2Memory(t *testing.T) {
	params := &Params{
		mode:        Argon2S2K,
		passes:      3,
		parallelism: 4,
		memoryExp:   16, // 64 MiB
	}
	budget := Budget{MaxArgon2Memory: 32 << 10}
	if _, err := budget.Check(params, 16); !goerrors.Is(err, ErrS2KBudgetExceeded) {
		t.Fatalf("Check error = %v, want ErrS2KBudgetExceeded", err)
	}
	if _, err := DefaultUnlockBudget().Check(params, 16); err != nil {
		t.Fatalf("default budget rejected a normal Argon2 key: %v", err)
	}
}

func TestS2KBudgetTotalWorkAndConcurrentPassphrases(t *testing.T) {
	params := testIteratedParams(96)
	passphrases := [][]byte{
		[]byte("alpha"),
		[]byte("bravo"),
		[]byte("charlie"),
		[]byte("delta"),
	}
	expected := make(map[string][]byte)
	for _, passphrase := range passphrases {
		expected[string(passphrase)] = directDerivedKey(t, params, passphrase, 16)
	}

	cache := &Cache{}
	tx := cache.BeginTransaction(context.Background(), Budget{
		MaxIterations: 1 << 20,
		MaxTotalWork:  4 * 65536, // exactly four derivations
	})

	var wg sync.WaitGroup
	errCh := make(chan error, len(passphrases))
	for _, passphrase := range passphrases {
		passphrase := passphrase
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, err := tx.DeriveKey(passphrase, params, 16)
			if err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(key, expected[string(passphrase)]) {
				errCh <- goerrors.New("concurrent derivation mixed passphrases")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestS2KIteratedContextCancelsMidDerivation(t *testing.T) {
	params := testIteratedParams(224)
	ctx := &cancelAfterChecksContext{
		Context:   context.Background(),
		remaining: 3,
	}
	out := make([]byte, 16)
	if err := params.Derive(ctx, out, []byte("passphrase")); !goerrors.Is(err, context.Canceled) {
		t.Fatalf("Derive error = %v, want context.Canceled", err)
	}
}

func TestParamsDeriveMatchesFunction(t *testing.T) {
	for i, test := range parseTests {
		if test.dummyKey {
			continue
		}
		params := &test.params
		function, err := params.Function()
		if err != nil {
			t.Fatalf("%d: Function: %v", i, err)
		}
		want := make([]byte, 16)
		function(want, []byte("hello"))

		got := make([]byte, 16)
		if err := params.Derive(context.Background(), got, []byte("hello")); err != nil {
			t.Fatalf("%d: Derive: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%d: Derive = %x, Function = %x", i, got, want)
		}
	}
}
