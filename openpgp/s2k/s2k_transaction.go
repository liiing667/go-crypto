// Copyright (C) 2026 Proton AG. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package s2k

import (
	"context"
	goerrors "errors"
	"fmt"
	"sync"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// ErrUnlockTransactionClosed is returned when a derivation is attempted on a
// transaction that has already been committed or aborted.
var ErrUnlockTransactionClosed = goerrors.New("openpgp: s2k unlock transaction is closed")

// UnlockTransaction ties the S2K parameter budget, the derivation work, the
// cancellation state, the cache generation, and the key identity checks for
// one batch unlock together.
//
// A transaction either commits as a whole or is aborted. Aborting drops every
// cache entry created by the transaction and advances the cache generation, so
// a canceled or failed derivation can never be reused by a later entity.
type UnlockTransaction struct {
	cache      *Cache
	generation uint64
	budget     Budget
	ctx        context.Context

	mu        sync.Mutex
	remaining uint64
	done      bool
	committed bool
	err       error
}

// Transaction is an alias for UnlockTransaction.
type Transaction = UnlockTransaction

// NewUnlockTransaction creates a transaction backed by a fresh cache.
func NewUnlockTransaction(ctx context.Context, budget Budget) *UnlockTransaction {
	return (&Cache{}).BeginTransaction(ctx, budget)
}

// BeginTransaction starts a new cache generation and returns a transaction
// that consumes budget. A nil context is treated as context.Background().
func (c *Cache) BeginTransaction(ctx context.Context, budget Budget) *UnlockTransaction {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil {
		c = &Cache{}
	}
	generation := c.begin()
	remaining := budget.MaxTotalWork
	return &UnlockTransaction{
		cache:      c,
		generation: generation,
		budget:     budget,
		ctx:        ctx,
		remaining:  remaining,
	}
}

// Generation returns the cache generation owned by the transaction.
func (tx *UnlockTransaction) Generation() uint64 {
	if tx == nil {
		return 0
	}
	return tx.generation
}

// Cache returns the cache used by the transaction.
func (tx *UnlockTransaction) Cache() *Cache {
	if tx == nil {
		return nil
	}
	return tx.cache
}

// Budget returns the budget configured for the transaction.
func (tx *UnlockTransaction) Budget() Budget {
	if tx == nil {
		return Budget{}
	}
	return tx.budget
}

// Context returns the cancellation context of the transaction.
func (tx *UnlockTransaction) Context() context.Context {
	if tx == nil || tx.ctx == nil {
		return context.Background()
	}
	return tx.ctx
}

// Remaining returns the remaining total-work budget. The second result is
// false when the budget is unlimited.
func (tx *UnlockTransaction) Remaining() (uint64, bool) {
	if tx == nil {
		return 0, false
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.remaining, tx.budget.MaxTotalWork != 0
}

// DeriveKey derives a key within the transaction. Cache hits do not consume
// budget. A cache miss first checks the per-parameter limits and reserves the
// normalized work from the transaction budget, then performs the derivation.
// Any error aborts the transaction.
func (tx *UnlockTransaction) DeriveKey(passphrase []byte, params *Params, expectedKeySize int) ([]byte, error) {
	if tx == nil {
		return nil, errors.InvalidArgumentError("nil s2k unlock transaction")
	}
	if tx.cache == nil {
		return nil, errors.InvalidArgumentError("nil s2k unlock cache")
	}
	if params == nil {
		return nil, errors.InvalidArgumentError("missing s2k parameters")
	}
	if expectedKeySize <= 0 {
		return nil, errors.InvalidArgumentError("invalid s2k key size")
	}

	tx.mu.Lock()
	if tx.done {
		err := tx.err
		if err == nil {
			err = ErrUnlockTransactionClosed
		}
		tx.mu.Unlock()
		return nil, err
	}
	ctx := tx.ctx
	tx.mu.Unlock()

	if err := ctx.Err(); err != nil {
		tx.Abort(err)
		return nil, err
	}

	cost, err := tx.budget.check(params, expectedKeySize)
	if err != nil {
		tx.Abort(err)
		return nil, err
	}

	// A cache hit is free. Check this before reserving budget.
	key := cacheKeyFor(passphrase, params, expectedKeySize)
	if cached, ok := tx.cache.lookup(key, tx.generation); ok {
		if err := ctx.Err(); err != nil {
			tx.Abort(err)
			return nil, err
		}
		return cached, nil
	}

	tx.mu.Lock()
	if tx.done {
		err := tx.err
		if err == nil {
			err = ErrUnlockTransactionClosed
		}
		tx.mu.Unlock()
		return nil, err
	}
	if tx.budget.MaxTotalWork != 0 {
		if tx.remaining < cost {
			remaining := tx.remaining
			tx.mu.Unlock()
			err := fmt.Errorf("%w: %d bytes of work requested, %d remaining", ErrS2KBudgetExceeded, cost, remaining)
			tx.Abort(err)
			return nil, err
		}
		tx.remaining -= cost
	}
	tx.mu.Unlock()

	derivedKey, err := tx.cache.computeDerivedKey(ctx, key, passphrase, params, expectedKeySize, tx.generation)
	if err != nil {
		tx.Abort(err)
		return nil, err
	}
	return derivedKey, nil
}

// Commit publishes the derivations produced by the transaction. If the
// transaction was already aborted it returns the abort error.
func (tx *UnlockTransaction) Commit() error {
	if tx == nil {
		return nil
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if tx.done {
		return tx.err
	}
	tx.done = true
	tx.committed = true
	return nil
}

// Abort discards every cache entry from the transaction and advances the cache
// generation. Subsequent derivations on this transaction fail with the same
// error. Abort is idempotent.
func (tx *UnlockTransaction) Abort(err error) {
	if tx == nil {
		return
	}
	tx.mu.Lock()
	if tx.done {
		tx.mu.Unlock()
		return
	}
	if err == nil {
		err = ErrUnlockTransactionClosed
	}
	tx.done = true
	tx.err = err
	tx.mu.Unlock()
	if tx.cache != nil {
		tx.cache.abort(tx.generation)
	}
}

// Err returns the transaction error, if any.
func (tx *UnlockTransaction) Err() error {
	if tx == nil {
		return nil
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.err
}

// Cancel aborts the transaction with context.Canceled.
func (tx *UnlockTransaction) Cancel() {
	tx.Abort(context.Canceled)
}

// Rollback is an alias for Abort.
func (tx *UnlockTransaction) Rollback(err error) {
	tx.Abort(err)
}

// Committed reports whether the transaction has been committed.
func (tx *UnlockTransaction) Committed() bool {
	if tx == nil {
		return false
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.committed
}
