package s2k

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// Cache stores keys derived with s2k functions to avoid recomputation when
// several keys use the same S2K parameters and passphrase.
//
// Entries are scoped to a generation. Starting an unlock transaction advances
// the generation, so results left over from an earlier batch (for example
// after a cancellation or a wrong passphrase) are never handed to a later
// entity. A failed derivation is never published: the cache is only updated
// after the complete S2K function has run successfully.
//
// The zero value is ready to use and safe for concurrent use.
type Cache struct {
	mu         sync.Mutex
	generation uint64
	entries    map[cacheKey]cacheEntry
}

type cacheKey struct {
	params         Params
	passphraseHash [sha256.Size]byte
	keySize        int
}

type cacheEntry struct {
	key        []byte
	generation uint64
}

// NewCache returns an empty S2K cache.
func NewCache() *Cache {
	return &Cache{}
}

func cacheKeyFor(passphrase []byte, params *Params, expectedKeySize int) cacheKey {
	return cacheKey{
		params:         *params,
		passphraseHash: sha256.Sum256(passphrase),
		keySize:        expectedKeySize,
	}
}

func cloneKey(key []byte) []byte {
	cloned := make([]byte, len(key))
	copy(cloned, key)
	return cloned
}

// ensureLocked initializes the cache. The caller must hold c.mu.
func (c *Cache) ensureLocked() {
	if c.entries == nil {
		c.entries = make(map[cacheKey]cacheEntry)
	}
	if c.generation == 0 {
		c.generation = 1
	}
}

// Generation returns the current cache generation. Every unlock transaction
// starts a new generation.
func (c *Cache) Generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()
	return c.generation
}

// Invalidate discards every cached derivation and starts a new generation.
// It is safe to call concurrently with derivations in progress; late results
// from the invalidated generation are not published.
func (c *Cache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()
	c.invalidateLocked()
}

// Reset is an alias for Invalidate.
func (c *Cache) Reset() {
	c.Invalidate()
}

// Clear is an alias for Invalidate.
func (c *Cache) Clear() {
	c.Invalidate()
}

func (c *Cache) invalidateLocked() {
	for key, entry := range c.entries {
		clear(entry.key)
		delete(c.entries, key)
	}
	c.generation++
}

// Len returns the number of derivations cached for the current generation.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()
	count := 0
	for _, entry := range c.entries {
		if entry.generation == c.generation {
			count++
		}
	}
	return count
}

// EntryCount is an alias for Len.
func (c *Cache) EntryCount() int {
	return c.Len()
}

// CurrentGeneration is an alias for Generation.
func (c *Cache) CurrentGeneration() uint64 {
	return c.Generation()
}

// begin starts a new generation for a single unlock operation.
func (c *Cache) begin() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()
	c.generation++
	generation := c.generation
	for key, entry := range c.entries {
		if entry.generation != generation {
			clear(entry.key)
			delete(c.entries, key)
		}
	}
	return generation
}

// abort discards all entries belonging to generation. If generation is still
// current, the generation is advanced so that derivations that finish late are
// not published for a subsequent entity.
func (c *Cache) abort(generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()
	for key, entry := range c.entries {
		if entry.generation == generation {
			clear(entry.key)
			delete(c.entries, key)
		}
	}
	if c.generation == generation {
		c.generation++
	}
}

func (c *Cache) lookup(key cacheKey, generation uint64) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()
	if generation != c.generation {
		return nil, false
	}
	entry, ok := c.entries[key]
	if !ok || entry.generation != generation {
		return nil, false
	}
	return cloneKey(entry.key), true
}

func (c *Cache) store(key cacheKey, derivedKey []byte, generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()
	if generation != c.generation {
		return
	}
	if old, ok := c.entries[key]; ok {
		clear(old.key)
	}
	c.entries[key] = cacheEntry{
		key:        cloneKey(derivedKey),
		generation: generation,
	}
}

// computeDerivedKey derives a key without touching the cache until the
// derivation has completed successfully.
func (c *Cache) computeDerivedKey(ctx context.Context, key cacheKey, passphrase []byte, params *Params, expectedKeySize int, generation uint64) ([]byte, error) {
	derivedKey := make([]byte, expectedKeySize)
	if err := params.Derive(ctx, derivedKey, passphrase); err != nil {
		clear(derivedKey)
		return nil, err
	}
	// Cancellation can race with the end of a derivation. Never publish a
	// result from a transaction that has already been canceled.
	if err := ctx.Err(); err != nil {
		clear(derivedKey)
		c.abort(generation)
		return nil, err
	}
	c.store(key, derivedKey, generation)
	return derivedKey, nil
}

// GetOrComputeDerivedKey tries to retrieve the key for the given S2K
// parameters and passphrase from the cache. If there is no hit, it derives the
// key with the S2K function, publishes it to the cache only after the complete
// derivation succeeded, and returns the key.
//
// The passphrase is part of the cache identity. A wrong passphrase can
// therefore never receive a key derived from another passphrase, even when the
// S2K parameters are identical (as they commonly are for several keys in one
// entity).
func (c *Cache) GetOrComputeDerivedKey(passphrase []byte, params *Params, expectedKeySize int) ([]byte, error) {
	return c.getOrComputeDerivedKey(context.Background(), passphrase, params, expectedKeySize, DefaultBudget, nil)
}

// GetOrComputeDerivedKeyWithContext is like GetOrComputeDerivedKey, but
// observes ctx and uses budget. If budget is nil, DefaultBudget is used.
func (c *Cache) GetOrComputeDerivedKeyWithContext(ctx context.Context, passphrase []byte, params *Params, expectedKeySize int, budget *Budget) ([]byte, error) {
	effective := DefaultBudget
	if budget != nil {
		effective = *budget
	}
	return c.getOrComputeDerivedKey(ctx, passphrase, params, expectedKeySize, effective, nil)
}

func (c *Cache) getOrComputeDerivedKey(ctx context.Context, passphrase []byte, params *Params, expectedKeySize int, budget Budget, remaining *uint64) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil {
		return nil, errors.InvalidArgumentError("nil s2k cache")
	}
	if params == nil {
		return nil, errors.InvalidArgumentError("missing s2k parameters")
	}
	if expectedKeySize <= 0 {
		return nil, errors.InvalidArgumentError("invalid s2k key size")
	}

	c.mu.Lock()
	c.ensureLocked()
	generation := c.generation
	c.mu.Unlock()

	key := cacheKeyFor(passphrase, params, expectedKeySize)
	if cached, ok := c.lookup(key, generation); ok {
		if err := ctx.Err(); err != nil {
			c.abort(generation)
			return nil, err
		}
		return cached, nil
	}

	cost, err := budget.check(params, expectedKeySize)
	if err != nil {
		c.abort(generation)
		return nil, err
	}
	if remaining != nil {
		if *remaining < cost {
			c.abort(generation)
			return nil, fmt.Errorf("%w: %d bytes of work requested, %d remaining", errors.ErrS2KBudgetExceeded, cost, *remaining)
		}
		*remaining -= cost
	}

	if err := ctx.Err(); err != nil {
		c.abort(generation)
		return nil, err
	}

	derivedKey, err := c.computeDerivedKey(ctx, key, passphrase, params, expectedKeySize, generation)
	if err != nil {
		c.abort(generation)
		return nil, err
	}
	return derivedKey, nil
}
