// Copyright (C) 2026 Proton AG. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package s2k

import (
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
)

// ErrS2KBudgetExceeded is returned when an S2K parameter set exceeds the
// configured budget. Imported keys control their own S2K parameters, so the
// budget is checked before any hashing or memory allocation happens.
var ErrS2KBudgetExceeded = errors.ErrS2KBudgetExceeded

// ErrBudgetExceeded is an alias for ErrS2KBudgetExceeded.
var ErrBudgetExceeded = ErrS2KBudgetExceeded

// Budget limits the work that may be spent deriving S2K keys.
//
// A zero value is unlimited. Fields can be limited independently. Budgets are
// also used as a per-unlock transaction budget: MaxTotalWork bounds the sum of
// all derivations performed for one batch, while the other fields bound each
// individual S2K parameter set.
type Budget struct {
	// MaxIterations is the largest iterated-and-salted count allowed for
	// mode 3 S2K. The count is measured in hashed bytes, as defined by
	// RFC 4880 section 3.7.1.3.
	MaxIterations uint64
	// MaxArgon2Memory is the largest Argon2 memory size in KiB.
	MaxArgon2Memory uint32
	// MaxArgon2Passes is the largest Argon2 iteration count.
	MaxArgon2Passes uint8
	// MaxArgon2Parallelism is the largest Argon2 degree of parallelism.
	MaxArgon2Parallelism uint8
	// MaxTotalWork bounds the total normalized work (in bytes) for one
	// transaction. Zero means unlimited.
	MaxTotalWork uint64
}

// S2KBudget is an alias for Budget.
type S2KBudget = Budget

// DefaultBudget permits every representable iterated-and-salted count, while
// keeping Argon2 memory and total batch work within bounds that are reasonable
// for an interactive unlock.
var DefaultBudget = Budget{
	MaxIterations:        65011712, // RFC 4880 maximum representable count
	MaxArgon2Memory:      256 << 10, // 256 MiB
	MaxArgon2Passes:      64,
	MaxArgon2Parallelism: 64,
	MaxTotalWork:         1 << 31, // 2 GiB of hash/memory traffic per unlock
}

// DefaultUnlockBudget returns a copy of DefaultBudget.
func DefaultUnlockBudget() Budget {
	return DefaultBudget
}

// Check validates params against b and returns the normalized work estimate.
// A zero Budget is unlimited.
func (b Budget) Check(params *Params, expectedKeySize int) (uint64, error) {
	return b.check(params, expectedKeySize)
}

// IteratedCount returns the decoded iteration count for mode 3 S2K, or zero
// for all other modes.
func (params *Params) IteratedCount() int {
	if params == nil || params.mode != IteratedSaltedS2K {
		return 0
	}
	return decodeCount(params.countByte)
}

// IterationCount is an alias for IteratedCount.
func (params *Params) IterationCount() int {
	return params.IteratedCount()
}

// Argon2Memory returns the decoded Argon2 memory size in KiB, or zero for
// non-Argon2 parameters.
func (params *Params) Argon2Memory() uint32 {
	if params == nil || params.mode != Argon2S2K {
		return 0
	}
	return decodeMemory(params.memoryExp)
}

// MemoryKiB is an alias for Argon2Memory.
func (params *Params) MemoryKiB() uint32 {
	return params.Argon2Memory()
}

// Argon2Passes returns the Argon2 iteration count, or zero for non-Argon2
// parameters.
func (params *Params) Argon2Passes() uint8 {
	if params == nil || params.mode != Argon2S2K {
		return 0
	}
	return params.passes
}

// Passes is an alias for Argon2Passes.
func (params *Params) Passes() uint8 {
	return params.Argon2Passes()
}

// Argon2Parallelism returns the Argon2 degree of parallelism, or zero for
// non-Argon2 parameters.
func (params *Params) Argon2Parallelism() uint8 {
	if params == nil || params.mode != Argon2S2K {
		return 0
	}
	return params.parallelism
}

// Parallelism is an alias for Argon2Parallelism.
func (params *Params) Parallelism() uint8 {
	return params.Argon2Parallelism()
}

// Cost returns a normalized estimate of the work needed to derive a key of
// expectedKeySize bytes with these parameters. It is intentionally cheap to
// compute and is used for budget checks before starting a derivation.
func (params *Params) Cost(expectedKeySize int) uint64 {
	if params == nil {
		return 0
	}
	if expectedKeySize < 0 {
		expectedKeySize = 0
	}

	switch params.mode {
	case IteratedSaltedS2K:
		hashSize := 32
		if hashObj, ok := algorithm.HashIdToHashWithSha1(params.hashId); ok {
			if size := hashObj.Size(); size > 0 {
				hashSize = size
			}
		}
		rounds := uint64(1)
		if expectedKeySize > hashSize {
			rounds = uint64((expectedKeySize + hashSize - 1) / hashSize)
		}
		return uint64(params.IteratedCount()) * rounds
	case Argon2S2K:
		// Argon2 touches roughly memory * passes bytes. Use 64-bit
		// arithmetic because the maximum legal memory size is 2 GiB.
		return uint64(params.Argon2Memory()) * 1024 * uint64(params.Argon2Passes())
	default:
		// Simple and salted S2K only hash the passphrase once.
		return uint64(expectedKeySize) + 1
	}
}

// check validates params against b and returns the normalized work estimate.
func (b Budget) check(params *Params, expectedKeySize int) (uint64, error) {
	if params == nil {
		return 0, errors.InvalidArgumentError("missing s2k parameters")
	}
	switch params.mode {
	case IteratedSaltedS2K:
		count := uint64(params.IteratedCount())
		if b.MaxIterations != 0 && count > b.MaxIterations {
			return 0, fmt.Errorf("%w: iterated count %d exceeds %d", ErrS2KBudgetExceeded, count, b.MaxIterations)
		}
	case Argon2S2K:
		memory := params.Argon2Memory()
		if b.MaxArgon2Memory != 0 && memory > b.MaxArgon2Memory {
			return 0, fmt.Errorf("%w: argon2 memory %d KiB exceeds %d KiB", ErrS2KBudgetExceeded, memory, b.MaxArgon2Memory)
		}
		passes := params.Argon2Passes()
		if b.MaxArgon2Passes != 0 && passes > b.MaxArgon2Passes {
			return 0, fmt.Errorf("%w: argon2 passes %d exceeds %d", ErrS2KBudgetExceeded, passes, b.MaxArgon2Passes)
		}
		parallelism := params.Argon2Parallelism()
		if b.MaxArgon2Parallelism != 0 && parallelism > b.MaxArgon2Parallelism {
			return 0, fmt.Errorf("%w: argon2 parallelism %d exceeds %d", ErrS2KBudgetExceeded, parallelism, b.MaxArgon2Parallelism)
		}
	case SimpleS2K, SaltedS2K:
		// No stretch cost to limit.
	default:
		// Let Params.Derive report the unsupported mode, but do not let an
		// unknown mode bypass the total-work bound.
	}

	cost := params.Cost(expectedKeySize)
	if b.MaxTotalWork != 0 && cost > b.MaxTotalWork {
		return 0, fmt.Errorf("%w: work %d exceeds %d", ErrS2KBudgetExceeded, cost, b.MaxTotalWork)
	}
	return cost, nil
}
