// Copyright 2026 Proton AG. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto/rand"
	"io"
	mathrand "math/rand"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// buildSeipdV2Stream serializes a SEIPDv2 (V2 Symmetrically Encrypted) packet
// for the given plaintext and returns the raw packet bytes together with the
// session key. A small chunk size is used to exercise multi-chunk streams.
func buildSeipdV2Stream(t *testing.T, plaintext []byte, mode AEADMode, chunkSize uint64) ([]byte, []byte) {
	t.Helper()
	cipher := CipherAES128
	key := make([]byte, cipher.KeySize())
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer(nil)
	writer, err := SerializeSymmetricallyEncrypted(
		buf,
		cipher,
		true,
		CipherSuite{Cipher: cipher, Mode: mode},
		key,
		&Config{AEADConfig: &AEADConfig{ChunkSize: chunkSize, DefaultMode: mode}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), key
}

// openSeipdV2 parses and decrypts a serialized SEIPDv2 packet.
func openSeipdV2(t *testing.T, raw, key []byte) io.ReadCloser {
	t.Helper()
	p, err := Read(bytes.NewBuffer(raw))
	if err != nil {
		t.Fatal(err)
	}
	se, ok := p.(*SymmetricallyEncrypted)
	if !ok || se.Version != symmetricallyEncryptedVersionAead {
		t.Fatalf("expected a V2 SymmetricallyEncrypted packet, got %T", p)
	}
	rc, err := se.Decrypt(CipherFunction(0), key)
	if err != nil {
		t.Fatal(err)
	}
	return rc
}

// readWithSizes drains a reader using the given sequence of (cycling) read
// sizes, returning every byte released before the first error.
func readWithSizes(rc io.Reader, sizes []int) ([]byte, error) {
	var out []byte
	i := 0
	for {
		n := sizes[i%len(sizes)]
		i++
		buf := make([]byte, n)
		k, err := rc.Read(buf)
		out = append(out, buf[:k]...)
		if err != nil {
			if err == io.EOF {
				return out, nil
			}
			return out, err
		}
		if i > 1_000_000 {
			return out, errors.StructuralError("read loop did not terminate")
		}
	}
}

// TestAeadTransactionReleasesOnlyAuthenticatedData ensures that no plaintext is
// published before the message transaction authenticates. In particular, a
// corrupted stream must never surface the trailing (last) chunk, even though a
// naive streaming decrypter would have handed it out before the final tag was
// checked.
func TestAeadTransactionReleasesOnlyAuthenticatedData(t *testing.T) {
	modes := map[AEADMode]string{
		AEADModeOCB: "OCB",
		AEADModeGCM: "GCM",
		AEADModeEAX: "EAX",
	}
	for mode, label := range modes {
		// Several full chunks plus a partial final chunk.
		chunkSize := uint64(32)
		plaintext := make([]byte, 32*3+7)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatal(err)
		}
		raw, key := buildSeipdV2Stream(t, plaintext, mode, chunkSize)

		t.Run(label, func(t *testing.T) {
			// Corrupt the final data chunk, which sits just before the final
			// authentication tag.
			tagLen := mode.TagLength()
			corrupt := append([]byte(nil), raw...)
			pos := len(corrupt) - tagLen - 1 // last byte of the final chunk
			corrupt[pos] ^= 0xff

			rc := openSeipdV2(t, corrupt, key)
			got, readErr := readWithSizes(rc, []int{1, 5, 17, 64})
			closeErr := rc.Close()

			if readErr == nil && closeErr == nil {
				t.Fatal("corrupted final chunk was accepted")
			}
			if closeErr == nil {
				t.Fatal("Close reported success despite a corrupted final chunk")
			}
			// No released byte may belong to the unauthenticated final chunk.
			if len(got) > len(plaintext)-7 {
				t.Fatalf("leaked %d unauthenticated bytes from the final chunk", len(got)-(len(plaintext)-7))
			}
			// Everything that was released must match the genuine prefix.
			if !bytes.Equal(got, plaintext[:len(got)]) {
				t.Fatal("released plaintext does not match the authenticated prefix")
			}

			// The failure is sticky: retries keep failing without new data.
			k, err := rc.Read(make([]byte, 32))
			if k != 0 || err == nil {
				t.Fatal("retry after failure returned data or no error")
			}
			if err := rc.Close(); err == nil {
				t.Fatal("retry of Close succeeded after a failed transaction")
			}
		})
	}
}

// TestAeadTransactionMidStreamCorruption corrupts a middle chunk and verifies
// that the corrupted chunk itself, and every chunk after it, stay unpublished.
// Only fully authenticated prefix chunks may be released.
func TestAeadTransactionMidStreamCorruption(t *testing.T) {
	chunkSize := uint64(32)
	tagLen := AEADModeOCB.TagLength()
	plaintext := make([]byte, 32*5+13) // 5 full chunks + partial 6th chunk
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	raw, key := buildSeipdV2Stream(t, plaintext, AEADModeOCB, chunkSize)

	// Corrupt a byte inside the second data chunk (index 1), data region only.
	unit := int(chunkSize) + tagLen
	corrupt := append([]byte(nil), raw...)
	corrupt[unit+3] ^= 0xff // 4th byte of chunk 1's ciphertext

	rc := openSeipdV2(t, corrupt, key)
	got, readErr := readWithSizes(rc, []int{1, 4, 31, 64, 128})
	if readErr == nil {
		t.Fatal("mid-stream corruption did not produce a read error")
	}
	if err := rc.Close(); err == nil {
		t.Fatal("Close succeeded despite mid-stream corruption")
	}
	// Chunk 0 is the only chunk authenticated before the failure; at most its
	// 32 bytes may have been released.
	if len(got) > int(chunkSize) {
		t.Fatalf("leaked %d bytes beyond the authenticated prefix", len(got)-int(chunkSize))
	}
	if !bytes.Equal(got, plaintext[:len(got)]) {
		t.Fatal("released prefix does not match authenticated plaintext")
	}
}

// TestAeadTransactionTruncationNeverCompletes checks that short and truncated
// streams cannot produce a successful Close nor the complete plaintext.
func TestAeadTransactionTruncationNeverCompletes(t *testing.T) {
	chunkSize := uint64(32)
	plaintext := make([]byte, 32*4+11)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	raw, key := buildSeipdV2Stream(t, plaintext, AEADModeOCB, chunkSize)

	for cut := 1; cut < len(raw) && cut < 160; cut++ {
		truncated := raw[:len(raw)-cut]
		rc := openSeipdV2(t, truncated, key)
		got, _ := readWithSizes(rc, []int{3, 33, 77})
		if err := rc.Close(); err == nil {
			t.Fatalf("Close succeeded for stream truncated by %d bytes", cut)
		}
		if bytes.Equal(got, plaintext) {
			t.Fatalf("full plaintext leaked for stream truncated by %d bytes", cut)
		}
	}
}

// TestAeadTransactionValidRoundTrip confirms that valid streams still decrypt
// byte-for-byte across varied read sizes, including empty and chunk-aligned
// messages, and that Close is idempotent.
func TestAeadTransactionValidRoundTrip(t *testing.T) {
	cases := []int{0, 1, 31, 32, 33, 64, 32*3 + 7, 32 * 5}
	for _, plen := range cases {
		plaintext := make([]byte, plen)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatal(err)
		}
		raw, key := buildSeipdV2Stream(t, plaintext, AEADModeOCB, 32)
		rc := openSeipdV2(t, raw, key)
		got, err := readWithSizes(rc, []int{1, 2, 64, 7})
		if err != nil {
			t.Fatalf("length %d: unexpected read error: %v", plen, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("length %d: plaintext mismatch", plen)
		}
		if err := rc.Close(); err != nil {
			t.Fatalf("length %d: Close error: %v", plen, err)
		}
		if err := rc.Close(); err != nil {
			t.Fatalf("length %d: Close is not idempotent: %v", plen, err)
		}
	}
}

// TestAeadTransactionEarlyCloseAuthenticates verifies that a caller which only
// reads a few bytes and then Close()s still gets an authoritative result for
// the whole message: success for an intact stream, failure for a corrupt one.
func TestAeadTransactionEarlyCloseAuthenticates(t *testing.T) {
	plaintext := make([]byte, 32*6+3)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	raw, key := buildSeipdV2Stream(t, plaintext, AEADModeGCM, 32)

	// Intact stream: early Close must validate the entire message.
	rc := openSeipdV2(t, raw, key)
	buf := make([]byte, 5)
	if _, err := io.ReadFull(rc, buf); err != nil {
		t.Fatal(err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("early Close rejected an intact stream: %v", err)
	}

	// Corrupt stream: early Close must fail.
	corrupt := append([]byte(nil), raw...)
	corrupt[len(corrupt)-AEADModeGCM.TagLength()-1] ^= 0xff
	rc = openSeipdV2(t, corrupt, key)
	if _, err := rc.Read(make([]byte, 5)); err != nil {
		t.Fatalf("initial read of an intact prefix should not fail: %v", err)
	}
	if err := rc.Close(); err == nil {
		t.Fatal("early Close reported success for a corrupted stream")
	}
}

// TestLegacyAEADPacketTransaction covers the deprecated AEADEncrypted packet
// (tag 20) which shares the same decrypter transaction implementation.
func TestLegacyAEADPacketTransaction(t *testing.T) {
	config := randomConfig()
	key := randomKey(config.Cipher().KeySize())
	plaintext := make([]byte, 128+mathrand.Intn(64))
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	raw, _, err := randomStream(key, len(plaintext), config)
	if err != nil {
		t.Fatal(err)
	}

	// Valid round trip through the shared aeadDecrypter.
	packet := new(AEADEncrypted)
	if _, _, contents, err := readHeader(bytes.NewBuffer(raw.Bytes())); err != nil {
		t.Fatal(err)
	} else if err := packet.parse(contents); err != nil {
		t.Fatal(err)
	}
	rc, err := packet.Decrypt(config.Cipher(), key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readWithSizes(rc, []int{13, 1, 40})
	if err != nil {
		t.Fatalf("legacy AEAD read error: %v", err)
	}
	if !bytes.Equal(got, plaintext) || rc.Close() != nil {
		t.Fatal("legacy AEAD round trip mismatch or Close failure")
	}

	// A corrupted legacy packet must fail a Close and never fully decrypt.
	corrupt := append([]byte(nil), raw.Bytes()...)
	corrupt[len(corrupt)-1] ^= 0xff
	packet = new(AEADEncrypted)
	if _, _, contents, err := readHeader(bytes.NewBuffer(corrupt)); err != nil {
		t.Fatal(err)
	} else if err := packet.parse(contents); err != nil {
		t.Fatal(err)
	}
	rc, err = packet.Decrypt(config.Cipher(), key)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = readWithSizes(rc, []int{13, 1, 40})
	if err := rc.Close(); err == nil {
		t.Fatal("legacy AEAD Close succeeded on a corrupted packet")
	}
	if bytes.Equal(got, plaintext) {
		t.Fatal("legacy AEAD leaked the full plaintext of a corrupted packet")
	}
}
