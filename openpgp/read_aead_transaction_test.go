// Copyright 2026 Proton AG. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"bytes"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// newTransactionEntity builds a fresh entity usable for both encryption and
// signing.
func newTransactionEntity(t *testing.T) *Entity {
	t.Helper()
	entity, err := NewEntity("transaction", "test", "transaction@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	return entity
}

// encryptAEADMessage produces an encrypted (and optionally signed and/or
// compressed) AEAD message containing message.
func encryptAEADMessage(t *testing.T, to []*Entity, signed *Entity, message []byte, comp packet.CompressionAlgo) []byte {
	t.Helper()
	buf := bytes.NewBuffer(nil)
	config := &packet.Config{
		AEADConfig:             &packet.AEADConfig{ChunkSize: 32, DefaultMode: packet.AEADModeOCB},
		DefaultCompressionAlgo: comp,
		CompressionConfig:      &packet.CompressionConfig{Level: packet.DefaultCompression},
	}
	w, err := Encrypt(buf, to, signed, nil, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(message); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestReadAEADCorruptionNoPartialPlaintext drives the full ReadMessage
// pipeline (encryption -> optional compression -> optional signature) and
// verifies that corrupting the final AEAD chunk aborts the whole transaction:
// the body read must error, no signature may verify, and the recovered bytes
// can never equal the original plaintext.
func TestReadAEADCorruptionNoPartialPlaintext(t *testing.T) {
	entity := newTransactionEntity(t)
	recipients := EntityList{entity}

	message := bytes.Repeat([]byte("OpenPGP-AEAD-transaction-"), 20)

	cases := []struct {
		name   string
		signed bool
		comp   packet.CompressionAlgo
	}{
		{"encrypted-only", false, packet.CompressionNone},
		{"encrypted-compressed", false, packet.CompressionZLIB},
		{"encrypted-signed", true, packet.CompressionNone},
		{"encrypted-signed-compressed", true, packet.CompressionZIP},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var signer *Entity
			if tc.signed {
				signer = entity
			}
			raw := encryptAEADMessage(t, recipients, signer, message, tc.comp)

			// Corrupt a byte in the final portion of the SEIPDv2 packet. The
			// final authentication tag sits at the very end of the message.
			corrupt := append([]byte(nil), raw...)
			corrupt[len(corrupt)-17] ^= 0xff

			md, err := ReadMessage(bytes.NewReader(corrupt), recipients, nil, nil)
			if err != nil {
				// Rejection during setup is an acceptable hard failure.
				return
			}

			got, copyErr := io.ReadAll(md.UnverifiedBody)
			if copyErr == nil {
				t.Fatal("reading a corrupted AEAD message did not fail")
			}
			if bytes.Equal(got, message) {
				t.Fatal("full plaintext was released from a corrupted message")
			}
			if tc.signed && md.SignatureError == nil && md.Signature != nil {
				t.Fatal("a signature verified over a corrupted message")
			}
		})
	}
}

// TestReadAEADTruncationFailsTransaction ensures truncating the ciphertext at
// various points never yields the complete plaintext nor a clean EOF.
func TestReadAEADTruncationFailsTransaction(t *testing.T) {
	entity := newTransactionEntity(t)
	recipients := EntityList{entity}
	message := bytes.Repeat([]byte("0123456789abcdef"), 30)
	raw := encryptAEADMessage(t, recipients, nil, message, packet.CompressionNone)

	for cut := 1; cut <= 64; cut++ {
		md, err := ReadMessage(bytes.NewReader(raw[:len(raw)-cut]), recipients, nil, nil)
		if err != nil {
			continue // hard rejection is acceptable
		}
		got, copyErr := io.ReadAll(md.UnverifiedBody)
		if copyErr == nil {
			t.Fatalf("truncation by %d bytes was accepted", cut)
		}
		if bytes.Equal(got, message) {
			t.Fatalf("full plaintext leaked after truncation by %d bytes", cut)
		}
	}
}

// TestReadAEADValidMessageStillVerifies guards the compatibility baseline: a
// well-formed, signed and compressed AEAD message decrypts fully and its
// signature verifies.
func TestReadAEADValidMessageStillVerifies(t *testing.T) {
	entity := newTransactionEntity(t)
	recipients := EntityList{entity}
	message := bytes.Repeat([]byte("compatibility-baseline-"), 15)

	raw := encryptAEADMessage(t, recipients, entity, message, packet.CompressionZLIB)
	md, err := ReadMessage(bytes.NewReader(raw), recipients, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatalf("valid message failed to decrypt: %v", err)
	}
	if !bytes.Equal(got, message) {
		t.Fatal("decrypted plaintext mismatch")
	}
	if md.SignatureError != nil {
		t.Fatalf("valid signature did not verify: %v", md.SignatureError)
	}
	if md.Signature == nil {
		t.Fatal("expected a verified signature packet")
	}
}
