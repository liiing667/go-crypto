// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	mathrand "math/rand"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

const (
	maxMessageLen = 1 << 12
)

func TestCompressed(t *testing.T) {
	packet, err := Read(readerFromHex(compressedHex))
	if err != nil {
		t.Errorf("failed to read Compressed: %s", err)
		return
	}

	c, ok := packet.(*Compressed)
	if !ok {
		t.Error("didn't find Compressed packet")
		return
	}

	contents, err := io.ReadAll(c.Body)
	if err != nil && err != io.EOF {
		t.Error(err)
		return
	}

	expected, _ := hex.DecodeString(compressedExpectedHex)
	if !bytes.Equal(expected, contents) {
		t.Errorf("got:%x want:%x", contents, expected)
	}
}

const compressedHex = "a3013b2d90c4e02b72e25f727e5e496a5e49b11e1700"
const compressedExpectedHex = "cb1062004d14c8fe636f6e74656e74732e0a"

func TestCompressDecompressRandomizeFast(t *testing.T) {
	algorithms := []CompressionAlgo{
		CompressionZIP,
		CompressionZLIB,
	}
	plaintext := make([]byte, mathrand.Intn(maxMessageLen))
	rand.Read(plaintext)
	algo := algorithms[mathrand.Intn(len(algorithms))]
	compConfig := &CompressionConfig{
		Level: -1 + mathrand.Intn(11),
	}
	w := bytes.NewBuffer(nil)
	wc := &noOpCloser{w: w}
	wcomp, err := SerializeCompressed(wc, algo, compConfig)
	if err != nil {
		t.Fatal(err)
	}
	// Compress to w
	wcomp.Write(plaintext)
	wcomp.Close()
	// Read the packet and decompress
	p, err := Read(w)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := p.(*Compressed)
	if !ok {
		t.Error("didn't find Compressed packet")
	}
	contents, err := io.ReadAll(c.Body)
	if err != nil && err != io.EOF {
		t.Error(err)
	}
	if !bytes.Equal(contents, plaintext) {
		t.Error("Could not retrieve original after decompress")
	}
}

// serializeNestedCompressedMessage builds a message consisting of `layers`
// nested compressed packets wrapping a literal data packet with the given
// payload.
func serializeNestedCompressedMessage(t *testing.T, layers int, payload []byte) []byte {
	t.Helper()
	buf := bytes.NewBuffer(nil)
	w := io.WriteCloser(noOpCloser{w: buf})
	for i := 0; i < layers; i++ {
		wc, err := SerializeCompressed(w, CompressionZLIB, nil)
		if err != nil {
			t.Fatal(err)
		}
		w = wc
	}
	lw, err := SerializeLiteral(w, true, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lw.Write(payload); err != nil {
		t.Fatal(err)
	}
	// Closing the literal writer cascades and closes the whole chain of
	// compressed writers below it.
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// readNestedMessage walks all packets of msg, sharing a single decompression
// budget across all compression layers, and reads the literal data body.
func readNestedMessage(msg []byte, limit int64) error {
	packets := NewReader(bytes.NewReader(msg))
	remaining := limit
	for {
		p, err := packets.Next()
		if err != nil {
			return err
		}
		switch p := p.(type) {
		case *Compressed:
			if err := packets.Push(p.LimitedBodyReader(&remaining)); err != nil {
				return err
			}
		case *LiteralData:
			_, err := io.Copy(io.Discard, p.Body)
			return err
		}
	}
}

func TestLimitedBodyReaderCumulativeLimit(t *testing.T) {
	// Incompressible payload so that each layer decompresses to roughly
	// the payload size.
	payload := make([]byte, 800)
	rand.Read(payload)
	msg := serializeNestedCompressedMessage(t, 2, payload)

	// Each layer alone decompresses to less than 1024 bytes, but the
	// cumulative decompressed size of both layers exceeds it, so the
	// shared budget must be exhausted.
	if err := readNestedMessage(msg, 1024); err != errors.ErrMessageTooLarge {
		t.Errorf("expected ErrMessageTooLarge, got %v", err)
	}

	// A generous limit accommodates the whole multi-layer message.
	if err := readNestedMessage(msg, 1<<20); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestLimitedBodyReaderClosesDecompressor(t *testing.T) {
	msg := serializeNestedCompressedMessage(t, 1, make([]byte, 1024))
	p, err := NewReader(bytes.NewReader(msg)).Next()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := p.(*Compressed)
	if !ok {
		t.Fatal("didn't find Compressed packet")
	}
	limit := int64(10)
	if _, err := io.ReadAll(c.LimitedBodyReader(&limit)); err != errors.ErrMessageTooLarge {
		t.Fatalf("expected ErrMessageTooLarge, got %v", err)
	}
	dr, ok := c.Body.(*decompressionReader)
	if !ok {
		t.Fatal("expected decompressionReader body")
	}
	if !dr.readAll {
		t.Error("decompressor was not closed after hitting the limit")
	}
	// Closing again must be safe.
	if err := dr.Close(); err != nil {
		t.Error(err)
	}
}

type closeTrackingReader struct {
	io.Reader
	closed bool
}

func (r *closeTrackingReader) Close() error {
	r.closed = true
	return nil
}

func TestLimitedBodyReaderClosesBodyOnLimit(t *testing.T) {
	body := &closeTrackingReader{Reader: bytes.NewReader(make([]byte, 100))}
	c := &Compressed{Body: body}
	limit := int64(10)
	if _, err := io.ReadAll(c.LimitedBodyReader(&limit)); err != errors.ErrMessageTooLarge {
		t.Fatalf("expected ErrMessageTooLarge, got %v", err)
	}
	if !body.closed {
		t.Error("body was not closed after hitting the limit")
	}
}
