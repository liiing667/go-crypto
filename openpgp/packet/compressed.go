// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"compress/bzip2"
	"compress/flate"
	"compress/zlib"
	"io"
	"strconv"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// Compressed represents a compressed OpenPGP packet. The decompressed contents
// will contain more OpenPGP packets. See RFC 4880, section 5.6.
type Compressed struct {
	Body io.Reader
}

const (
	NoCompression      = flate.NoCompression
	BestSpeed          = flate.BestSpeed
	BestCompression    = flate.BestCompression
	DefaultCompression = flate.DefaultCompression
)

// CompressionConfig contains compressor configuration settings.
type CompressionConfig struct {
	// Level is the compression level to use. It must be set to
	// between -1 and 9, with -1 causing the compressor to use the
	// default compression level, 0 causing the compressor to use
	// no compression and 1 to 9 representing increasing (better,
	// slower) compression levels. If Level is less than -1 or
	// more then 9, a non-nil error will be returned during
	// encryption. See the constants above for convenient common
	// settings for Level.
	Level int
}

// decompressionReader ensures that the whole compression packet is read.
type decompressionReader struct {
	compressed   io.Reader
	decompressed io.ReadCloser
	readAll      bool
}

func newDecompressionReader(r io.Reader, decompressor io.ReadCloser) *decompressionReader {
	return &decompressionReader{
		compressed:   r,
		decompressed: decompressor,
	}
}

func (dr *decompressionReader) Read(data []byte) (n int, err error) {
	if dr.readAll {
		return 0, io.EOF
	}
	n, err = dr.decompressed.Read(data)
	if err == io.EOF {
		dr.readAll = true
		// Close the decompressor.
		if errDec := dr.decompressed.Close(); errDec != nil {
			return n, errDec
		}
		// Consume all remaining data from the compressed packet.
		consumeAll(dr.compressed)
	}
	return n, err
}

// Close closes the underlying decompressor. It is idempotent and safe to
// call even if the stream was already fully read.
func (dr *decompressionReader) Close() error {
	if dr.readAll {
		return nil
	}
	dr.readAll = true
	return dr.decompressed.Close()
}

func (c *Compressed) parse(r io.Reader) error {
	var buf [1]byte
	_, err := readFull(r, buf[:])
	if err != nil {
		return err
	}

	switch buf[0] {
	case 0:
		c.Body = r
	case 1:
		c.Body = newDecompressionReader(r, flate.NewReader(r))
	case 2:
		decompressor, err := zlib.NewReader(r)
		if err != nil {
			return err
		}
		c.Body = newDecompressionReader(r, decompressor)
	case 3:
		c.Body = newDecompressionReader(r, io.NopCloser(bzip2.NewReader(r)))
	default:
		err = errors.UnsupportedError("unknown compression algorithm: " + strconv.Itoa(int(buf[0])))
	}

	return err
}

// LimitedBodyReader wraps the provided body reader with a limiter that
// restricts the number of bytes read to the specified limit.
// The limit is a shared budget: the pointed-to value is decremented as bytes
// are read, so callers should pass a per-message copy such that all nested
// compression layers of a single message cumulatively consume the same
// budget. When the budget is exhausted, the body reader is closed if it
// implements io.Closer.
// If limit is nil, the reader is unbounded.
func (c *Compressed) LimitedBodyReader(limit *int64) io.Reader {
	if limit == nil {
		return c.Body
	}
	return &sharedLimitReader{body: c.Body, remaining: limit}
}

// sharedLimitReader is an io.Reader that fails with errors.ErrMessageTooLarge
// once the cumulative number of bytes read through all readers sharing the
// same remaining budget exceeds it. On exhaustion, it closes the underlying
// reader if it implements io.Closer, so that decompression resources are
// released immediately.
type sharedLimitReader struct {
	body      io.Reader
	remaining *int64
	closed    bool
}

func (l *sharedLimitReader) Read(p []byte) (int, error) {
	if *l.remaining <= 0 {
		l.closeBody()
		return 0, errors.ErrMessageTooLarge
	}

	n, err := l.body.Read(p)
	*l.remaining -= int64(n)

	if *l.remaining <= 0 {
		l.closeBody()
		return n, errors.ErrMessageTooLarge
	}
	if err != nil {
		l.closeBody()
	}

	return n, err
}

func (l *sharedLimitReader) closeBody() {
	if l.closed {
		return
	}
	l.closed = true
	if closer, ok := l.body.(io.Closer); ok {
		closer.Close()
	}
}

// compressedWriterCloser represents the serialized compression stream
// header and the compressor. Its Close() method ensures that both the
// compressor and serialized stream header are closed. Its Write()
// method writes to the compressor.
type compressedWriteCloser struct {
	sh io.Closer      // Stream Header
	c  io.WriteCloser // Compressor
}

func (cwc compressedWriteCloser) Write(p []byte) (int, error) {
	return cwc.c.Write(p)
}

func (cwc compressedWriteCloser) Close() (err error) {
	err = cwc.c.Close()
	if err != nil {
		return err
	}

	return cwc.sh.Close()
}

// SerializeCompressed serializes a compressed data packet to w and
// returns a WriteCloser to which the literal data packets themselves
// can be written and which MUST be closed on completion. If cc is
// nil, sensible defaults will be used to configure the compression
// algorithm.
func SerializeCompressed(w io.WriteCloser, algo CompressionAlgo, cc *CompressionConfig) (literaldata io.WriteCloser, err error) {
	compressed, err := serializeStreamHeader(w, packetTypeCompressed)
	if err != nil {
		return
	}

	_, err = compressed.Write([]byte{uint8(algo)})
	if err != nil {
		return
	}

	level := DefaultCompression
	if cc != nil {
		level = cc.Level
	}

	var compressor io.WriteCloser
	switch algo {
	case CompressionZIP:
		compressor, err = flate.NewWriter(compressed, level)
	case CompressionZLIB:
		compressor, err = zlib.NewWriterLevel(compressed, level)
	default:
		s := strconv.Itoa(int(algo))
		err = errors.UnsupportedError("Unsupported compression algorithm: " + s)
	}
	if err != nil {
		return
	}

	literaldata = compressedWriteCloser{compressed, compressor}

	return
}

// LimitReader is an io.Reader that fails with MessageToLarge if read bytes exceed N.
type LimitReader struct {
	R io.Reader // underlying reader
	N int64     // max bytes allowed
}

func (l *LimitReader) Read(p []byte) (int, error) {
	if l.N <= 0 {
		return 0, errors.ErrMessageTooLarge
	}

	n, err := l.R.Read(p)
	l.N -= int64(n)

	if err == nil && l.N <= 0 {
		err = errors.ErrMessageTooLarge
	}

	return n, err
}
