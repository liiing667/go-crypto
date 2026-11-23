// Copyright (C) 2019 ProtonTech AG

package packet

import (
	"crypto/cipher"
	"encoding/binary"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// aeadCrypter is an AEAD opener/sealer, its configuration, and data for en/decryption.
type aeadCrypter struct {
	aead           cipher.AEAD
	chunkSize      int
	nonce          []byte
	associatedData []byte       // Chunk-independent associated data
	chunkIndex     []byte       // Chunk counter
	packetTag      packetType   // SEIP packet (v2) or AEAD Encrypted Data packet
	bytesProcessed int          // Amount of plaintext bytes encrypted/decrypted
}

// computeNonce takes the incremental index and computes an eXclusive OR with
// the least significant 8 bytes of the receivers' initial nonce (see sec.
// 5.16.1 and 5.16.2). It returns the resulting nonce.
func (wo *aeadCrypter) computeNextNonce() (nonce []byte) {
	if wo.packetTag == packetTypeSymmetricallyEncryptedIntegrityProtected {
		return wo.nonce
	}

	nonce = make([]byte, len(wo.nonce))
	copy(nonce, wo.nonce)
	offset := len(wo.nonce) - 8
	for i := 0; i < 8; i++ {
		nonce[i+offset] ^= wo.chunkIndex[i]
	}
	return
}

// incrementIndex performs an integer increment by 1 of the integer represented by the
// slice, modifying it accordingly.
func (wo *aeadCrypter) incrementIndex() error {
	index := wo.chunkIndex
	if len(index) == 0 {
		return errors.AEADError("Index has length 0")
	}
	for i := len(index) - 1; i >= 0; i-- {
		if index[i] < 255 {
			index[i]++
			return nil
		}
		index[i] = 0
	}
	return errors.AEADError("cannot further increment index")
}

// aeadDecrypter reads and decrypts bytes. It buffers extra decrypted bytes when
// necessary, similar to aeadEncrypter.
type aeadDecrypter struct {
	aeadCrypter           // Embedded ciphertext opener
	reader      io.Reader // 'reader' is a partialLengthReader
	chunkBytes  []byte
	peekedBytes []byte    // Used to detect last chunk

	// pending holds a fully decrypted chunk that has not been released to the
	// caller yet. Plaintext is only published one chunk behind: a chunk is
	// handed out after the following chunk (or the final authentication tag)
	// has been successfully authenticated. This keeps the decryption state,
	// plaintext publication and the final Close() result inside a single
	// message transaction, so a short, truncated or replayed stream can never
	// expose partial plaintext nor report a successful completion.
	pending []byte

	// err records the first failure of the transaction. Once set, Read keeps
	// returning the same error and Close() fails deterministically.
	err error
	// done is true once the final authentication tag has been validated and
	// every authenticated plaintext byte has been published.
	done bool
}

// Read decrypts bytes and reads them into dst. It decrypts when necessary and
// buffers extra decrypted bytes. It returns the number of bytes copied into dst
// and an error.
//
// Read only returns plaintext that is part of an authenticated message
// transaction. Each decrypted chunk is held back until the next chunk, or the
// final authentication tag, is verified. If the stream is short, truncated,
// replayed or otherwise invalid, the transaction is aborted: no unverified
// plaintext is published and the same error is returned on every subsequent
// Read and from Close.
func (ar *aeadDecrypter) Read(dst []byte) (n int, err error) {
	// Drain authenticated, not yet published plaintext first.
	if len(ar.pending) > 0 {
		n = copy(dst, ar.pending)
		ar.pending = ar.pending[n:]
		return n, nil
	}

	// No authenticated plaintext is buffered: a finished transaction keeps
	// reporting EOF, a failed transaction keeps reporting its original error.
	// This makes retries after a short read or a failure deterministic and
	// prevents partial plaintext from leaking.
	if ar.done {
		return 0, io.EOF
	}
	if ar.err != nil {
		return 0, ar.err
	}

	if len(dst) == 0 {
		return 0, nil
	}

	// No authenticated data is buffered. Pull the next chunk from the wire.
	chunk, last, errChunk := ar.readChunk()
	if errChunk != nil {
		ar.fail(errChunk)
		return 0, ar.err
	}

	if last {
		// The final authentication tag is valid. The last chunk is the only
		// authenticated data left, so publishing it is safe.
		ar.done = true
		n = copy(dst, chunk)
		ar.pending = chunk[n:]
		if n == 0 {
			// An empty final chunk (e.g. an empty plaintext stream) yields an
			// immediate EOF.
			return 0, io.EOF
		}
		return n, nil
	}

	// Hold the chunk back until the next chunk/final tag authenticates.
	ar.pending = chunk
	n = copy(dst, ar.pending)
	ar.pending = ar.pending[n:]
	return n, nil
}

// fail aborts the message transaction. The recorded error is sticky: every
// later Read returns it and Close() can never succeed.
func (ar *aeadDecrypter) fail(err error) {
	if ar.err == nil {
		ar.err = err
	}
	// Drop any plaintext that has not been authenticated yet.
	ar.pending = nil
}

// readChunk reads and authenticates the next chunk of the stream. It returns
// the decrypted chunk, whether it is the final chunk and an error.
//
// The final chunk is only returned after the standalone final authentication
// tag has been validated against the total amount of plaintext. Any other
// chunk is returned without releasing its plaintext to the caller yet.
func (ar *aeadDecrypter) readChunk() (chunk []byte, last bool, err error) {
	tagLen := ar.aead.Overhead()

	// Read a chunk
	copy(ar.chunkBytes, ar.peekedBytes) // Copy bytes peeked in previous chunk or in initialization
	bytesRead, errRead := io.ReadFull(ar.reader, ar.chunkBytes[tagLen:])
	if errRead != nil && errRead != io.EOF && errRead != io.ErrUnexpectedEOF {
		return nil, false, errRead
	}

	if bytesRead > 0 {
		ar.peekedBytes = ar.chunkBytes[bytesRead:bytesRead+tagLen]

		chunk, err = ar.openChunk(ar.chunkBytes[:bytesRead])
		if err != nil {
			return nil, false, err
		}

		// A short read means there are no more bytes following the chunk, so
		// the carried tag bytes are the standalone final authentication tag.
		if errRead == io.EOF || errRead == io.ErrUnexpectedEOF {
			if err = ar.validateFinalTag(ar.peekedBytes); err != nil {
				return nil, false, err
			}
			return chunk, true, nil
		}
		return chunk, false, nil
	}

	// No further chunk bytes were available. If the stream ended exactly on a
	// chunk boundary, the carried peeked bytes are the standalone final
	// authentication tag. Validate it and finish the transaction with an empty
	// final chunk.
	if errRead == io.EOF || errRead == io.ErrUnexpectedEOF {
		if err = ar.validateFinalTag(ar.peekedBytes); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	}

	// No chunk data could be read. A well-formed stream always carries at
	// least one (possibly empty) authenticated chunk plus the final tag.
	// Reaching EOF here means the stream was truncated or is otherwise
	// malformed, so the transaction cannot complete.
	return nil, false, errors.ErrAEADTagVerification
}

// Close finalizes the message transaction. It drains any remaining chunk and
// validates the final authentication tag so that a caller which only read part
// of the body still gets an authoritative result.
//
// Close is idempotent. It returns nil only if the whole stream was
// authenticated; otherwise it returns the sticky transaction error.
func (ar *aeadDecrypter) Close() (err error) {
	if ar.err != nil {
		return ar.err
	}
	if ar.done {
		return nil
	}

	// Drain the stream, authenticating every remaining chunk and the final
	// tag, without publishing plaintext.
	for {
		chunk, last, errChunk := ar.readChunk()
		if errChunk != nil {
			ar.fail(errChunk)
			return ar.err
		}
		if last {
			ar.pending = nil
			ar.done = true
			return nil
		}
		// The chunk authenticated successfully but is superseded by the next
		// one; keep only the most recent chunk pending to bound memory use.
		ar.pending = chunk
	}
}

// openChunk decrypts and checks integrity of an encrypted chunk, returning
// the underlying plaintext and an error. It accesses peeked bytes from next
// chunk, to identify the last chunk and decrypt/validate accordingly.
func (ar *aeadDecrypter) openChunk(data []byte) ([]byte, error) {
	adata := ar.associatedData
	if ar.aeadCrypter.packetTag == packetTypeAEADEncrypted {
		adata = append(ar.associatedData, ar.chunkIndex...)
	}

	nonce := ar.computeNextNonce()
	plainChunk, err := ar.aead.Open(data[:0:len(data)], nonce, data, adata)
	if err != nil {
		return nil, errors.ErrAEADTagVerification
	}
	ar.bytesProcessed += len(plainChunk)
	if err = ar.aeadCrypter.incrementIndex(); err != nil {
		return nil, err
	}
	return plainChunk, nil
}

// Checks the summary tag. It takes into account the total decrypted bytes into
// the associated data. It returns an error, or nil if the tag is valid.
func (ar *aeadDecrypter) validateFinalTag(tag []byte) error {
	// Associated: tag, version, cipher, aead, chunk size, ...
	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, uint64(ar.bytesProcessed))

	adata := ar.associatedData
	if ar.aeadCrypter.packetTag == packetTypeAEADEncrypted {
		// ... index ...
		adata = append(ar.associatedData, ar.chunkIndex...)
	}

	// ... and total number of encrypted octets
	adata = append(adata, amountBytes...)
	nonce := ar.computeNextNonce()
	if _, err := ar.aead.Open(nil, nonce, tag, adata); err != nil {
		return errors.ErrAEADTagVerification
	}
	return nil
}

// aeadEncrypter encrypts and writes bytes. It encrypts when necessary according
// to the AEAD block size, and buffers the extra encrypted bytes for next write.
type aeadEncrypter struct {
	aeadCrypter                // Embedded plaintext sealer
	writer      io.WriteCloser // 'writer' is a partialLengthWriter
	chunkBytes  []byte
	offset      int
}

// Write encrypts and writes bytes. It encrypts when necessary and buffers extra
// plaintext bytes for next call. When the stream is finished, Close() MUST be
// called to append the final tag.
func (aw *aeadEncrypter) Write(plaintextBytes []byte) (n int, err error) {
	for n != len(plaintextBytes) {
		copied := copy(aw.chunkBytes[aw.offset:aw.chunkSize], plaintextBytes[n:])
		n += copied
		aw.offset += copied

		if aw.offset == aw.chunkSize {
			encryptedChunk, err := aw.sealChunk(aw.chunkBytes[:aw.offset])
			if err != nil {
				return n, err
			}
			_, err = aw.writer.Write(encryptedChunk)
			if err != nil {
				return n, err
			}
			aw.offset = 0
		}
	}
	return
}

// Close encrypts and writes the remaining buffered plaintext if any, appends
// the final authentication tag, and closes the embedded writer. This function
// MUST be called at the end of a stream.
func (aw *aeadEncrypter) Close() (err error) {
	// Encrypt and write a chunk if there's buffered data left, or if we haven't
	// written any chunks yet.
	if aw.offset > 0 || aw.bytesProcessed == 0 {
		lastEncryptedChunk, err := aw.sealChunk(aw.chunkBytes[:aw.offset])
		if err != nil {
			return err
		}
		_, err = aw.writer.Write(lastEncryptedChunk)
		if err != nil {
			return err
		}
	}
	// Compute final tag (associated data: packet tag, version, cipher, aead,
	// chunk size...
	adata := aw.associatedData

	if aw.aeadCrypter.packetTag == packetTypeAEADEncrypted {
		// ... index ...
		adata = append(aw.associatedData, aw.chunkIndex...)
	}

	// ... and total number of encrypted octets
	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, uint64(aw.bytesProcessed))
	adata = append(adata, amountBytes...)

	nonce := aw.computeNextNonce()
	finalTag := aw.aead.Seal(nil, nonce, nil, adata)
	_, err = aw.writer.Write(finalTag)
	if err != nil {
		return err
	}
	return aw.writer.Close()
}

// sealChunk Encrypts and authenticates the given chunk.
func (aw *aeadEncrypter) sealChunk(data []byte) ([]byte, error) {
	if len(data) > aw.chunkSize {
		return nil, errors.AEADError("chunk exceeds maximum length")
	}
	if aw.associatedData == nil {
		return nil, errors.AEADError("can't seal without headers")
	}
	adata := aw.associatedData
	if aw.aeadCrypter.packetTag == packetTypeAEADEncrypted {
		adata = append(aw.associatedData, aw.chunkIndex...)
	}

	nonce := aw.computeNextNonce()
	encrypted := aw.aead.Seal(data[:0], nonce, data, adata)
	aw.bytesProcessed += len(data)
	if err := aw.aeadCrypter.incrementIndex(); err != nil {
		return nil, err
	}
	return encrypted, nil
}
