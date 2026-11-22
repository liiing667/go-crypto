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

// aeadDecrypter authenticates and decrypts a complete stream. It stages
// plaintext internally and does not publish it until every chunk and the final
// tag have been verified.
type aeadDecrypter struct {
	aeadCrypter           // Embedded ciphertext opener
	reader      io.Reader // 'reader' is a partialLengthReader
	chunkBytes  []byte
	peekedBytes []byte    // Used to detect last chunk
	buffer      []byte    // Buffered decrypted bytes
	err         error     // Latched error of the whole message transaction
	staged      bool      // Whether the whole stream has been decrypted and authenticated
	closed      bool      // Whether Close has been called successfully
	sawChunk    bool      // Whether at least one data chunk was authenticated
}

// Read decrypts and authenticates the whole message before publishing any
// plaintext to the caller. AEAD chunks are authenticated individually, but the
// final tag authenticates the length of the complete stream. Returning earlier
// chunks before the final tag has been checked would let a caller consume
// plaintext from a message that is later found to be truncated or otherwise
// incomplete. The staged plaintext is only published after every chunk tag and
// the final tag have been verified.
func (ar *aeadDecrypter) Read(dst []byte) (n int, err error) {
	if ar.err != nil {
		return 0, ar.err
	}
	if !ar.staged {
		if err := ar.stage(); err != nil {
			return 0, err
		}
	}
	if ar.closed {
		return 0, io.EOF
	}

	// Return buffered plaintext bytes from previous calls
	if len(ar.buffer) > 0 {
		n = copy(dst, ar.buffer)
		if n == len(ar.buffer) {
			ar.buffer = nil
		} else {
			ar.buffer = ar.buffer[n:]
		}
		return n, nil
	}

	return 0, io.EOF
}

// readSource decrypts the next chunk from the stream. It is only used while
// staging the message transaction and never publishes data to the caller.
func (ar *aeadDecrypter) readSource(dst []byte) (n int, err error) {
	// Return buffered plaintext bytes from previous calls
	if len(ar.buffer) > 0 {
		n = copy(dst, ar.buffer)
		ar.buffer = ar.buffer[n:]
		return
	}

	// Read a chunk
	tagLen := ar.aead.Overhead()
	copy(ar.chunkBytes, ar.peekedBytes) // Copy bytes peeked in previous chunk or in initialization
	bytesRead, errRead := io.ReadFull(ar.reader, ar.chunkBytes[tagLen:])
	if errRead != nil && errRead != io.EOF && errRead != io.ErrUnexpectedEOF {
		return 0, errRead
	}

	if bytesRead > 0 {
		ar.sawChunk = true
		ar.peekedBytes = ar.chunkBytes[bytesRead:bytesRead+tagLen]

		decrypted, errChunk := ar.openChunk(ar.chunkBytes[:bytesRead])
		if errChunk != nil {
			return 0, errChunk
		}

		// Return decrypted bytes, buffering if necessary
		n = copy(dst, decrypted)
		ar.buffer = decrypted[n:]
		return
	}

	return 0, io.EOF
}

// stage drains and authenticates the complete stream into memory. Plaintext is
// only made available through ar.buffer if every chunk and the final tag are
// valid.
func (ar *aeadDecrypter) stage() error {
	if ar.staged {
		return ar.err
	}
	ar.staged = true

	var plaintext []byte
	var buf [32 * 1024]byte
	emptyReads := 0
	for {
		n, err := ar.readSource(buf[:])
		if n > 0 {
			plaintext = append(plaintext, buf[:n]...)
			emptyReads = 0
		} else if err == nil {
			emptyReads++
			if emptyReads >= 100 {
				return ar.fail(io.ErrNoProgress)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return ar.fail(err)
		}
	}

	if err := ar.validateFinalTag(ar.peekedBytes); err != nil {
		return ar.fail(err)
	}
	if !ar.sawChunk {
		// A complete stream always contains at least one data chunk (which
		// may be empty) before the final authentication tag. A bare final
		// tag must not be accepted as an empty message.
		return ar.fail(errors.ErrAEADTagVerification)
	}
	ar.buffer = plaintext
	return nil
}

func (ar *aeadDecrypter) fail(err error) error {
	ar.buffer = nil
	ar.err = err
	return err
}

// Close authenticates the stream if it has not been consumed yet and reports
// the same latched error as Read. A successful Close therefore means the whole
// message transaction, including every chunk tag and the final tag, succeeded.
func (ar *aeadDecrypter) Close() (err error) {
	if ar.err != nil {
		return ar.err
	}
	if !ar.staged {
		if err := ar.stage(); err != nil {
			return err
		}
	}
	ar.closed = true
	ar.buffer = nil
	return nil
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
