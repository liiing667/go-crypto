// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package openpgp implements high level operations on OpenPGP messages.
package openpgp // import "github.com/ProtonMail/go-crypto/openpgp"

import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"hash"
	"io"
	"strconv"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	_ "golang.org/x/crypto/sha3"
)

// SignatureType is the armor type for a PGP signature.
var SignatureType = "PGP SIGNATURE"

// MessageType is the armor type for a PGP message.
var MessageType = "PGP MESSAGE"

// readArmored reads an armored block with the given type.
func readArmored(r io.Reader, expectedType string) (body io.Reader, err error) {
	block, err := armor.Decode(r)
	if err != nil {
		return
	}

	if block.Type != expectedType {
		return nil, errors.InvalidArgumentError("expected '" + expectedType + "', got: " + block.Type)
	}

	return block.Body, nil
}

// MessageDetails contains the result of parsing an OpenPGP encrypted and/or
// signed message.
type MessageDetails struct {
	IsEncrypted              bool                // true if the message was encrypted.
	EncryptedToKeyIds        []uint64            // the list of recipient key ids.
	IsSymmetricallyEncrypted bool                // true if a passphrase could have decrypted the message.
	DecryptedWith            Key                 // the private key used to decrypt the message, if any.
	IsSigned                 bool                // true if the message is signed.
	SignedByKeyId            uint64              // the key id of the signer, if any.
	SignedByFingerprint      []byte              // the key fingerprint of the signer, if any.
	SignedBy                 *Key                // the key of the signer, if available.
	LiteralData              *packet.LiteralData // the metadata of the contents
	UnverifiedBody           io.Reader           // the contents of the message.

	// If IsSigned is true and SignedBy is non-zero then the signature will
	// be verified as UnverifiedBody is read. The signature cannot be
	// checked until the whole of UnverifiedBody is read so UnverifiedBody
	// must be consumed until EOF before the data can be trusted. Even if a
	// message isn't signed (or the signer is unknown) the data may contain
	// an authentication code that is only checked once UnverifiedBody has
	// been consumed. Once EOF has been seen, the following fields are
	// valid. (An authentication code failure is reported as a
	// SignatureError error when reading from UnverifiedBody.)
	Signature            *packet.Signature   // the signature packet itself.
	SignatureError       error               // nil if the signature is good.
	UnverifiedSignatures []*packet.Signature // all other unverified signature packets.

	decrypted io.ReadCloser
}

// A PromptFunction is used as a callback by functions that may need to decrypt
// a private key, or prompt for a passphrase. It is called with a list of
// acceptable, encrypted private keys and a boolean that indicates whether a
// passphrase is usable. It should either decrypt a private key or return a
// passphrase to try. If the decrypted private key or given passphrase isn't
// correct, the function will be called again, forever. Any error returned will
// be passed up.
type PromptFunction func(keys []Key, symmetric bool) ([]byte, error)

// A keyEnvelopePair is used to store a private key with the envelope that
// contains a symmetric key, encrypted with that key.
type keyEnvelopePair struct {
	key          Key
	encryptedKey *packet.EncryptedKey
}

// ReadMessage parses an OpenPGP message that may be signed and/or encrypted.
// The given KeyRing should contain both public keys (for signature
// verification) and, possibly encrypted, private keys for decrypting.
// If config is nil, sensible defaults will be used.
func ReadMessage(r io.Reader, keyring KeyRing, prompt PromptFunction, config *packet.Config) (md *MessageDetails, err error) {
	var p packet.Packet

	var symKeys []*packet.SymmetricKeyEncrypted
	var pubKeys []keyEnvelopePair
	// Integrity protected encrypted packet: SymmetricallyEncrypted or AEADEncrypted
	var edp packet.EncryptedDataPacket

	packets := packet.NewReader(r)
	md = new(MessageDetails)
	md.IsEncrypted = true
	// Use one keyring view for the whole decryption and verification
	// transaction. In particular, the recipient key and the signer must not be
	// resolved from two different keyring generations.
	keyring = snapshotKeyRing(keyring)

	// The message, if encrypted, starts with a number of packets
	// containing an encrypted decryption key. The decryption key is either
	// encrypted to a public key, or with a passphrase. This loop
	// collects these packets.
ParsePackets:
	for {
		p, err = packets.Next()
		if err != nil {
			return nil, err
		}
		switch p := p.(type) {
		case *packet.SymmetricKeyEncrypted:
			// This packet contains the decryption key encrypted with a passphrase.
			md.IsSymmetricallyEncrypted = true
			symKeys = append(symKeys, p)
		case *packet.EncryptedKey:
			// This packet contains the decryption key encrypted to a public key.
			md.EncryptedToKeyIds = append(md.EncryptedToKeyIds, p.KeyId)
			switch p.Algo {
			case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoElGamal, packet.PubKeyAlgoECDH,
				packet.PubKeyAlgoX25519, packet.PubKeyAlgoX448,
				packet.PubKeyAlgoMlkem768X25519, packet.PubKeyAlgoMlkem1024X448:
				break
			default:
				continue
			}
			if keyring != nil {
				var keys []Key
				if p.KeyId == 0 {
					keys = keyring.DecryptionKeys()
				} else {
					keys = keyring.KeysById(p.KeyId)
				}
				for _, k := range keys {
					pubKeys = append(pubKeys, keyEnvelopePair{k, p})
				}
			}
		case *packet.SymmetricallyEncrypted:
			if !p.IntegrityProtected && !config.AllowUnauthenticatedMessages() {
				return nil, errors.UnsupportedError("message is not integrity protected")
			}
			edp = p
			break ParsePackets
		case *packet.AEADEncrypted:
			edp = p
			break ParsePackets
		case *packet.Compressed, *packet.LiteralData, *packet.OnePassSignature:
			// This message isn't encrypted.
			if len(symKeys) != 0 || len(pubKeys) != 0 {
				return nil, errors.StructuralError("key material not followed by encrypted message")
			}
			packets.Unread(p)
			return readSignedMessage(packets, nil, keyring, config)
		}
	}

	var candidates []Key
	var decrypted io.ReadCloser

	// Now that we have the list of encrypted keys we need to decrypt at
	// least one of them or, if we cannot, we need to call the prompt
	// function so that it can decrypt a key or give us a passphrase.
FindKey:
	for {
		// See if any of the keys already have a private key available
		candidates = candidates[:0]
		candidateFingerprints := make(map[string]bool)

		for _, pk := range pubKeys {
			if pk.key.PrivateKey == nil {
				continue
			}
			if !pk.key.PrivateKey.Encrypted {
				if len(pk.encryptedKey.Key) == 0 {
					errDec := pk.encryptedKey.Decrypt(pk.key.PrivateKey, config)
					if errDec != nil {
						continue
					}
				}
				// Try to decrypt symmetrically encrypted
				decrypted, err = edp.Decrypt(pk.encryptedKey.CipherFunc, pk.encryptedKey.Key)
				if err != nil && err != errors.ErrKeyIncorrect {
					return nil, err
				}
				if decrypted != nil {
					md.DecryptedWith = pk.key
					break FindKey
				}
			} else {
				fpr := string(pk.key.PublicKey.Fingerprint[:])
				if v := candidateFingerprints[fpr]; v {
					continue
				}
				candidates = append(candidates, pk.key)
				candidateFingerprints[fpr] = true
			}
		}

		if len(candidates) == 0 && len(symKeys) == 0 {
			return nil, errors.ErrKeyIncorrect
		}

		if prompt == nil {
			return nil, errors.ErrKeyIncorrect
		}

		passphrase, err := prompt(candidates, len(symKeys) != 0)
		if err != nil {
			return nil, err
		}

		// Try the symmetric passphrase first
		if len(symKeys) != 0 && passphrase != nil {
			for _, s := range symKeys {
				key, cipherFunc, err := s.Decrypt(passphrase)
				// In v4, on wrong passphrase, session key decryption is very likely to result in an invalid cipherFunc:
				// only for < 5% of cases we will proceed to decrypt the data
				if err == nil {
					decrypted, err = edp.Decrypt(cipherFunc, key)
					if err != nil {
						return nil, err
					}
					if decrypted != nil {
						break FindKey
					}
				}
			}
		}
	}

	md.decrypted = decrypted
	if err := packets.Push(decrypted); err != nil {
		return nil, err
	}
	mdFinal, sensitiveParsingErr := readSignedMessage(packets, md, keyring, config)
	if sensitiveParsingErr != nil {
		return nil, errors.HandleSensitiveParsingError(sensitiveParsingErr, md.decrypted != nil)
	}
	return mdFinal, nil
}

// readSignedMessage reads a possibly signed message if mdin is non-zero then
// that structure is updated and returned. Otherwise a fresh MessageDetails is
// used.
func readSignedMessage(packets *packet.Reader, mdin *MessageDetails, keyring KeyRing, config *packet.Config) (md *MessageDetails, err error) {
	if mdin == nil {
		mdin = new(MessageDetails)
	}
	md = mdin

	var p packet.Packet
	var h hash.Hash
	var wrappedHash hash.Hash
	var prevLast bool
	var candidates []*keySelection
	var selectedHash crypto.Hash
	var selectedSigType packet.SignatureType
	var selectedSalt []byte
FindLiteralData:
	for {
		p, err = packets.Next()
		if err != nil {
			return nil, err
		}
		switch p := p.(type) {
		case *packet.Compressed:
			if err := packets.Push(p.LimitedBodyReader(config.DecompressedMessageSizeLimit())); err != nil {
				return nil, err
			}
		case *packet.OnePassSignature:
			if prevLast {
				return nil, errors.UnsupportedError("nested signature packets")
			}

			if p.IsLast {
				prevLast = true
			}

			h, wrappedHash, err = hashForSignature(p.Hash, p.SigType, p.Salt)
			if err != nil {
				md.SignatureError = err
			}
			selectedHash = p.Hash
			selectedSigType = p.SigType
			selectedSalt = append([]byte(nil), p.Salt...)

			md.IsSigned = true
			if p.Version == 6 {
				md.SignedByFingerprint = p.KeyFingerprint
			} else {
				md.SignedByFingerprint = nil
			}
			md.SignedByKeyId = p.KeyId

			// Resolve the candidate signer keys once, against one keyring
			// generation and one selection time. The trailing signature and
			// all of its validity checks must use this same selection.
			keys := signingKeysByIdUsage(keyring, p.KeyId, p.KeyFingerprint, packet.KeyFlagSign)
			candidates = make([]*keySelection, len(keys))
			for index := range keys {
				// The verification time is committed once, when the trailing
				// signature and the complete signed body are available. This
				// keeps a revocation that appears during the read visible to
				// the final check while still using a single instant for all
				// candidates and checks.
				candidates[index] = newKeySelection(keys[index], time.Time{})
				candidates[index].requiredUsage = packet.KeyFlagSign
			}
			md.SignedBy = nil
			if len(candidates) > 0 {
				// Preserve the historical behavior of exposing a signer as
				// soon as a matching key is known. Verification will replace
				// this with the exact key that verifies the signature.
				md.SignedBy = &candidates[0].key
			}
		case *packet.LiteralData:
			md.LiteralData = p
			break FindLiteralData
		}
	}

	if md.IsSigned && md.SignatureError == nil {
		reader := &signatureCheckReader{
			packets:         packets,
			h:               h,
			wrappedHash:     wrappedHash,
			md:              md,
			config:          config,
			candidates:      candidates,
			selectedHash:    selectedHash,
			selectedSigType: selectedSigType,
			selectedSalt:    selectedSalt,
		}
		// Normally there is exactly one candidate key and the body can be
		// hashed while it is streamed. If a key id collision produced more
		// than one candidate, keep the signed bytes so that every candidate
		// can be tried with a fresh hash state.
		if len(candidates) > 1 {
			reader.buffer = new(bytes.Buffer)
		}
		md.UnverifiedBody = reader
	} else if md.decrypted != nil {
		md.UnverifiedBody = &checkReader{md, false}
	} else {
		md.UnverifiedBody = md.LiteralData.Body
	}

	return md, nil
}

func wrapHashForSignature(hashFunc hash.Hash, sigType packet.SignatureType) (hash.Hash, error) {
	switch sigType {
	case packet.SigTypeBinary:
		return hashFunc, nil
	case packet.SigTypeText:
		return NewCanonicalTextHash(hashFunc), nil
	}
	return nil, errors.UnsupportedError("unsupported signature type: " + strconv.Itoa(int(sigType)))
}

// hashForSignature returns a pair of hashes that can be used to verify a
// signature. The signature may specify that the contents of the signed message
// should be preprocessed (i.e. to normalize line endings). Thus this function
// returns two hashes. The second should be used to hash the message itself and
// performs any needed preprocessing.
func hashForSignature(hashFunc crypto.Hash, sigType packet.SignatureType, sigSalt []byte) (hash.Hash, hash.Hash, error) {
	if _, ok := algorithm.HashToHashIdWithSha1(hashFunc); !ok {
		return nil, nil, errors.UnsupportedError("unsupported hash function")
	}
	if !hashFunc.Available() {
		return nil, nil, errors.UnsupportedError("hash not available: " + strconv.Itoa(int(hashFunc)))
	}
	h := hashFunc.New()
	if sigSalt != nil {
		h.Write(sigSalt)
	}
	wrappedHash, err := wrapHashForSignature(h, sigType)
	if err != nil {
		return nil, nil, err
	}
	switch sigType {
	case packet.SigTypeBinary:
		return h, wrappedHash, nil
	case packet.SigTypeText:
		return h, wrappedHash, nil
	}
	return nil, nil, errors.UnsupportedError("unsupported signature type: " + strconv.Itoa(int(sigType)))
}

// checkReader wraps an io.Reader from a LiteralData packet. When it sees EOF
// it closes the ReadCloser from any SymmetricallyEncrypted packet to trigger
// MDC checks.
type checkReader struct {
	md      *MessageDetails
	checked bool
}

func (cr *checkReader) Read(buf []byte) (int, error) {
	n, sensitiveParsingError := cr.md.LiteralData.Body.Read(buf)
	if sensitiveParsingError == io.EOF {
		if cr.checked {
			// Only check once
			return n, io.EOF
		}
		mdcErr := cr.md.decrypted.Close()
		if mdcErr != nil {
			return n, mdcErr
		}
		cr.checked = true
		return n, io.EOF
	}

	if sensitiveParsingError != nil {
		return n, errors.HandleSensitiveParsingError(sensitiveParsingError, true)
	}

	return n, nil
}

// signatureCheckReader wraps an io.Reader from a LiteralData packet and hashes
// the data as it is read. When it sees an EOF from the underlying io.Reader
// it parses and checks a trailing Signature packet and triggers any MDC checks.
type signatureCheckReader struct {
	packets         *packet.Reader
	h, wrappedHash  hash.Hash
	md              *MessageDetails
	config          *packet.Config
	candidates      []*keySelection
	selectedHash    crypto.Hash
	selectedSigType packet.SignatureType
	selectedSalt    []byte
	buffer          *bytes.Buffer
	now             time.Time
	nowSet          bool
}

func (scr *signatureCheckReader) Read(buf []byte) (int, error) {
	n, sensitiveParsingError := scr.md.LiteralData.Body.Read(buf)

	// Hash only if required
	if scr.md.SignedBy != nil {
		scr.wrappedHash.Write(buf[:n])
	}
	if scr.buffer != nil {
		scr.buffer.Write(buf[:n])
	}

	readsDecryptedData := scr.md.decrypted != nil
	if sensitiveParsingError == io.EOF {
		verificationTime := scr.now
		if !scr.nowSet {
			verificationTime = scr.config.Now()
			scr.now = verificationTime
			scr.nowSet = true
		}
		for _, selection := range scr.candidates {
			if selection.now.IsZero() {
				selection.now = verificationTime
			}
		}

		var p packet.Packet
		var readError error
		var sig *packet.Signature

		p, readError = scr.packets.Next()
		for readError == nil {
			var ok bool
			if sig, ok = p.(*packet.Signature); ok {
				if sig.Version == 5 && (sig.SigType == 0x00 || sig.SigType == 0x01) {
					sig.Metadata = scr.md.LiteralData
				}

				// If signature KeyID matches
				if len(scr.candidates) > 0 && signatureIssuerMatches(sig, scr.md.SignedByKeyId, scr.md.SignedByFingerprint) {
					selection, signatureError := scr.verifyWithCandidates(sig)
					if selection != nil {
						// Report the key that actually verified the
						// signature, not merely the first key id match.
						scr.md.SignedBy = &selection.key
					}
					scr.md.Signature = sig
					scr.md.SignatureError = signatureError
				} else {
					scr.md.UnverifiedSignatures = append(scr.md.UnverifiedSignatures, sig)
				}
			}

			p, readError = scr.packets.Next()
		}

		if scr.md.SignedBy != nil && scr.md.Signature == nil {
			if scr.md.UnverifiedSignatures == nil {
				scr.md.SignatureError = errors.StructuralError("LiteralData not followed by signature")
			} else {
				scr.md.SignatureError = errors.StructuralError("No matching signature found")
			}
		}

		// The SymmetricallyEncrypted packet, if any, might have an
		// unsigned hash of its own. In order to check this we need to
		// close that Reader.
		if scr.md.decrypted != nil {
			if sensitiveParsingError := scr.md.decrypted.Close(); sensitiveParsingError != nil {
				return n, errors.HandleSensitiveParsingError(sensitiveParsingError, true)
			}
		}
		return n, io.EOF
	}

	if sensitiveParsingError != nil {
		return n, errors.HandleSensitiveParsingError(sensitiveParsingError, readsDecryptedData)
	}

	return n, nil
}

// signatureIssuerMatches checks the issuer identity carried by a one-pass
// signature and its trailing signature packet. A key id match alone is not
// enough when a v6 fingerprint is available.
func signatureIssuerMatches(sig *packet.Signature, issuerKeyId uint64, issuerFingerprint []byte) bool {
	if sig == nil || sig.IssuerKeyId == nil || *sig.IssuerKeyId != issuerKeyId {
		return false
	}
	if len(issuerFingerprint) == 0 || len(sig.IssuerFingerprint) == 0 {
		return true
	}
	return bytes.Equal(issuerFingerprint, sig.IssuerFingerprint)
}

// verifyWithCandidates verifies sig against the candidates captured by the
// one-pass signature transaction. Each attempt uses either the single
// streaming hash or a fresh hash over the buffered signed body, so a failed
// candidate cannot corrupt the hash state used by the next one. The first
// candidate that cryptographically verifies is committed; its own entity's
// revocation and expiry state decides the final result.
func (scr *signatureCheckReader) verifyWithCandidates(sig *packet.Signature) (*keySelection, error) {
	fingerprint := sig.IssuerFingerprint
	var lastError error
	for _, selection := range scr.candidates {
		if len(fingerprint) > 0 && !bytes.Equal(selection.key.PublicKey.Fingerprint, fingerprint) {
			continue
		}

		h := scr.h
		if scr.buffer != nil {
			freshHash, wrappedHash, err := hashForSignature(scr.selectedHash, scr.selectedSigType, scr.selectedSalt)
			if err != nil {
				return nil, err
			}
			if _, err := wrappedHash.Write(scr.buffer.Bytes()); err != nil {
				return nil, err
			}
			h = freshHash
		} else if cloned, ok := cloneHashState(scr.h, scr.selectedHash); ok {
			h = cloned
		}

		if err := selection.key.PublicKey.VerifySignature(h, sig); err != nil {
			lastError = err
			continue
		}

		// Revocation may have been added to the selected entity while the
		// message was being read. Refreshing by the exact public key keeps
		// that state in the same entity and cannot borrow a status from a
		// different entity.
		selection.refreshFromEntity()
		return selection, checkKeySelectionDetails(selection, sig, scr.config)
	}
	if lastError == nil {
		lastError = errors.SignatureError("signature was not made by a candidate key")
	}
	return nil, lastError
}

// VerifyDetachedSignature takes a signed file and a detached signature and
// returns the signature packet and the entity the signature was signed by,
// if any, and a possible signature verification error.
// If the signer isn't known, ErrUnknownIssuer is returned.
func VerifyDetachedSignature(keyring KeyRing, signed, signature io.Reader, config *packet.Config) (sig *packet.Signature, signer *Entity, err error) {
	return verifyDetachedSignature(keyring, signed, signature, nil, false, config)
}

// VerifyDetachedSignatureAndHash performs the same actions as
// VerifyDetachedSignature and checks that the expected hash functions were used.
func VerifyDetachedSignatureAndHash(keyring KeyRing, signed, signature io.Reader, expectedHashes []crypto.Hash, config *packet.Config) (sig *packet.Signature, signer *Entity, err error) {
	return verifyDetachedSignature(keyring, signed, signature, expectedHashes, true, config)
}

// CheckDetachedSignature takes a signed file and a detached signature and
// returns the entity the signature was signed by, if any, and a possible
// signature verification error. If the signer isn't known,
// ErrUnknownIssuer is returned.
func CheckDetachedSignature(keyring KeyRing, signed, signature io.Reader, config *packet.Config) (signer *Entity, err error) {
	_, signer, err = verifyDetachedSignature(keyring, signed, signature, nil, false, config)
	return
}

// CheckDetachedSignatureAndHash performs the same actions as
// CheckDetachedSignature and checks that the expected hash functions were used.
func CheckDetachedSignatureAndHash(keyring KeyRing, signed, signature io.Reader, expectedHashes []crypto.Hash, config *packet.Config) (signer *Entity, err error) {
	_, signer, err = verifyDetachedSignature(keyring, signed, signature, expectedHashes, true, config)
	return
}

type detachedSignatureCandidate struct {
	signature *packet.Signature
	keys      []Key
}

func verifyDetachedSignature(keyring KeyRing, signed, signature io.Reader, expectedHashes []crypto.Hash, checkHashes bool, config *packet.Config) (sig *packet.Signature, signer *Entity, err error) {
	if signature == nil {
		return nil, nil, errors.InvalidArgumentError("nil signature reader")
	}
	if signed == nil {
		signed = bytes.NewReader(nil)
	}
	keyring = snapshotKeyRing(keyring)

	packets := packet.NewReader(signature)
	var candidates []detachedSignatureCandidate
	for {
		p, err := packets.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}

		sig, ok := p.(*packet.Signature)
		if !ok {
			if _, isPadding := p.(packet.Padding); isPadding {
				continue
			}
			return nil, nil, errors.StructuralError("non signature packet found")
		}
		if sig.IssuerKeyId == nil {
			return nil, nil, errors.StructuralError("signature doesn't have an issuer")
		}
		if checkHashes {
			matchFound := false
			for _, expectedHash := range expectedHashes {
				if sig.Hash == expectedHash {
					matchFound = true
					break
				}
			}
			if !matchFound {
				return nil, nil, errors.StructuralError("hash algorithm or salt mismatch with cleartext message headers")
			}
		}

		keys := signingKeysByIdUsage(keyring, *sig.IssuerKeyId, sig.IssuerFingerprint, packet.KeyFlagSign)
		if len(keys) > 0 {
			candidates = append(candidates, detachedSignatureCandidate{signature: sig, keys: keys})
		}
	}
	if len(candidates) == 0 {
		return nil, nil, errors.ErrUnknownIssuer
	}

	// Capture the verification time once for the whole detached-signature
	// transaction, including every candidate and every signature packet.
	now := config.Now()

	attempts := 0
	for _, candidate := range candidates {
		attempts += len(candidate.keys)
	}
	if attempts == 1 {
		for _, candidate := range candidates {
			if len(candidate.keys) == 1 {
				return verifyDetachedSignatureWithKey(signed, candidate.signature, candidate.keys[0], config, now)
			}
		}
	}

	signedData, err := io.ReadAll(signed)
	if err != nil {
		return nil, nil, err
	}

	var lastError error
	for _, candidate := range candidates {
		for _, key := range candidate.keys {
			h, err := candidate.signature.PrepareVerify()
			if err != nil {
				lastError = err
				continue
			}
			wrappedHash, err := wrapHashForSignature(h, candidate.signature.SigType)
			if err != nil {
				lastError = err
				continue
			}
			if _, err := wrappedHash.Write(signedData); err != nil {
				return nil, nil, err
			}
			if err := key.PublicKey.VerifySignature(h, candidate.signature); err != nil {
				lastError = err
				continue
			}

			// Commit to the key that actually verified the signature. Its
			// own entity decides usage, time and revocation; a retry must
			// not substitute another entity's conclusion.
			selection := newKeySelection(key, now)
			selection.requiredUsage = packet.KeyFlagSign
			selection.refreshFromEntity()
			return candidate.signature, key.Entity, checkKeySelectionDetails(selection, candidate.signature, config)
		}
	}
	if lastError == nil {
		lastError = errors.ErrUnknownIssuer
	}
	return nil, nil, lastError
}

func verifyDetachedSignatureWithKey(signed io.Reader, sig *packet.Signature, key Key, config *packet.Config, now time.Time) (verifiedSig *packet.Signature, signer *Entity, err error) {
	h, err := sig.PrepareVerify()
	if err != nil {
		return nil, nil, err
	}
	wrappedHash, err := wrapHashForSignature(h, sig.SigType)
	if err != nil {
		return nil, nil, err
	}
	if _, err := io.Copy(wrappedHash, signed); err != nil && err != io.EOF {
		return nil, nil, err
	}
	if err := key.PublicKey.VerifySignature(h, sig); err != nil {
		return nil, nil, err
	}
	selection := newKeySelection(key, now)
	selection.requiredUsage = packet.KeyFlagSign
	selection.refreshFromEntity()
	return sig, key.Entity, checkKeySelectionDetails(selection, sig, config)
}

// CheckArmoredDetachedSignature performs the same actions as
// CheckDetachedSignature but expects the signature to be armored.
func CheckArmoredDetachedSignature(keyring KeyRing, signed, signature io.Reader, config *packet.Config) (signer *Entity, err error) {
	body, err := readArmored(signature, SignatureType)
	if err != nil {
		return
	}

	return CheckDetachedSignature(keyring, signed, body, config)
}

// checkMessageSignatureDetails returns an error if:
//   - The signature (or one of the binding signatures mentioned below)
//     has a unknown critical notation data subpacket
//   - The primary key of the signing entity is revoked
//   - The primary identity is revoked
//   - The signature is expired
//   - The primary key of the signing entity is expired according to the
//     primary identity binding signature
//
// ... or, if the signature was signed by a subkey and:
//   - The signing subkey is revoked
//   - The signing subkey is expired according to the subkey binding signature
//   - The signing subkey binding signature is expired
//   - The signing subkey cross-signature is expired
//
// NOTE: The order of these checks is important, as the caller may choose to
// ignore ErrSignatureExpired or ErrKeyExpired errors, but should never
// ignore any other errors.
func checkMessageSignatureDetails(key *Key, signature *packet.Signature, config *packet.Config) error {
	if key == nil {
		return errors.InvalidArgumentError("openpgp: no key")
	}
	selection := newKeySelection(*key, config.Now())
	selection.refreshFromEntity()
	return checkKeySelectionDetails(selection, signature, config)
}
