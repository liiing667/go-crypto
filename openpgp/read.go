// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package openpgp implements high level operations on OpenPGP messages.
package openpgp // import "github.com/ProtonMail/go-crypto/openpgp"

import (
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding"
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
	// A message read is one decryption transaction. Freeze both the keyring
	// view and the verification clock so recipient and signer resolution, key
	// ids/fingerprints, usage checks and the final MessageDetails identity all
	// refer to the same generation.
	keyring = snapshotKeyRing(keyring)
	now := config.Now()

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
			return readSignedMessage(packets, nil, keyring, now, config)
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
	mdFinal, sensitiveParsingErr := readSignedMessage(packets, md, keyring, now, config)
	if sensitiveParsingErr != nil {
		return nil, errors.HandleSensitiveParsingError(sensitiveParsingErr, md.decrypted != nil)
	}
	return mdFinal, nil
}

// readSignedMessage reads a possibly signed message if mdin is non-zero then
// that structure is updated and returned. Otherwise a fresh MessageDetails is
// used.
func readSignedMessage(packets *packet.Reader, mdin *MessageDetails, keyring KeyRing, now time.Time, config *packet.Config) (md *MessageDetails, err error) {
	if mdin == nil {
		mdin = new(MessageDetails)
	}
	md = mdin

	var p packet.Packet
	var h hash.Hash
	var wrappedHash hash.Hash
	var hashFunc crypto.Hash
	var candidates []Key
	var prevLast bool
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
			hashFunc = p.Hash

			md.IsSigned = true
			if p.Version == 6 {
				md.SignedByFingerprint = p.KeyFingerprint
			} else {
				md.SignedByFingerprint = nil
			}
			md.SignedByKeyId = p.KeyId

			// Resolve all candidates against the keyring snapshot now. A
			// signer with the same key id may be behind another entity in the
			// snapshot; verification below commits to the key that actually
			// verifies the signature.
			candidates = signingKeysByIdUsage(keyring, p.KeyId, p.KeyFingerprint, packet.KeyFlagSign)
			if len(candidates) > 0 {
				md.SignedBy = &candidates[0]
			}
		case *packet.LiteralData:
			md.LiteralData = p
			break FindLiteralData
		}
	}

	if md.IsSigned && md.SignatureError == nil {
		md.UnverifiedBody = &signatureCheckReader{
			packets:     packets,
			h:           h,
			wrappedHash: wrappedHash,
			hashFunc:    hashFunc,
			candidates:  candidates,
			md:          md,
			now:         now,
			config:      config,
		}
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

// cloneHashState copies a partially filled message hash. Verification mutates
// the hash by appending the signature suffix, so trying several keys with the
// same key id needs an independent copy for every attempt.
func cloneHashState(state hash.Hash, hashFunc crypto.Hash) (hash.Hash, bool) {
	if state == nil {
		return nil, false
	}
	marshaler, ok := state.(encoding.BinaryMarshaler)
	if !ok {
		return nil, false
	}
	serialized, err := marshaler.MarshalBinary()
	if err != nil {
		return nil, false
	}
	clone := hashFunc.New()
	unmarshaler, ok := clone.(encoding.BinaryUnmarshaler)
	if !ok {
		return nil, false
	}
	if err := unmarshaler.UnmarshalBinary(serialized); err != nil {
		return nil, false
	}
	return clone, true
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
	packets        *packet.Reader
	h, wrappedHash hash.Hash
	hashFunc       crypto.Hash
	candidates     []Key
	md             *MessageDetails
	now            time.Time
	config         *packet.Config
}

func (scr *signatureCheckReader) Read(buf []byte) (int, error) {
	n, sensitiveParsingError := scr.md.LiteralData.Body.Read(buf)

	// Hash only if required
	if scr.md.SignedBy != nil {
		scr.wrappedHash.Write(buf[:n])
	}

	readsDecryptedData := scr.md.decrypted != nil
	if sensitiveParsingError == io.EOF {
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

				// If signature KeyID matches, try every candidate captured for
				// this signature and commit to the one that actually verifies.
				if len(scr.candidates) > 0 && sig.IssuerKeyId != nil && *sig.IssuerKeyId == scr.md.SignedByKeyId {
					key, signatureError := scr.verifyCandidates(sig)
					if key != nil {
						scr.md.SignedBy = key
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

// verifyCandidates checks a trailing signature against the keys captured when
// the one-pass signature was parsed. Each attempt starts from the same message
// hash so a failed candidate cannot change the hash state used by the next.
func (scr *signatureCheckReader) verifyCandidates(sig *packet.Signature) (*Key, error) {
	var pristine hash.Hash
	if len(scr.candidates) > 1 {
		pristine, _ = cloneHashState(scr.h, scr.hashFunc)
	}

	var lastError error
	for index := range scr.candidates {
		key := &scr.candidates[index]
		if key.PublicKey == nil {
			continue
		}

		verifyHash := scr.h
		if index > 0 {
			var ok bool
			verifyHash, ok = cloneHashState(pristine, scr.hashFunc)
			if !ok {
				break
			}
		}
		if err := key.PublicKey.VerifySignature(verifyHash, sig); err != nil {
			lastError = err
			continue
		}
		return key, checkMessageSignatureDetailsAt(key, sig, scr.config, scr.now)
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

func verifyDetachedSignature(keyring KeyRing, signed, signature io.Reader, expectedHashes []crypto.Hash, checkHashes bool, config *packet.Config) (sig *packet.Signature, signer *Entity, err error) {
	var issuerKeyId uint64
	var hashFunc crypto.Hash
	var sigType packet.SignatureType
	var keys []Key
	var p packet.Packet

	keyring = snapshotKeyRing(keyring)
	now := config.Now()
	packets := packet.NewReader(signature)
	for {
		p, err = packets.Next()
		if err == io.EOF {
			return nil, nil, errors.ErrUnknownIssuer
		}
		if err != nil {
			return nil, nil, err
		}

		var ok bool
		sig, ok = p.(*packet.Signature)
		if !ok {
			return nil, nil, errors.StructuralError("non signature packet found")
		}
		if sig.IssuerKeyId == nil {
			return nil, nil, errors.StructuralError("signature doesn't have an issuer")
		}
		issuerKeyId = *sig.IssuerKeyId
		hashFunc = sig.Hash
		sigType = sig.SigType
		if checkHashes {
			matchFound := false
			// check for hashes
			for _, expectedHash := range expectedHashes {
				if hashFunc == expectedHash {
					matchFound = true
					break
				}
			}
			if !matchFound {
				return nil, nil, errors.StructuralError("hash algorithm or salt mismatch with cleartext message headers")
			}
		}
		keys = signingKeysByIdUsage(keyring, issuerKeyId, sig.IssuerFingerprint, packet.KeyFlagSign)
		if len(keys) > 0 {
			break
		}
	}

	if len(keys) == 0 {
		panic("unreachable")
	}

	h, err := sig.PrepareVerify()
	if err != nil {
		return nil, nil, err
	}
	wrappedHash, err := wrapHashForSignature(h, sigType)
	if err != nil {
		return nil, nil, err
	}

	if _, err := io.Copy(wrappedHash, signed); err != nil && err != io.EOF {
		return nil, nil, err
	}

	var pristine hash.Hash
	if len(keys) > 1 {
		pristine, _ = cloneHashState(h, sig.Hash)
	}
	for index := range keys {
		verifyHash := h
		if index > 0 {
			var ok bool
			verifyHash, ok = cloneHashState(pristine, sig.Hash)
			if !ok {
				break
			}
		}
		err = keys[index].PublicKey.VerifySignature(verifyHash, sig)
		if err == nil {
			return sig, keys[index].Entity, checkMessageSignatureDetailsAt(&keys[index], sig, config, now)
		}
	}

	return nil, nil, err
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
	return checkMessageSignatureDetailsAt(key, signature, config, config.Now())
}

func checkMessageSignatureDetailsAt(key *Key, signature *packet.Signature, config *packet.Config, now time.Time) error {
	primarySelfSignature, primaryIdentity := key.Entity.PrimarySelfSignature()
	signedBySubKey := key.PublicKey != key.Entity.PrimaryKey
	sigsToCheck := []*packet.Signature{signature, primarySelfSignature}
	if signedBySubKey {
		sigsToCheck = append(sigsToCheck, key.SelfSignature, key.SelfSignature.EmbeddedSignature)
	}
	for _, sig := range sigsToCheck {
		for _, notation := range sig.Notations {
			if notation.IsCritical && !config.KnownNotation(notation.Name) {
				return errors.SignatureError("unknown critical notation: " + notation.Name)
			}
		}
	}
	if key.Entity.Revoked(now) || // primary key is revoked
		(signedBySubKey && key.Revoked(now)) || // subkey is revoked
		(primaryIdentity != nil && primaryIdentity.Revoked(now)) { // primary identity is revoked for v4
		return errors.ErrKeyRevoked
	}
	if key.Entity.PrimaryKey.KeyExpired(primarySelfSignature, now) { // primary key is expired
		return errors.ErrKeyExpired
	}
	if signedBySubKey {
		if key.PublicKey.KeyExpired(key.SelfSignature, now) { // subkey is expired
			return errors.ErrKeyExpired
		}
	}
	for _, sig := range sigsToCheck {
		if sig.SigExpired(now) { // any of the relevant signatures are expired
			return errors.ErrSignatureExpired
		}
	}
	return nil
}
