package openpgp

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

func secPacketLength(n int) []byte {
	switch {
	case n < 192:
		return []byte{byte(n)}
	case n < 8384:
		n -= 192
		return []byte{byte(n>>8) + 192, byte(n)}
	default:
		return []byte{0xff, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func secWrapPacket(tag byte, body []byte) []byte {
	out := []byte{0xc0 | tag}
	out = append(out, secPacketLength(len(body))...)
	return append(out, body...)
}

func secOnePassSig(keyId uint64) []byte {
	var body bytes.Buffer
	body.WriteByte(0x03)
	body.WriteByte(0x00)
	body.WriteByte(0x08)
	body.WriteByte(0x01)
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], keyId)
	body.Write(id[:])
	body.WriteByte(0x01)
	return secWrapPacket(4, body.Bytes())
}

func secLiteral(data []byte) []byte {
	var body bytes.Buffer
	body.WriteByte('b')
	body.WriteByte(0x00)
	body.Write([]byte{0x00, 0x00, 0x00, 0x00})
	body.Write(data)
	return secWrapPacket(11, body.Bytes())
}

func secSigNoIssuer() []byte {
	creation := []byte{0x05, 0x02, 0x00, 0x00, 0x00, 0x01}
	var body bytes.Buffer
	body.WriteByte(0x04)
	body.WriteByte(0x00)
	body.WriteByte(0x01)
	body.WriteByte(0x08)
	binary.Write(&body, binary.BigEndian, uint16(len(creation)))
	body.Write(creation)
	binary.Write(&body, binary.BigEndian, uint16(0))
	body.Write([]byte{0x00, 0x00})
	body.Write([]byte{0x00, 0x00})
	return secWrapPacket(2, body.Bytes())
}

func TestReadV1NilIssuerNoPanic(t *testing.T) {
	entity, err := NewEntity("test", "", "test@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, ok := entity.SigningKey(time.Now())
	if !ok {
		t.Fatal("no signing key")
	}

	var msg []byte
	msg = append(msg, secOnePassSig(signingKey.PublicKey.KeyId)...)
	msg = append(msg, secLiteral([]byte("hello"))...)
	msg = append(msg, secSigNoIssuer()...)

	md, err := ReadMessage(bytes.NewReader(msg), EntityList{entity}, nil, nil)
	if err != nil {
		return
	}
	io.Copy(io.Discard, md.UnverifiedBody)
}

func uid34371DetachedSignatureBytes(t *testing.T) []byte {
	t.Helper()
	signature, err := io.ReadAll(readerFromHex(detachedSignatureHex))
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func TestUid34371DetachedSignatureTrailingMalformedData(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2Hex))
	signature := append(uid34371DetachedSignatureBytes(t), 0x00)

	signer, err := CheckDetachedSignature(
		kring,
		bytes.NewBufferString(signedInput),
		bytes.NewReader(signature),
		nil,
	)
	if err == nil {
		t.Fatal("accepted a detached signature with trailing malformed data")
	}
	if signer != nil {
		t.Fatal("returned a signer for a detached signature with trailing malformed data")
	}
}

func TestUid34371DetachedSignatureEmptyOrMissingKeyring(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2Hex))

	for _, test := range []struct {
		name      string
		keyring   KeyRing
		signature io.Reader
	}{
		{name: "empty signature", keyring: kring, signature: bytes.NewReader(nil)},
		{name: "missing keyring", keyring: nil, signature: readerFromHex(detachedSignatureHex)},
		{name: "nil signature reader", keyring: kring, signature: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			signer, err := CheckDetachedSignature(
				test.keyring,
				bytes.NewBufferString(signedInput),
				test.signature,
				nil,
			)
			if err == nil {
				t.Fatal("accepted a detached signature without a verifiable signer")
			}
			if signer != nil {
				t.Fatal("returned a signer without a verifiable signature")
			}
		})
	}
}

func TestUid34371DetachedSignatureMultipleSignaturesAndPadding(t *testing.T) {
	kring, _ := ReadKeyRing(readerFromHex(testKeys1And2Hex))
	first := uid34371DetachedSignatureBytes(t)
	signature := append(append([]byte{}, first...), first...)
	signature = append(signature, secWrapPacket(21, []byte{0x00, 0x00, 0x00})...)

	signer, err := CheckDetachedSignature(
		kring,
		bytes.NewBufferString(signedInput),
		bytes.NewReader(signature),
		nil,
	)
	if err != nil {
		t.Fatalf("signature error: %s", err)
	}
	if signer == nil || signer.PrimaryKey.KeyId != testKey1KeyId {
		t.Fatal("did not return the expected signer")
	}
}
