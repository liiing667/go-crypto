package openpgp

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// txLiteralMessage is a raw, unencrypted and unsigned OpenPGP message
// consisting of a single literal data packet containing "hello".
var txLiteralMessage = []byte{
	0xcb, 0x0b, // new-format literal data packet, body length 11
	't', // text format
	0x00,                   // empty filename
	0x00, 0x00, 0x00, 0x00, // zero timestamp
	'h', 'e', 'l', 'l', 'o',
}

// txTrailingGarbage is not a valid packet header (the tag byte does not have
// its most significant bit set) and must abort any read transaction that
// tries to consume it.
var txTrailingGarbage = []byte{0x00, 0x00, 0x00}

func txArmorEncode(t *testing.T, blockType string, raw []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, blockType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// txCorruptChecksum flips one character of the CRC24 checksum line of an
// armored block so that the checksum no longer matches the body.
func txCorruptChecksum(armored string) string {
	i := strings.LastIndex(armored, "\n=")
	if i < 0 || i+3 >= len(armored) {
		return armored
	}
	replacement := byte('A')
	if armored[i+2] == 'A' {
		replacement = 'B'
	}
	return armored[:i+2] + string(replacement) + armored[i+3:]
}

// txReadArmoredMessage decodes the first armor block and reads the message
// from it, fully consuming the body of the message.
func txReadArmoredMessage(armored string) (*MessageDetails, []byte, error) {
	block, err := armor.Decode(strings.NewReader(armored))
	if err != nil {
		return nil, nil, err
	}
	md, err := ReadMessage(block.Body, nil, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return md, nil, err
	}
	return md, body, nil
}

// TestReadMessageArmoredTransaction checks that a valid armored message and
// the equivalent raw message yield the same message details and contents.
func TestReadMessageArmoredTransaction(t *testing.T) {
	armored := txArmorEncode(t, MessageType, txLiteralMessage)

	mdArmored, bodyArmored, err := txReadArmoredMessage(armored)
	if err != nil {
		t.Fatalf("reading valid armored message failed: %s", err)
	}

	mdRaw, err := ReadMessage(bytes.NewReader(txLiteralMessage), nil, nil, nil)
	if err != nil {
		t.Fatalf("reading valid raw message failed: %s", err)
	}
	bodyRaw, err := io.ReadAll(mdRaw.UnverifiedBody)
	if err != nil {
		t.Fatalf("reading valid raw message body failed: %s", err)
	}

	if !bytes.Equal(bodyArmored, bodyRaw) || !bytes.Equal(bodyArmored, []byte("hello")) {
		t.Errorf("message bodies differ: armored %q, raw %q", bodyArmored, bodyRaw)
	}
	if mdArmored.IsEncrypted != mdRaw.IsEncrypted || mdArmored.IsSigned != mdRaw.IsSigned {
		t.Errorf("message details differ: armored %+v, raw %+v", mdArmored, mdRaw)
	}
	if mdArmored.LiteralData == nil || mdRaw.LiteralData == nil {
		t.Error("expected literal data in both messages")
	}
}

// TestReadMessageArmoredEmptyLines checks that empty lines inside and around
// an armor block do not disturb the read transaction.
func TestReadMessageArmoredEmptyLines(t *testing.T) {
	armored := txArmorEncode(t, MessageType, txLiteralMessage)
	// Insert empty lines before the block and before the checksum line.
	armored = "\n\n" + strings.Replace(armored, "\n=", "\n\n=", 1)

	md, body, err := txReadArmoredMessage(armored)
	if err != nil {
		t.Fatalf("reading armored message with empty lines failed: %s", err)
	}
	if md == nil || !bytes.Equal(body, []byte("hello")) {
		t.Errorf("unexpected message: md=%v body=%q", md, body)
	}
}

// TestReadMessageArmoredCorruptChecksum checks that a message whose armor
// checksum does not match its body is not returned as a complete message.
func TestReadMessageArmoredCorruptChecksum(t *testing.T) {
	armored := txCorruptChecksum(txArmorEncode(t, MessageType, txLiteralMessage))

	_, _, err := txReadArmoredMessage(armored)
	if err == nil {
		t.Error("expected an error for a corrupt armor checksum, got nil")
	}
}

// TestReadMessageArmoredTruncated checks that an armor block that is not
// properly terminated is not returned as a complete message.
func TestReadMessageArmoredTruncated(t *testing.T) {
	armored := txArmorEncode(t, MessageType, txLiteralMessage)

	// Drop the -----END----- line.
	truncated := armored[:strings.LastIndex(armored, "-----END")]
	if _, _, err := txReadArmoredMessage(truncated); err == nil {
		t.Error("expected an error for a missing END line, got nil")
	}

	// Drop the checksum line as well.
	truncated = armored[:strings.LastIndex(armored, "\n=")]
	if _, _, err := txReadArmoredMessage(truncated); err == nil {
		t.Error("expected an error for a truncated armor body, got nil")
	}
}

// TestReadMessageArmoredEmptyBlock checks that an armor block without any
// packets does not yield a complete message.
func TestReadMessageArmoredEmptyBlock(t *testing.T) {
	armored := txArmorEncode(t, MessageType, nil)

	block, err := armor.Decode(strings.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	md, err := ReadMessage(block.Body, nil, nil, nil)
	if err == nil {
		t.Error("expected an error for an empty armor block, got nil")
	}
	if md != nil {
		t.Error("expected no message details for an empty armor block")
	}
}

// TestReadMessageTrailingGarbage checks that unconsumed trailing data after
// the message invalidates it instead of being silently ignored.
func TestReadMessageTrailingGarbage(t *testing.T) {
	raw := append(append([]byte{}, txLiteralMessage...), txTrailingGarbage...)

	md, err := ReadMessage(bytes.NewReader(raw), nil, nil, nil)
	if err != nil {
		t.Fatalf("reading message failed: %s", err)
	}
	if _, err := io.ReadAll(md.UnverifiedBody); err == nil {
		t.Error("expected an error for trailing garbage, got nil")
	}

	armored := txArmorEncode(t, MessageType, raw)
	if _, _, err := txReadArmoredMessage(armored); err == nil {
		t.Error("expected an error for armored trailing garbage, got nil")
	}
}

// txCancelingReader returns errTxCanceled after limit bytes have been read.
type txCancelingReader struct {
	r     io.Reader
	limit int
}

var errTxCanceled = errors.New("read canceled")

func (cr *txCancelingReader) Read(p []byte) (int, error) {
	if cr.limit <= 0 {
		return 0, errTxCanceled
	}
	if len(p) > cr.limit {
		p = p[:cr.limit]
	}
	n, err := cr.r.Read(p)
	cr.limit -= n
	return n, err
}

// TestReadMessageCanceled checks that a canceled underlying reader does not
// yield a complete message, neither while parsing nor while reading the
// message contents.
func TestReadMessageCanceled(t *testing.T) {
	// Cancellation before the first packet.
	md, err := ReadMessage(&txCancelingReader{r: bytes.NewReader(txLiteralMessage)}, nil, nil, nil)
	if err == nil {
		t.Error("expected an error for a canceled reader, got nil")
	}
	if md != nil {
		t.Error("expected no message details for a canceled reader")
	}

	// Cancellation in the middle of the literal data. The packet header
	// parsing consumes 8 bytes, so the message parses but its contents
	// cannot be read completely.
	md, err = ReadMessage(&txCancelingReader{r: bytes.NewReader(txLiteralMessage), limit: 10}, nil, nil, nil)
	if err != nil {
		t.Fatalf("reading message failed: %s", err)
	}
	if _, err := io.ReadAll(md.UnverifiedBody); err == nil {
		t.Error("expected an error for a canceled reader, got nil")
	}
}

// TestReadKeyRingArmoredTransaction checks that a multi-entity armored
// keyring yields the same entities as the equivalent raw keyring, and that a
// corrupt armor checksum invalidates the whole keyring instead of returning
// a partial result.
func TestReadKeyRingArmoredTransaction(t *testing.T) {
	rawKeyring, err := io.ReadAll(readerFromHex(testKeys1And2Hex))
	if err != nil {
		t.Fatal(err)
	}

	expected, err := ReadKeyRing(bytes.NewReader(rawKeyring))
	if err != nil {
		t.Fatalf("reading raw keyring failed: %s", err)
	}
	if len(expected) != 2 {
		t.Fatalf("expected 2 entities in raw keyring, got %d", len(expected))
	}

	armored := txArmorEncode(t, PublicKeyType, rawKeyring)
	block, err := armor.Decode(strings.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	fromArmor, err := ReadKeyRing(block.Body)
	if err != nil {
		t.Fatalf("reading armored keyring failed: %s", err)
	}
	if len(fromArmor) != len(expected) {
		t.Fatalf("entity count differs: armored %d, raw %d", len(fromArmor), len(expected))
	}
	for i := range expected {
		if fromArmor[i].PrimaryKey.KeyId != expected[i].PrimaryKey.KeyId {
			t.Errorf("entity %d key id differs: armored %X, raw %X",
				i, fromArmor[i].PrimaryKey.KeyId, expected[i].PrimaryKey.KeyId)
			continue
		}
		var rawSerialized, armorSerialized bytes.Buffer
		if err := expected[i].Serialize(&rawSerialized); err != nil {
			t.Fatal(err)
		}
		if err := fromArmor[i].Serialize(&armorSerialized); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rawSerialized.Bytes(), armorSerialized.Bytes()) {
			t.Errorf("entity %d differs between raw and armored keyring", i)
		}
	}

	// A corrupt checksum must invalidate the whole keyring.
	corrupt := txCorruptChecksum(armored)
	block, err = armor.Decode(strings.NewReader(corrupt))
	if err != nil {
		t.Fatal(err)
	}
	el, err := ReadKeyRing(block.Body)
	if err == nil {
		t.Error("expected an error for a corrupt armor checksum, got nil")
	}
	if el != nil {
		t.Error("expected no entities for a corrupt armor checksum")
	}

	// Trailing garbage after the keyring must invalidate it as well.
	withGarbage := txArmorEncode(t, PublicKeyType, append(rawKeyring, txTrailingGarbage...))
	block, err = armor.Decode(strings.NewReader(withGarbage))
	if err != nil {
		t.Fatal(err)
	}
	el, err = ReadKeyRing(block.Body)
	if err == nil {
		t.Error("expected an error for trailing garbage, got nil")
	}
	if el != nil {
		t.Error("expected no entities for trailing garbage")
	}
}
