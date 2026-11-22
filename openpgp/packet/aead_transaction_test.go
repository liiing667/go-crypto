package packet

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func serializeSeipdV2ForTransactionTest(t *testing.T, plaintext []byte, chunkSize uint64) ([]byte, []byte) {
	t.Helper()

	suite := CipherSuite{Cipher: CipherAES128, Mode: AEADModeOCB}
	key := make([]byte, suite.Cipher.KeySize())
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	var raw bytes.Buffer
	config := &Config{AEADConfig: &AEADConfig{ChunkSize: chunkSize}}
	w, err := SerializeSymmetricallyEncrypted(&raw, CipherFunction(0), true, suite, key, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes(), key
}

func decryptSeipdV2ForTransactionTest(t *testing.T, raw, key []byte) io.ReadCloser {
	t.Helper()

	p, err := Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	se, ok := p.(*SymmetricallyEncrypted)
	if !ok {
		t.Fatalf("expected *SymmetricallyEncrypted, got %T", p)
	}
	rc, err := se.Decrypt(CipherFunction(0), key)
	if err != nil {
		t.Fatal(err)
	}
	return rc
}

func TestSeipdV2TransactionPublishesOnlyAuthenticatedPlaintext(t *testing.T) {
	const chunkSize = 256
	plaintext := bytes.Repeat([]byte("authenticated chunk "), 64)
	raw, key := serializeSeipdV2ForTransactionTest(t, plaintext, chunkSize)

	corrupt := append([]byte(nil), raw...)
	corrupt[len(corrupt)-1] ^= 0xff
	rc := decryptSeipdV2ForTransactionTest(t, corrupt, key)

	out, readErr := io.ReadAll(rc)
	if readErr == nil {
		t.Fatal("reading a stream with a corrupt final tag succeeded")
	}
	if len(out) != 0 {
		t.Fatalf("published %d bytes of unauthenticated plaintext", len(out))
	}
	if closeErr := rc.Close(); closeErr != readErr {
		t.Fatalf("Read error %v, Close error %v", readErr, closeErr)
	}
	if _, retryErr := rc.Read(make([]byte, 16)); retryErr != readErr {
		t.Fatalf("retry error %v, want %v", retryErr, readErr)
	}
	if closeErr := rc.Close(); closeErr != readErr {
		t.Fatalf("second Close error %v, want %v", closeErr, readErr)
	}
}

func TestSeipdV2TransactionTruncatedAndClose(t *testing.T) {
	const chunkSize = 256
	plaintext := bytes.Repeat([]byte("truncated chunk "), 64)
	raw, key := serializeSeipdV2ForTransactionTest(t, plaintext, chunkSize)

	for _, cut := range []int{1, AEADModeOCB.TagLength(), AEADModeOCB.TagLength() + 7} {
		if cut >= len(raw) {
			continue
		}
		rc := decryptSeipdV2ForTransactionTest(t, raw[:len(raw)-cut], key)
		out, readErr := io.ReadAll(rc)
		if readErr == nil {
			t.Fatalf("cut=%d: reading a truncated stream succeeded", cut)
		}
		if len(out) != 0 {
			t.Fatalf("cut=%d: published %d bytes of unauthenticated plaintext", cut, len(out))
		}
		if closeErr := rc.Close(); closeErr != readErr {
			t.Fatalf("cut=%d: Read error %v, Close error %v", cut, readErr, closeErr)
		}
	}

	// Closing without reading must authenticate the complete stream.
	rc := decryptSeipdV2ForTransactionTest(t, raw, key)
	if err := rc.Close(); err != nil {
		t.Fatalf("Close on a valid unread stream failed: %v", err)
	}

	corrupt := append([]byte(nil), raw...)
	corrupt[len(corrupt)-1] ^= 0xff
	rc = decryptSeipdV2ForTransactionTest(t, corrupt, key)
	if err := rc.Close(); err == nil {
		t.Fatal("Close on a corrupt unread stream succeeded")
	}
}

func TestSeipdV2TransactionLegalChunkBoundaries(t *testing.T) {
	const chunkSize = 256
	lengths := []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 2 * chunkSize, 2*chunkSize + 1}
	for _, length := range lengths {
		plaintext := bytes.Repeat([]byte("x"), length)
		raw, key := serializeSeipdV2ForTransactionTest(t, plaintext, chunkSize)
		rc := decryptSeipdV2ForTransactionTest(t, raw, key)
		out, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("length=%d: read failed: %v", length, err)
		}
		if !bytes.Equal(out, plaintext) {
			t.Fatalf("length=%d: got %d bytes, want %d", length, len(out), len(plaintext))
		}
		if err := rc.Close(); err != nil {
			t.Fatalf("length=%d: Close failed: %v", length, err)
		}
	}
}
