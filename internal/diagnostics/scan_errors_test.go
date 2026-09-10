package diagnostics

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestOversizedLogLineIsNotCompleteEvidence(t *testing.T) {
	archive := buildArchive(t, map[string]string{
		"Analyze (go).txt": strings.Repeat("x", 128*1024) + "\n##[warning]Low Go analysis quality\n",
	})
	if _, err := Scan(archive, "", 300); err == nil || !strings.Contains(err.Error(), "token too long") {
		t.Fatalf("oversized line silently truncated the inspection: %v", err)
	}
}

func storedLogArchive(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	file, err := writer.CreateHeader(&zip.FileHeader{Name: "Analyze (go).txt", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("analysis finished\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestCorruptLogReadErrorIsPropagated(t *testing.T) {
	archive := storedLogArchive(t)
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	offset, err := reader.File[0].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	archive[offset] = 'x'
	if _, err := Scan(archive, "", 300); !errors.Is(err, zip.ErrChecksum) {
		t.Fatalf("corrupt entry was accepted as complete: %v", err)
	}
}

func TestUnsupportedLogEntryIsNotSilentlySkipped(t *testing.T) {
	archive := storedLogArchive(t)
	header := bytes.Index(archive, []byte{'P', 'K', 1, 2})
	if header < 0 {
		t.Fatal("central directory was not found")
	}
	binary.LittleEndian.PutUint16(archive[header+10:], 99)
	if _, err := Scan(archive, "", 300); !errors.Is(err, zip.ErrAlgorithm) {
		t.Fatalf("unreadable entry was skipped without an error: %v", err)
	}
}
