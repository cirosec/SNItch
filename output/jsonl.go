// Package output provides the JSONL (newline-delimited JSON) sink for scan
// reports. Records are written as one JSON object per line, which keeps the
// format stream-friendly and easy to consume with jq or line-oriented tools.
package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/cirosec/snitch/report"
)

// JSONLWriter serializes report records to a writer as JSONL. A nil
// *JSONLWriter is a valid no-op, so callers never need guards.
type JSONLWriter struct {
	mu      sync.Mutex
	writer  *bufio.Writer
	encoder *json.Encoder
	closer  io.Closer
	path    string
}

// NewFile creates a JSONLWriter that writes to the file at path.
func NewFile(path string) (*JSONLWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create jsonl output file: %w", err)
	}
	return newWriter(f, f, path), nil
}

// NewStdout creates a JSONLWriter on w, tagged as the stdout sink. It is used
// when human output has been diverted to stderr but JSONL must keep flowing to
// the real stdout. The underlying writer is not closed on Close.
func NewStdout(w io.Writer) *JSONLWriter {
	return newWriter(w, nil, "-")
}

// NewWriter creates a JSONLWriter on an arbitrary io.Writer. Primarily used
// by tests. The underlying writer is not closed.
func NewWriter(w io.Writer) *JSONLWriter {
	return newWriter(w, nil, "")
}

func newWriter(w io.Writer, closer io.Closer, path string) *JSONLWriter {
	buf := bufio.NewWriter(w)
	return &JSONLWriter{writer: buf, encoder: json.NewEncoder(buf), closer: closer, path: path}
}

// Path returns the output destination for display purposes. "-" means stdout.
func (j *JSONLWriter) Path() string {
	if j == nil {
		return ""
	}
	return j.path
}

// Write serializes one record. It is safe for concurrent use.
func (j *JSONLWriter) Write(record interface{}) error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	// json.Encoder.Encode appends a newline, producing one object per line.
	if err := j.encoder.Encode(record); err != nil {
		return err
	}
	// Flush per record so consumers reading a pipe receive complete lines
	// immediately rather than only when the buffer fills or the file closes.
	return j.writer.Flush()
}

// WriteConfig, WriteCertificate, WriteHost, WriteIP and WriteSummary are
// small typed conveniences over Write.
func (j *JSONLWriter) WriteConfig(c report.Config) error           { return j.Write(c) }
func (j *JSONLWriter) WriteCertificate(c report.Certificate) error { return j.Write(c) }
func (j *JSONLWriter) WriteHost(h report.Host) error               { return j.Write(h) }
func (j *JSONLWriter) WriteIP(i report.IP) error                   { return j.Write(i) }
func (j *JSONLWriter) WriteSummary(s report.Summary) error         { return j.Write(s) }

// Close flushes buffered output and closes an owned file handle, if any.
func (j *JSONLWriter) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.writer.Flush(); err != nil {
		return err
	}
	if j.closer != nil {
		return j.closer.Close()
	}
	return nil
}
