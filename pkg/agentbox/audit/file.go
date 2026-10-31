package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// FileOptions configure a FileSink.
type FileOptions struct {
	// Sync makes every Write fsync before returning.
	Sync bool
}

// FileSink appends events to a JSON Lines file, one event per line, each
// written with a single write call. It never rewrites what is there.
type FileSink struct {
	mu   sync.Mutex
	f    *os.File
	sync bool
}

// OpenFile opens (creating, mode 0600) the record file at path for
// appending. If the file ends in a partial line (a crash mid-write), a
// newline is appended so the fragment stays a line of its own, which
// readers report, instead of corrupting the next event.
func OpenFile(path string, opts FileOptions) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	fi, err := f.Stat()
	if err == nil && fi.Size() > 0 {
		last := make([]byte, 1)
		if _, err = f.ReadAt(last, fi.Size()-1); err == nil && last[0] != '\n' {
			_, err = f.Write([]byte{'\n'})
		}
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: %s: %w", path, err)
	}
	return &FileSink{f: f, sync: opts.Sync}, nil
}

func (s *FileSink) Write(e Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	b = append(b, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(b); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	if s.sync {
		if err := s.f.Sync(); err != nil {
			return fmt.Errorf("audit: %w", err)
		}
	}
	return nil
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// LastSequence is the highest source_sequence sourceID has in the file at
// path: 0 if the file is missing or holds none. Lines that are not valid
// events are skipped.
func LastSequence(path, sourceID string) (uint64, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("audit: %w", err)
	}
	defer f.Close()
	var last uint64
	d := NewDecoder(f, 0)
	for {
		e, err := d.Next()
		var le *LineError
		switch {
		case errors.Is(err, io.EOF):
			return last, nil
		case errors.As(err, &le):
			continue
		case err != nil:
			return 0, err
		}
		if e.SourceID == sourceID && e.SourceSequence > last {
			last = e.SourceSequence
		}
	}
}

// LineError is a complete line that is not a valid event. The decoder has
// moved past it; the reader records it and goes on.
type LineError struct {
	Offset int64 // where the line starts
	Err    error
}

func (e *LineError) Error() string { return fmt.Sprintf("audit: line at byte %d: %v", e.Offset, e.Err) }
func (e *LineError) Unwrap() error { return e.Err }

// Decoder reads events from a JSONL record, for ingesters that tail it.
type Decoder struct {
	r       io.Reader
	buf     []byte // read but not yet returned; may end in a partial line
	off     int64  // file offset of buf[0]
	line    []byte // the line Next last returned, newline excluded
	readErr error
}

// NewDecoder reads r, which is positioned at byte offset of the file (a
// checkpoint from Offset, or 0).
func NewDecoder(r io.Reader, offset int64) *Decoder {
	return &Decoder{r: r, off: offset}
}

// Offset is just past the last complete line returned, the checkpoint to
// resume from. A trailing partial line is not counted.
func (d *Decoder) Offset() int64 { return d.off }

// Line is the exact bytes of the line Next last returned (an event or a
// *LineError), without its newline: what an ingester hashes and keeps as
// evidence. It is overwritten by the next call.
func (d *Decoder) Line() []byte { return d.line }

// Next returns the next event. A complete line that is not a valid event
// gives a *LineError. At the end of the input, including when only a
// partial line is left, it returns io.EOF; calling Next again after the
// file has grown picks up from there.
func (d *Decoder) Next() (Event, error) {
	for {
		if i := bytes.IndexByte(d.buf, '\n'); i >= 0 {
			line, start := d.buf[:i], d.off
			d.line = append(d.line[:0], line...)
			d.buf = d.buf[i+1:]
			d.off += int64(i + 1)
			e, err := parseLine(line)
			if err != nil {
				return Event{}, &LineError{Offset: start, Err: err}
			}
			return e, nil
		}
		if err := d.fill(); err != nil {
			return Event{}, err
		}
	}
}

// fill reads more input onto buf; io.EOF when there is none now.
func (d *Decoder) fill() error {
	var chunk [32 << 10]byte
	n, err := d.r.Read(chunk[:])
	d.buf = append(d.buf, chunk[:n]...)
	if n > 0 || err == nil {
		return nil
	}
	return err
}

func parseLine(line []byte) (Event, error) {
	if len(line) > MaxEventBytes {
		return Event{}, fmt.Errorf("line is %d bytes, over %d", len(line), MaxEventBytes)
	}
	var e Event
	dec := json.NewDecoder(bytes.NewReader(line))
	if err := dec.Decode(&e); err != nil {
		return Event{}, err
	}
	if dec.More() {
		return Event{}, errors.New("more than one value on the line")
	}
	return e, e.Validate()
}
