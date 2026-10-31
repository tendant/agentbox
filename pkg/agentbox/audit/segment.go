package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
)

// A record directory holds the record as numbered segment files
// (00000000, 00000001, ...), as Prometheus keeps its write-ahead log: events
// are appended to the newest segment, a full one is closed and the next
// number started, and the oldest are deleted to keep the newest Keep. A
// segment is never renamed or rewritten, so "segment path @ byte offset"
// names an event's line for as long as the segment exists.

// DefaultSegmentBytes is a segment's size when DirOptions leaves it unset.
const DefaultSegmentBytes = 10 << 20

// DirOptions configure a DirSink.
type DirOptions struct {
	// Sync makes every Write fsync before returning.
	Sync bool
	// SegmentBytes is when a segment is full (default DefaultSegmentBytes).
	// An event that would take a non-empty segment past it starts the next.
	SegmentBytes int64
	// Keep is how many segments are kept, the newest (0: all).
	Keep int
}

// Segment is one segment file of a record directory.
type Segment struct {
	Index int
	Path  string
}

// SegmentName is segment i's file name.
func SegmentName(i int) string { return fmt.Sprintf("%08d", i) }

// Segments lists dir's segments in order: files named by a segment number;
// anything else is ignored. A missing dir has none.
func Segments(dir string) ([]Segment, error) {
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	var out []Segment
	for _, e := range ents {
		n := e.Name()
		i, err := strconv.Atoi(n)
		if err != nil || !e.Type().IsRegular() || len(n) != 8 || i < 0 {
			continue
		}
		out = append(out, Segment{Index: i, Path: filepath.Join(dir, n)})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Index < out[b].Index })
	return out, nil
}

// DirSink appends events to a record directory's newest segment.
type DirSink struct {
	mu    sync.Mutex
	dir   string
	opts  DirOptions
	cur   *FileSink
	index int
}

// OpenDir opens (creating, mode 0700) the record directory dir, appending
// to its newest segment (fenced like OpenFile), or to a new 00000000.
func OpenDir(dir string, opts DirOptions) (*DirSink, error) {
	if opts.SegmentBytes <= 0 {
		opts.SegmentBytes = DefaultSegmentBytes
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	segs, err := Segments(dir)
	if err != nil {
		return nil, err
	}
	s := &DirSink{dir: dir, opts: opts}
	if len(segs) > 0 {
		s.index = segs[len(segs)-1].Index
	}
	if s.cur, err = OpenFile(filepath.Join(dir, SegmentName(s.index)), FileOptions{Sync: opts.Sync}); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *DirSink) Write(e Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur.size > 0 && s.cur.size+int64(len(b))+1 > s.opts.SegmentBytes {
		if err := s.cut(); err != nil {
			return err
		}
	}
	return s.cur.Write(e)
}

// cut closes the full segment, starts the next and deletes the oldest past
// Keep. Callers hold s.mu.
func (s *DirSink) cut() error {
	if err := s.cur.f.Sync(); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	if err := s.cur.Close(); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	next, err := OpenFile(filepath.Join(s.dir, SegmentName(s.index+1)), FileOptions{Sync: s.opts.Sync})
	if err != nil {
		return err
	}
	s.cur, s.index = next, s.index+1
	// Pruning is best effort: a segment left behind costs disk, not events.
	if segs, err := Segments(s.dir); err == nil && s.opts.Keep > 0 && len(segs) > s.opts.Keep {
		for _, old := range segs[:len(segs)-s.opts.Keep] {
			os.Remove(old.Path)
		}
	}
	return nil
}

func (s *DirSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur.Close()
}

// OpenDirRecorder appends to the record directory dir, resuming sourceID's
// sequence from its newest segment that holds any of the source's events.
// Close closes the segment.
func OpenDirRecorder(dir, sourceID string, opts DirOptions) (*Recorder, error) {
	segs, err := Segments(dir)
	if err != nil {
		return nil, err
	}
	var last uint64
	for i := len(segs) - 1; i >= 0 && last == 0; i-- {
		if last, err = LastSequence(segs[i].Path, sourceID); err != nil {
			return nil, err
		}
	}
	sink, err := OpenDir(dir, opts)
	if err != nil {
		return nil, err
	}
	return NewRecorder(sourceID, sink, last)
}
