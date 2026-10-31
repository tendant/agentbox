package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Sink stores events in the order it is given them.
type Sink interface {
	Write(Event) error
}

// Recorder stamps events from one source (ID, sequence, observation time)
// and hands them to a Sink. It is safe for concurrent use; sequence order is
// the order events reach the sink.
type Recorder struct {
	source string
	sink   Sink
	now    func() time.Time

	mu  sync.Mutex
	seq uint64
	ids idGen
}

// NewRecorder records as sourceID, continuing after lastSeq (0 for a new
// source; LastSequence finds it in an existing file).
func NewRecorder(sourceID string, sink Sink, lastSeq uint64) (*Recorder, error) {
	if sourceID == "" {
		return nil, errors.New("audit: no source id")
	}
	if sink == nil {
		return nil, errors.New("audit: no sink")
	}
	return &Recorder{source: sourceID, sink: sink, now: time.Now, seq: lastSeq}, nil
}

// OpenFileRecorder appends to the JSONL file at path, resuming sourceID's
// sequence from what the file already holds. Close closes the file.
func OpenFileRecorder(path, sourceID string, opts FileOptions) (*Recorder, error) {
	last, err := LastSequence(path, sourceID)
	if err != nil {
		return nil, err
	}
	f, err := OpenFile(path, opts)
	if err != nil {
		return nil, err
	}
	return NewRecorder(sourceID, f, last)
}

// Record completes e and writes it. The caller sets RunID, Type and,
// when known, OccurredAt (default: now) and PolicyID; detail, if not nil,
// becomes e.Detail. It returns the event as written.
//
// An event that fails validation is not written and uses no sequence number.
// One the sink fails to store does use one: the gap is how a reader learns
// it was lost.
func (r *Recorder) Record(e Event, detail any) (Event, error) {
	if detail != nil {
		d, err := json.Marshal(detail)
		if err != nil {
			return e, fmt.Errorf("audit: detail: %w", err)
		}
		e.Detail = d
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now().UTC().Round(0)
	e.SchemaVersion = SchemaVersion
	e.SourceID = r.source
	e.SourceSequence = r.seq + 1
	e.EventID = r.ids.next(now)
	e.ObservedAt = now
	if e.OccurredAt.IsZero() {
		e.OccurredAt = now
	} else {
		e.OccurredAt = e.OccurredAt.UTC().Round(0)
	}
	if err := e.Validate(); err != nil {
		return e, err
	}
	if b, _ := json.Marshal(e); len(b) > MaxEventBytes {
		return e, fmt.Errorf("audit: event is %d bytes, over %d", len(b), MaxEventBytes)
	}
	r.seq++
	return e, r.sink.Write(e)
}

// RecordPolicy writes run runID's policy snapshot and returns its
// digest, the PolicyID for the run's later events.
func (r *Recorder) RecordPolicy(runID string, snap PolicySnapshot) (string, error) {
	detail, err := json.Marshal(snap)
	if err != nil {
		return "", fmt.Errorf("audit: policy snapshot: %w", err)
	}
	id, err := PolicyDigest(detail)
	if err != nil {
		return "", err
	}
	_, err = r.Record(Event{RunID: runID, Type: TypePolicySnapshot, PolicyID: id, Detail: detail}, nil)
	return id, err
}

// Close closes the sink if it can be closed.
func (r *Recorder) Close() error {
	if c, ok := r.sink.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
