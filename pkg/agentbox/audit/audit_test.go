package audit

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type memSink struct{ events []Event }

func (m *memSink) Write(e Event) error { m.events = append(m.events, e); return nil }

func readAll(t *testing.T, path string) (events []Event, bad []*LineError) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d := NewDecoder(f, 0)
	for {
		e, err := d.Next()
		var le *LineError
		switch {
		case errors.Is(err, io.EOF):
			return events, bad
		case errors.As(err, &le):
			bad = append(bad, le)
		case err != nil:
			t.Fatal(err)
		default:
			events = append(events, e)
		}
	}
}

func TestRecordStamps(t *testing.T) {
	sink := &memSink{}
	r, err := NewRecorder("host-1", sink, 0)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 10, 29, 1, 2, 3, 0, time.FixedZone("x", 3600))
	e, err := r.Record(Event{RunID: "run-1", Type: TypeNetworkBlocked, OccurredAt: when},
		NetworkDetail{Destination: "example.org", Port: 443, Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if e.SchemaVersion != SchemaVersion || e.SourceID != "host-1" || e.SourceSequence != 1 {
		t.Errorf("stamps: %+v", e)
	}
	if !validEventID(e.EventID) {
		t.Errorf("event id %q", e.EventID)
	}
	if !e.OccurredAt.Equal(when) || e.OccurredAt.Location() != time.UTC || e.ObservedAt.IsZero() {
		t.Errorf("times: occurred %v observed %v", e.OccurredAt, e.ObservedAt)
	}
	if string(e.Detail) != `{"destination":"example.org","port":443,"protocol":"tcp"}` {
		t.Errorf("detail %s", e.Detail)
	}
	e2, _ := r.Record(Event{RunID: "run-1", Type: TypeSandboxClosed}, nil)
	if e2.SourceSequence != 2 || e2.OccurredAt != e2.ObservedAt || e2.EventID <= e.EventID {
		t.Errorf("second event: %+v", e2)
	}
}

func TestRecordRejects(t *testing.T) {
	sink := &memSink{}
	r, _ := NewRecorder("host-1", sink, 0)
	for name, c := range map[string]struct {
		e      Event
		detail any
	}{
		"no run":       {Event{Type: TypeSandboxCreated}, nil},
		"no type":      {Event{RunID: "run"}, nil},
		"bad policy":   {Event{RunID: "run", Type: TypeSandboxCreated, PolicyID: "md5:x"}, nil},
		"array detail": {Event{RunID: "run", Type: TypeSandboxCreated}, []int{1}},
		"too big":      {Event{RunID: "run", Type: TypeSandboxCreated}, map[string]string{"x": strings.Repeat("a", MaxEventBytes)}},
	} {
		if _, err := r.Record(c.e, c.detail); err == nil {
			t.Errorf("%s: recorded", name)
		}
	}
	// Rejected events use no sequence number.
	e, err := r.Record(Event{RunID: "run", Type: TypeSandboxCreated}, nil)
	if err != nil || e.SourceSequence != 1 || len(sink.events) != 1 {
		t.Errorf("after rejects: %v %+v", err, e)
	}
}

type failSink struct{ fail bool }

func (f *failSink) Write(Event) error {
	if f.fail {
		return errors.New("disk full")
	}
	return nil
}

// A lost write leaves a sequence gap rather than reusing the number.
func TestLostWriteLeavesGap(t *testing.T) {
	s := &failSink{fail: true}
	r, _ := NewRecorder("h", s, 0)
	if _, err := r.Record(Event{RunID: "run", Type: TypeSandboxCreated}, nil); err == nil {
		t.Fatal("sink error swallowed")
	}
	s.fail = false
	e, err := r.Record(Event{RunID: "run", Type: TypeSandboxClosed}, nil)
	if err != nil || e.SourceSequence != 2 {
		t.Errorf("after a lost write: %v seq %d, want 2", err, e.SourceSequence)
	}
}

func TestFileRoundTripAndResume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	r, err := OpenFileRecorder(path, "host-1", FileOptions{Sync: true})
	if err != nil {
		t.Fatal(err)
	}
	var want []Event
	for _, typ := range []string{TypeSandboxCreated, TypeNetworkAllowed, TypeSandboxClosed} {
		e, err := r.Record(Event{RunID: "run-1", Type: typ}, nil)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, e)
	}
	r.Close()
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v", fi.Mode().Perm())
	}

	// A restart continues the sequence; another source in the same file
	// does not affect it.
	other, _ := OpenFileRecorder(path, "host-2", FileOptions{})
	other.Record(Event{RunID: "run-9", Type: TypeSandboxCreated}, nil)
	other.Close()
	r, err = OpenFileRecorder(path, "host-1", FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e, _ := r.Record(Event{RunID: "run-2", Type: TypeSandboxCreated}, nil)
	r.Close()
	if e.SourceSequence != 4 {
		t.Errorf("resumed at %d, want 4", e.SourceSequence)
	}

	got, bad := readAll(t, path)
	if len(bad) != 0 || len(got) != 5 {
		t.Fatalf("read %d events, %d bad", len(got), len(bad))
	}
	for i, w := range want {
		g := got[i]
		if g.EventID != w.EventID || g.SourceSequence != w.SourceSequence || g.Type != w.Type ||
			!g.OccurredAt.Equal(w.OccurredAt) || !g.ObservedAt.Equal(w.ObservedAt) {
			t.Errorf("event %d: got %+v want %+v", i, g, w)
		}
	}
}

// A crash mid-write leaves a partial line; reopening fences it off so the
// next event is intact and the fragment is reported, not merged.
func TestPartialTailIsFenced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	r, _ := OpenFileRecorder(path, "h", FileOptions{})
	r.Record(Event{RunID: "run", Type: TypeSandboxCreated}, nil)
	r.Close()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"schema_version":"1.0","event_id":"evt_`)
	f.Close()

	r, err := OpenFileRecorder(path, "h", FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e, _ := r.Record(Event{RunID: "run", Type: TypeSandboxClosed}, nil)
	r.Close()
	if e.SourceSequence != 2 {
		t.Errorf("seq %d, want 2", e.SourceSequence)
	}
	got, bad := readAll(t, path)
	if len(got) != 2 || len(bad) != 1 || got[1].Type != TypeSandboxClosed {
		t.Errorf("got %d events, %d bad", len(got), len(bad))
	}
}

// A tailing reader stops before a partial line and resumes once it is
// complete, from the same reader or from a saved offset.
func TestDecoderTail(t *testing.T) {
	sink := &memSink{}
	r, _ := NewRecorder("h", sink, 0)
	r.Record(Event{RunID: "run", Type: TypeSandboxCreated}, nil)
	r.Record(Event{RunID: "run", Type: TypeSandboxClosed}, nil)
	line := func(e Event) string { b, _ := json.Marshal(e); return string(b) + "\n" }
	first, second := line(sink.events[0]), line(sink.events[1])

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	os.WriteFile(path, []byte(first+second[:20]), 0o600)
	f, _ := os.Open(path)
	defer f.Close()
	d := NewDecoder(f, 0)
	if e, err := d.Next(); err != nil || e.Type != TypeSandboxCreated {
		t.Fatalf("first: %v %+v", err, e)
	}
	if string(d.Line())+"\n" != first {
		t.Errorf("Line() = %q, want the exact first line", d.Line())
	}
	if _, err := d.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("partial line: %v, want EOF", err)
	}
	if d.Offset() != int64(len(first)) {
		t.Errorf("offset %d, want %d", d.Offset(), len(first))
	}
	checkpoint := d.Offset()

	w, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	w.WriteString(second[20:])
	w.Close()
	if e, err := d.Next(); err != nil || e.Type != TypeSandboxClosed {
		t.Fatalf("completed line: %v %+v", err, e)
	}
	if d.Offset() != int64(len(first)+len(second)) {
		t.Errorf("offset %d", d.Offset())
	}

	g, _ := os.Open(path)
	defer g.Close()
	g.Seek(checkpoint, io.SeekStart)
	d2 := NewDecoder(g, checkpoint)
	if e, err := d2.Next(); err != nil || e.EventID != sink.events[1].EventID {
		t.Errorf("resume from checkpoint: %v %+v", err, e)
	}
}

func TestDecoderBadLines(t *testing.T) {
	good := Event{SchemaVersion: "1.3", EventID: "evt_01J00000000000000000000000", RunID: "r",
		SourceID: "h", SourceSequence: 1, Type: "something_new",
		OccurredAt: time.Unix(1, 0).UTC(), ObservedAt: time.Unix(1, 0).UTC()}
	gb, _ := json.Marshal(good)
	input := strings.Join([]string{
		"not json",
		`{"schema_version":"2.0"}`,
		`{"a":1} {"b":2}`,
		string(gb),
	}, "\n") + "\n"
	d := NewDecoder(strings.NewReader(input), 100)
	var offsets []int64
	for i := 0; i < 3; i++ {
		_, err := d.Next()
		var le *LineError
		if !errors.As(err, &le) {
			t.Fatalf("line %d: %v, want LineError", i, err)
		}
		offsets = append(offsets, le.Offset)
	}
	if offsets[0] != 100 || offsets[1] != 109 {
		t.Errorf("offsets %v", offsets)
	}
	// Unknown event types and newer 1.x versions are kept.
	if e, err := d.Next(); err != nil || e.Type != "something_new" {
		t.Errorf("good line: %v", err)
	}
}

func TestConcurrentOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	r, _ := OpenFileRecorder(path, "h", FileOptions{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if _, err := r.Record(Event{RunID: "run", Type: TypeNetworkAllowed}, nil); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	r.Close()
	got, bad := readAll(t, path)
	if len(got) != 500 || len(bad) != 0 {
		t.Fatalf("%d events, %d bad", len(got), len(bad))
	}
	seen := map[string]bool{}
	for i, e := range got {
		if e.SourceSequence != uint64(i+1) {
			t.Fatalf("line %d has sequence %d", i, e.SourceSequence)
		}
		if seen[e.EventID] {
			t.Fatalf("duplicate id %s", e.EventID)
		}
		seen[e.EventID] = true
	}
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].EventID < got[j].EventID }) {
		t.Error("event ids do not sort in sequence order")
	}
}

func TestIDsMonotonic(t *testing.T) {
	var g idGen
	t0 := time.UnixMilli(1_800_000_000_000)
	prev := g.next(t0)
	for i, at := range []time.Time{t0, t0, t0.Add(-time.Hour), t0.Add(time.Millisecond)} {
		id := g.next(at)
		if !validEventID(id) || id <= prev {
			t.Fatalf("id %d: %s after %s", i, id, prev)
		}
		prev = id
	}
	g.rand = [10]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if id := g.next(time.UnixMilli(0)); id <= prev {
		t.Errorf("wrapped id %s not after %s", id, prev)
	}
	if encode([16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) != "7ZZZZZZZZZZZZZZZZZZZZZZZZZ" {
		t.Error("encode of the maximum")
	}
}

func TestPolicySnapshot(t *testing.T) {
	spec := map[string]any{"version": 1, "network": map[string]string{"egress": "restricted"}}
	check := struct {
		Backend  string   `json:"backend"`
		Enforced []string `json:"enforced"`
	}{"gvisor", []string{"fs.deny", "network.restricted_egress"}}
	snap, err := NewPolicySnapshot("gvisor", "strict", 1, spec, check)
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSink{}
	r, _ := NewRecorder("h", sink, 0)
	id, err := r.RecordPolicy("run-1", snap)
	if err != nil {
		t.Fatal(err)
	}
	e := sink.events[0]
	if e.Type != TypePolicySnapshot || e.PolicyID != id || !strings.HasPrefix(id, "sha256:") {
		t.Fatalf("snapshot event %+v", e)
	}
	// A reader recomputes the digest from the stored detail, however it
	// was re-indented on the way.
	b, _ := json.Marshal(e)
	var back Event
	json.Unmarshal(b, &back)
	indented, _ := json.MarshalIndent(json.RawMessage(back.Detail), "", "  ")
	if again, _ := PolicyDigest(indented); again != id {
		t.Errorf("digest %s, recomputed %s", id, again)
	}
	var got PolicySnapshot
	json.Unmarshal(back.Detail, &got)
	if got.Backend != "gvisor" || got.Mode != "strict" || string(got.Check) != `{"backend":"gvisor","enforced":["fs.deny","network.restricted_egress"]}` {
		t.Errorf("snapshot %+v", got)
	}
	// Same policy, same digest; different policy, different digest.
	snap2, _ := NewPolicySnapshot("gvisor", "strict", 1, spec, check)
	id2, _ := r.RecordPolicy("run-2", snap2)
	snap3, _ := NewPolicySnapshot("gvisor", "permissive", 1, spec, check)
	id3, _ := r.RecordPolicy("run-3", snap3)
	if id2 != id || id3 == id {
		t.Errorf("digests %s %s %s", id, id2, id3)
	}
}

// TestFileCapMarksDroppedRuns: past the cap, events are refused but keep
// their sequence numbers (gaps), and each run's first loss is marked once,
// including a run that starts after the file is full.
func TestFileCapMarksDroppedRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	r, err := OpenFileRecorder(path, "host-1", FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Record(Event{RunID: "run-a", Type: TypeSandboxCreated}, nil); err != nil {
		t.Fatal(err)
	}
	r.Close()
	fi, _ := os.Stat(path)
	limit := fi.Size() + 1 // nothing more fits

	r, err = OpenFileRecorder(path, "host-1", FileOptions{MaxBytes: limit})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []Event{
		{RunID: "run-a", Type: TypeNetworkAllowed, PolicyID: "sha256:aa"}, // seq 2, marker 3
		{RunID: "run-a", Type: TypeSandboxClosed},                         // seq 4, already marked
		{RunID: "run-b", Type: TypeSandboxCreated},                        // seq 5, marker 6
	} {
		var full *FullError
		if _, err := r.Record(e, nil); !errors.As(err, &full) || full.Limit != limit {
			t.Fatalf("%s %s: %v, want a *FullError at %d", e.RunID, e.Type, err, limit)
		}
	}
	r.Close()

	events, bad := readAll(t, path)
	if len(bad) != 0 || len(events) != 3 {
		t.Fatalf("%d events, %d bad lines; want 3 and 0", len(events), len(bad))
	}
	for i, want := range []struct {
		run, typ   string
		seq, first uint64
		policy     string
	}{
		{"run-a", TypeSandboxCreated, 1, 0, ""},
		{"run-a", TypeEventsDropped, 3, 2, "sha256:aa"},
		{"run-b", TypeEventsDropped, 6, 5, ""},
	} {
		e := events[i]
		if e.RunID != want.run || e.Type != want.typ || e.SourceSequence != want.seq || e.PolicyID != want.policy {
			t.Errorf("event %d: %s %s seq %d policy %q; want %+v", i, e.RunID, e.Type, e.SourceSequence, e.PolicyID, want)
		}
		if want.typ == TypeEventsDropped {
			var d DroppedDetail
			json.Unmarshal(e.Detail, &d)
			if d.FirstSequence != want.first || d.LimitBytes != limit || d.Reason == "" {
				t.Errorf("event %d detail %+v", i, d)
			}
		}
	}
	// A restart resumes after the last number used, as for any lost write.
	if last, _ := LastSequence(path, "host-1"); last != 6 {
		t.Errorf("last sequence %d, want 6", last)
	}
}
