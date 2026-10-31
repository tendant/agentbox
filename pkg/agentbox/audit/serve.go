package audit

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

// SegmentInfo is one segment as DirHandler lists it.
type SegmentInfo struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// DirHandler serves the record directory dir, read-only, for a reader on
// another host (agent-gate) to pull:
//
//	GET segments         {"segments": [{"name": "00000003", "size": 1234}, ...]}, in order
//	GET segments/{name}  the segment's bytes; Range requests resume from an offset
//
// Paths are relative: mount it under a prefix with http.StripPrefix. It does
// no authentication; the host serving it must (the record is not for
// everyone). A segment is never rewritten, so a byte range read once
// reads the same later, for as long as the segment is kept.
func DirHandler(dir string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /segments", func(w http.ResponseWriter, r *http.Request) {
		segs, err := Segments(dir)
		if err != nil {
			http.Error(w, "record unreadable", http.StatusInternalServerError)
			return
		}
		out := make([]SegmentInfo, 0, len(segs))
		for _, s := range segs {
			fi, err := os.Stat(s.Path)
			if err != nil {
				continue // deleted since it was listed
			}
			out = append(out, SegmentInfo{Name: SegmentName(s.Index), Size: fi.Size()})
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]any{"segments": out})
	})
	mux.HandleFunc("GET /segments/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if i, err := strconv.Atoi(name); err != nil || i < 0 || name != SegmentName(i) {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Cache-Control", "no-store")
		// The segment may grow while it is read: serve the size it had now.
		http.ServeContent(w, r, "", fi.ModTime(), io.NewSectionReader(f, 0, fi.Size()))
	})
	return mux
}
