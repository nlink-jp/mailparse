package mailparse

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestRealMessages parses a directory of real messages kept outside the
// repository (MAILPARSE_REAL_DIR, searched recursively for .eml and .msg). It
// skips when the variable is unset. It prints only counts and warning codes —
// never content, addresses or subjects — so its log can be shared.
func TestRealMessages(t *testing.T) {
	dir := os.Getenv("MAILPARSE_REAL_DIR")
	if dir == "" {
		t.Skip("MAILPARSE_REAL_DIR not set")
	}
	var files []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			switch strings.ToLower(filepath.Ext(p)) {
			case ".eml", ".msg":
				files = append(files, p)
			}
		}
		return nil
	})
	if len(files) == 0 {
		t.Fatalf("no .eml or .msg under %s", dir)
	}
	sort.Strings(files)
	for i, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		m, err := ParseBytes(b, Options{})
		if err != nil {
			t.Logf("#%02d %s: %v", i+1, filepath.Ext(p), err)
			continue
		}
		codes := map[string]int{}
		for _, w := range m.Warnings {
			codes[w.Code]++
		}
		nested := 0
		for _, a := range m.Attachments {
			if a.Message != nil {
				nested++
			}
		}
		t.Logf("#%02d %s: header %d, from %d, received %d, auth-results %d, bodies %d, attachments %d (nested %d), date ok %v, warnings %v",
			i+1, m.Format, len(m.Header), len(m.From), len(m.Header.All("Received")), len(m.Header.All("Authentication-Results")),
			len(m.Bodies), len(m.Attachments), nested, !m.Date.IsZero(), codes)
	}
}
