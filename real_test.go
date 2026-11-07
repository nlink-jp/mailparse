package mailparse

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestRealMessages parses real messages kept outside the repository:
// MAILPARSE_REAL_DIR names one file, or a directory searched recursively for
// .eml, .msg and .dat (TNEF). It
// skips when the variable is unset. It prints only counts and warning codes —
// never content, addresses or subjects — so its log can be shared.
func TestRealMessages(t *testing.T) {
	dir := os.Getenv("MAILPARSE_REAL_DIR")
	if dir == "" {
		t.Skip("MAILPARSE_REAL_DIR not set")
	}
	var files []string
	if fi, err := os.Stat(dir); err == nil && !fi.IsDir() {
		files = []string{dir}
	}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && p != dir {
			switch strings.ToLower(filepath.Ext(p)) {
			case ".eml", ".msg", ".dat":
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
		var bodies []string
		for _, b := range m.Bodies {
			bodies = append(bodies, fmt.Sprintf("%s %s %s/%s %d", b.Part, b.MediaType, b.Charset, b.CharsetSource, len(b.Content)))
		}
		withData := 0
		for _, a := range m.Attachments {
			if len(a.Data) > 0 {
				withData++
			}
		}
		t.Logf("#%02d %s: header %d, from %d (addr %v), to %d, received %d, auth-results %d, subject %v, message-id %v, bodies %v, attachments %d (with bytes %d, nested %d), date ok %v, warnings %v",
			i+1, m.Format, len(m.Header), len(m.From), hasAddress(m.From), len(m.To), len(m.Header.All("Received")), len(m.Header.All("Authentication-Results")),
			m.Subject != "", m.MessageID != "", bodies, len(m.Attachments), withData, nested, !m.Date.IsZero(), codes)
	}
}

func hasAddress(ls []AddressList) bool {
	for _, l := range ls {
		for _, mb := range l.Mailboxes {
			if mb.Address != "" {
				return true
			}
		}
	}
	return false
}
