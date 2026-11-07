package mailparse

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hdr = "From: a@example.net\r\nDate: Fri, 6 Nov 2026 10:00:00 +0900\r\nMessage-ID: <x@example.net>\r\n"

func TestDetectRefusesWhatIsNotAMessage(t *testing.T) {
	for name, in := range map[string]string{
		"dotenv":       "API_KEY=secret\nDB_PASSWORD=hunter2\n",
		"yaml":         "subject: hello\nto: someone\nlist:\n  - a\n",
		"ini":          "[server]\nhost = example.com\n",
		"one known":    "Subject: only one\n\nbody\n",
		"no anchor":    "Subject: x\nTo: y@example.org\n\nbody\n",
		"binary":       "\x00\x01\x02\x03",
		"empty":        "",
		"plain prose":  "Dear user, From: is a word here.\n",
		"ole document": string(cfbSignature) + strings.Repeat("\x00", 600),
	} {
		if got := Detect([]byte(in)); got != FormatUnknown {
			t.Errorf("%s: Detect = %s, want unknown", name, got)
		}
		if _, err := ParseBytes([]byte(in), Options{}); !errors.Is(err, ErrNotMessage) {
			t.Errorf("%s: ParseBytes err = %v, want ErrNotMessage", name, err)
		}
	}
}

func TestDetectMSGAndTNEF(t *testing.T) {
	msg := append(append([]byte{}, cfbSignature...), append(utf16le("__substg1.0_0037001F"), utf16le("__properties_version1.0")...)...)
	if Detect(msg) != FormatMSG {
		t.Error("CFB with MSG stream names is a .msg")
	}
	// Recognized by its names but not a readable compound file: refused, not
	// read as something else.
	if _, err := ParseBytes(msg, Options{}); !errors.Is(err, ErrNotMessage) {
		t.Errorf("err = %v; a .msg whose compound file does not open is not a message", err)
	}
	if Detect([]byte{0x78, 0x9F, 0x3E, 0x22, 1, 0}) != FormatTNEF {
		t.Error("the TNEF signature is TNEF")
	}
	if Detect([]byte("From MAILER-DAEMON Fri Nov  6 10:00:00 2026\n"+hdr+"\nbody\n")) != FormatEML {
		t.Error("an mbox separator line before the header is still a message")
	}
}

func TestTooLarge(t *testing.T) {
	b := []byte(hdr + "\r\n" + strings.Repeat("x", 2000))
	if _, err := ParseBytes(b, Options{MaxSize: 1000}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("ParseBytes err = %v", err)
	}
	if _, err := Parse(bytes.NewReader(b), Options{MaxSize: 1000}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Parse err = %v", err)
	}
}

func multipartOf(n int) string {
	var b strings.Builder
	b.WriteString(hdr + "Content-Type: multipart/mixed; boundary=\"z\"\r\n\r\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "--z\r\nContent-Type: text/plain\r\n\r\npart %d\r\n", i)
	}
	b.WriteString("--z--\r\n")
	return b.String()
}

func TestPartLimit(t *testing.T) {
	m, err := ParseBytes([]byte(multipartOf(50)), Options{MaxParts: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Bodies) > 10 || !hasWarning(m, WarnPartLimit) {
		t.Errorf("bodies %d; parts beyond the limit must not be read, with a warning", len(m.Bodies))
	}
}

func TestMIMEDepthLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString(hdr)
	depth := 40
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=\"b%d\"\r\n\r\n--b%d\r\n", i, i)
	}
	b.WriteString("Content-Type: text/plain\r\n\r\ndeep\r\n")
	m, err := ParseBytes([]byte(b.String()), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(m, WarnMIMEDepthLimit) {
		t.Error("a MIME tree deeper than the limit must stop with a warning")
	}
}

// nest wraps an inner message n times as message/rfc822.
func nest(inner string, n int) string {
	s := inner
	for i := 0; i < n; i++ {
		s = hdr + "Content-Type: message/rfc822\r\n\r\n" + s
	}
	return s
}

func TestMessageDepthLimit(t *testing.T) {
	m, err := ParseBytes([]byte(nest(hdr+"Subject: innermost\r\n\r\nx\r\n", 6)), Options{MaxMessageDepth: 3})
	if err != nil {
		t.Fatal(err)
	}
	depth := 0
	cur := m
	for len(cur.Attachments) > 0 && cur.Attachments[0].Message != nil {
		cur = cur.Attachments[0].Message
		depth++
	}
	if depth != 3 || !hasWarning(cur, WarnMessageDepthLimit) {
		t.Errorf("opened %d layers; want exactly 3 and a warning at the cut", depth)
	}
}

// The decoded budget is shared across one parse, nested messages included.
func TestDecodedBudgetIsShared(t *testing.T) {
	blob := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("A"), 3000))
	part := hdr + "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n" + blob + "\r\n"
	outer := hdr + "Content-Type: multipart/mixed; boundary=\"q\"\r\n\r\n" +
		"--q\r\nContent-Type: message/rfc822\r\n\r\n" + part + "\r\n" +
		"--q\r\nContent-Type: message/rfc822\r\n\r\n" + part + "\r\n--q--\r\n"
	m, err := ParseBytes([]byte(outer), Options{MaxDecoded: 5000})
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	var walk func(*Message)
	walk = func(x *Message) {
		for _, a := range x.Attachments {
			if a.Message != nil {
				walk(a.Message)
				continue
			}
			total += len(a.Data)
		}
	}
	walk(m)
	cut := false
	var find func(*Message)
	find = func(x *Message) {
		if hasWarning(x, WarnDecodedLimit) {
			cut = true
		}
		for _, a := range x.Attachments {
			if a.Message != nil {
				find(a.Message)
			}
		}
	}
	find(m)
	if total > 5000 || !cut {
		t.Errorf("decoded attachment bytes %d (limit 5000), cut warned %v", total, cut)
	}
}

func TestHeaderLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString(hdr)
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "X-Flood-%d: v\r\n", i)
	}
	b.WriteString("Subject: after the flood\r\n\r\nbody\r\n")
	m, err := ParseBytes([]byte(b.String()), Options{MaxHeaders: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Header) > 20 || !hasWarning(m, WarnHeaderLimit) {
		t.Errorf("header fields %d; the limit must hold, with a warning", len(m.Header))
	}
	if len(m.Bodies) != 1 || !strings.Contains(m.Bodies[0].Content, "body") {
		t.Errorf("the body after a truncated header block must still be found: %+v", m.Bodies)
	}
}

// FuzzParseBytes holds the package to "never panics, limits hold". The seeds
// are the fixtures; `make fuzz` explores beyond them.
func FuzzParseBytes(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("testdata", "eml", "*.eml"))
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(multipartOf(3)))
	f.Add([]byte(nest(hdr+"\r\nx", 4)))
	f.Add(sampleMSG())
	f.Add(buildMSG([]mapi{{pidSubject, "r"}, {pidRTFCompressed, compressLiteral([]byte(specExampleRTF))}}))
	opt := Options{MaxSize: 1 << 20, MaxParts: 200, MaxDecoded: 1 << 20, MaxHeaders: 200, MaxHeaderBytes: 64 << 10}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseBytes(b, opt)
		if err != nil {
			return
		}
		var total int
		var walk func(*Message, int)
		walk = func(x *Message, d int) {
			if d > DefaultMaxMessageDepth {
				t.Fatalf("nested deeper than the limit: %d", d)
			}
			for _, a := range x.Attachments {
				total += len(a.Data)
				if a.Message != nil {
					walk(a.Message, d+1)
				}
			}
			for _, bd := range x.Bodies {
				total += bd.Size
			}
		}
		walk(m, 0)
		if int64(total) > opt.MaxDecoded*2 { // a nested message's raw bytes are its parent's attachment data
			t.Fatalf("decoded total %d exceeds the budget", total)
		}
	})
}
