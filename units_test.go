package mailparse

import (
	"strings"
	"testing"
)

func collect() (*[]Warning, func(Warning)) {
	var ws []Warning
	return &ws, func(w Warning) { ws = append(ws, w) }
}

func TestReadHeaderKeepsRawAndFolding(t *testing.T) {
	st := &state{opt: Options{}.withDefaults()}
	_, warn := collect()
	h, body := st.readHeader([]byte("Subject: one\r\n two\r\nX-A: =?UTF-8?B?44GC?=\r\n\r\nbody"), "", warn)
	if len(h) != 2 || h[0].Raw != " one\n two" || h[0].Value != "one two" || h[1].Value != "あ" {
		t.Fatalf("header = %+v", h)
	}
	if string(body) != "body" {
		t.Fatalf("body = %q", body)
	}
}

func TestReadHeaderLeadingContinuationAndLFOnly(t *testing.T) {
	st := &state{opt: Options{}.withDefaults()}
	ws, warn := collect()
	h, body := st.readHeader([]byte(" stray\nFrom: a@example.net\n\nb"), "1", warn)
	if len(h) != 1 || string(body) != "b" || len(*ws) != 1 || (*ws)[0].Code != WarnMalformedHeaderLine || (*ws)[0].Part != "1" {
		t.Fatalf("h=%+v body=%q warnings=%+v", h, body, *ws)
	}
}

func TestRaw8BitHeaderIsGuessed(t *testing.T) {
	st := &state{opt: Options{}.withDefaults()}
	ws, warn := collect()
	sjis := []byte("Subject: \x83e\x83X\x83g\r\n\r\n") // "テスト" in Shift_JIS
	h, _ := st.readHeader(sjis, "", warn)
	if h[0].Value != "テスト" || len(*ws) != 1 || (*ws)[0].Code != WarnRaw8BitHeader {
		t.Fatalf("value %q warnings %+v", h[0].Value, *ws)
	}
}

func TestUndecodableWordIsKept(t *testing.T) {
	ws, warn := collect()
	out := decodeWords("=?x-unknown-cs?B?AAAA?=", "Subject", "", warn)
	if out != "=?x-unknown-cs?B?AAAA?=" || len(*ws) != 1 || (*ws)[0].Code != WarnUndecodableWord {
		t.Fatalf("out %q warnings %+v", out, *ws)
	}
	if strings.Contains((*ws)[0].Detail, "AAAA") {
		t.Fatal("a warning must not quote message text")
	}
}

func TestLenientAddresses(t *testing.T) {
	ws, warn := collect()
	al := parseAddressList(Field{Name: "To", Raw: ` "Doe, J" <j@example.org>, broken <<a@example.net, /O=EXCHANGE/OU=FIRST/CN=RECIPIENTS/CN=USER`}, "", warn)
	if al.Parsed || len(*ws) != 1 || (*ws)[0].Code != WarnInvalidAddress {
		t.Fatalf("parsed=%v warnings=%+v", al.Parsed, *ws)
	}
	var got []string
	for _, mb := range al.Mailboxes {
		got = append(got, mb.Name+"|"+mb.Address)
	}
	want := "Doe, J|j@example.org;broken|a@example.net;/O=EXCHANGE/OU=FIRST/CN=RECIPIENTS/CN=USER|"
	if strings.Join(got, ";") != want {
		t.Fatalf("mailboxes = %q\nwant       %q", strings.Join(got, ";"), want)
	}
}

func TestGroupAndEmptyAddresses(t *testing.T) {
	_, warn := collect()
	if al := parseAddressList(Field{Name: "To", Raw: " "}, "", warn); !al.Parsed || len(al.Mailboxes) != 0 {
		t.Errorf("empty = %+v", al)
	}
	al := parseAddressList(Field{Name: "To", Raw: " undisclosed-recipients:;"}, "", warn)
	groupOK := len(al.Mailboxes) == 0 || (len(al.Mailboxes) == 1 && al.Mailboxes[0].Address == "")
	if !groupOK {
		t.Errorf("group = %+v", al)
	}
}

func TestBase64Tolerance(t *testing.T) {
	for in, want := range map[string]string{
		"QUJD":      "ABC",
		"QUJD\r\n":  "ABC",
		"QUI=":      "AB",
		"QUI":       "AB", // missing padding
		"QUJD=junk": "ABC",
	} {
		ws, warn := collect()
		got := string(decodeBase64([]byte(in), "", warn))
		if got != want {
			t.Errorf("decodeBase64(%q) = %q, want %q (warnings %+v)", in, got, want, *ws)
		}
	}
}

func TestQuotedPrintable(t *testing.T) {
	ws, warn := collect()
	got := string(decodeQP([]byte("caf=C3=A9 =\r\nsoft   \r\nbad=ZZ end\r\n"), "", warn))
	if got != "café soft\r\nbad=ZZ end\r\n" {
		t.Fatalf("got %q", got)
	}
	if len(*ws) != 1 || (*ws)[0].Code != WarnInvalidQP {
		t.Fatalf("warnings %+v", *ws)
	}
}

func TestUnknownTransferEncoding(t *testing.T) {
	ws, warn := collect()
	if got := string(decodeTransfer("x-uuencode", []byte("raw"), "", warn)); got != "raw" || len(*ws) != 1 || (*ws)[0].Code != WarnUnknownEncoding {
		t.Fatalf("got %q warnings %+v", got, *ws)
	}
}

func TestCharsetPaths(t *testing.T) {
	cases := []struct {
		name, mt, declared string
		data               []byte
		content, cs, src   string
		warn               string
	}{
		{"ascii default", "text/plain", "", []byte("hello"), "hello", "us-ascii", "default", ""},
		{"declared sjis", "text/plain", "Shift_JIS", []byte("\x83e\x83X\x83g"), "テスト", "shift_jis", "mime", ""},
		{"alias cp932", "text/plain", "cp932", []byte("\x83e\x83X\x83g"), "テスト", "shift_jis", "mime", ""},
		{"undeclared utf8", "text/plain", "", []byte("テスト"), "テスト", "utf-8", "guessed", WarnCharsetGuessed},
		{"undeclared sjis", "text/plain", "", []byte("\x83e\x83X\x83g"), "テスト", "shift_jis", "guessed", WarnCharsetGuessed},
		{"wrong declared", "text/plain", "us-ascii", []byte("テスト"), "テスト", "utf-8", "guessed", WarnCharsetMismatch},
		{"unknown declared", "text/plain", "x-made-up", []byte("abc\xff"), "", "", "guessed", WarnUnknownCharset},
		{"meta http-equiv", "text/html", "", []byte(`<meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS"><p>` + "\x83e\x83X\x83g"), "テスト", "shift_jis", "meta", ""},
	}
	for _, c := range cases {
		ws, warn := collect()
		r := toUTF8(c.mt, c.declared, c.data, "", warn)
		if c.content != "" && !strings.Contains(r.content, c.content) {
			t.Errorf("%s: content %q", c.name, r.content)
		}
		if c.cs != "" && (r.charset != c.cs || r.source != c.src) {
			t.Errorf("%s: charset %s/%s, want %s/%s", c.name, r.charset, r.source, c.cs, c.src)
		}
		if c.warn != "" {
			found := false
			for _, w := range *ws {
				if w.Code == c.warn {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: want warning %s, got %+v", c.name, c.warn, *ws)
			}
		}
	}
}

func TestSplitMultipartBoundaries(t *testing.T) {
	parts, closed := splitMultipart([]byte("preamble\r\n--b  \r\nA\r\n--b\r\nB\r\n--b--\r\nepilogue"), "b")
	if !closed || len(parts) != 2 || string(parts[0]) != "A" || string(parts[1]) != "B" {
		t.Fatalf("parts %q closed %v", parts, closed)
	}
	// A line that only starts with the delimiter is content, not a delimiter.
	parts, _ = splitMultipart([]byte("--b\r\n--bX not a delimiter\r\n--b--\r\n"), "b")
	if len(parts) != 1 || string(parts[0]) != "--bX not a delimiter" {
		t.Fatalf("parts %q", parts)
	}
	if parts, closed := splitMultipart([]byte("no delimiters here"), "b"); len(parts) != 0 || closed {
		t.Fatalf("parts %q", parts)
	}
}

func TestMissingBoundaryAndBadContentType(t *testing.T) {
	m, _ := ParseBytes([]byte(hdr+"Content-Type: multipart/mixed\r\n\r\nx\r\n"), Options{})
	if !hasWarning(m, WarnMissingBoundary) {
		t.Errorf("warnings %+v", m.Warnings)
	}
	m, _ = ParseBytes([]byte(hdr+"Content-Type: multipart/mixed; boundary=\"q\"\r\n\r\nno delimiter\r\n"), Options{})
	if !hasWarning(m, WarnNoParts) {
		t.Errorf("warnings %+v", m.Warnings)
	}
	m, _ = ParseBytes([]byte(hdr+"Content-Type: ;;;\r\n\r\nx\r\n"), Options{})
	if !hasWarning(m, WarnInvalidContentType) || len(m.Attachments) != 1 {
		t.Errorf("warnings %+v attachments %d", m.Warnings, len(m.Attachments))
	}
}

func TestInvalidDateKeepsRaw(t *testing.T) {
	m, _ := ParseBytes([]byte("From: a@example.net\r\nMessage-ID: <x@example.net>\r\nDate: yesterday-ish\r\n\r\nx"), Options{})
	if !m.Date.IsZero() || m.DateRaw != "yesterday-ish" || !hasWarning(m, WarnInvalidDate) {
		t.Errorf("date %v raw %q", m.Date, m.DateRaw)
	}
}

func TestInlineTextWithFilenameIsAnAttachment(t *testing.T) {
	m, _ := ParseBytes([]byte(hdr+"Content-Type: multipart/mixed; boundary=\"q\"\r\n\r\n--q\r\nContent-Type: text/plain\r\nContent-Disposition: inline; filename=\"note.txt\"\r\n\r\nx\r\n--q\r\nContent-Type: text/calendar\r\n\r\nBEGIN:VCALENDAR\r\n--q--\r\n"), Options{})
	if len(m.Bodies) != 0 || len(m.Attachments) != 2 || !m.Attachments[0].Inline || m.Attachments[0].Filename != "note.txt" {
		t.Errorf("bodies %+v attachments %+v", m.Bodies, m.Attachments)
	}
}

func TestSafeToken(t *testing.T) {
	if got := safeToken("ab\u202ecd<script>"); got != "ab?cd?script?" {
		t.Errorf("safeToken = %q", got)
	}
	if got := safeToken(strings.Repeat("a", 60)); len([]rune(got)) != 41 {
		t.Errorf("not capped: %q", got)
	}
}

func TestUndeclaredISO2022JP(t *testing.T) {
	jis := "\x1b$B$3$s$K$A$O\x1b(B" // こんにちは in ISO-2022-JP: every byte is 7-bit
	var ws []Warning
	r := toUTF8("text/plain", "", []byte(jis), "1", func(w Warning) { ws = append(ws, w) })
	if r.content != "こんにちは" || r.charset != "iso-2022-jp" || r.source != "guessed" || len(ws) != 1 || ws[0].Code != WarnCharsetGuessed {
		t.Fatalf("got %+v, warnings %v", r, ws)
	}
	if r := toUTF8("text/plain", "", []byte("plain ascii"), "1", func(Warning) { t.Fatal("warned on ascii") }); r.charset != "us-ascii" {
		t.Fatalf("ascii: %+v", r)
	}
}
