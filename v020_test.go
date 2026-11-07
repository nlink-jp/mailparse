package mailparse

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/text/encoding/japanese"
)

func utf16Bytes(s string, bigEndian bool) []byte {
	var out []byte
	for _, c := range utf16.Encode([]rune(s)) {
		if bigEndian {
			out = append(out, byte(c>>8), byte(c))
		} else {
			out = append(out, byte(c), byte(c>>8))
		}
	}
	return out
}

// Issue #1: a byte order mark decides the charset.
func TestBOM(t *testing.T) {
	cases := []struct {
		name    string
		html    []byte
		charset string
	}{
		{"utf-16le", append([]byte{0xFF, 0xFE}, utf16Bytes("Hello <b>World</b>", false)...), "utf-16le"},
		{"utf-16be", append([]byte{0xFE, 0xFF}, utf16Bytes("Hello <b>World</b>", true)...), "utf-16be"},
		{"utf-8", append([]byte{0xEF, 0xBB, 0xBF}, "Hello <b>World</b>"...), "utf-8"},
		{"utf-16le with trailing NULs", append(append([]byte{0xFF, 0xFE}, utf16Bytes("Hello <b>World</b>", false)...), 0, 0), "utf-16le"},
	}
	for _, c := range cases {
		m, _ := ParseBytes(buildMSG([]mapi{{pidSubject, "s"}, {pidHTML, c.html}}), Options{})
		b := m.Bodies[0]
		if b.Content != "Hello <b>World</b>" || b.Charset != c.charset || b.CharsetSource != "bom" || len(m.Warnings) != 1 {
			t.Errorf("%s: %+v %v", c.name, b, m.Warnings)
		}
	}
	// A declaration that disagrees with the mark is warned about; the mark wins.
	eml := "From: a@example.com\r\nMessage-ID: <b@example.com>\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\n\xEF\xBB\xBFcaf\xC3\xA9"
	m, _ := ParseBytes([]byte(eml), Options{})
	if m.Bodies[0].Content != "caf\u00e9" || codes(m.Warnings)[WarnCharsetMismatch] != 1 {
		t.Fatalf("%+v %v", m.Bodies, m.Warnings)
	}
}

// Issue #4: the recipient table is read when headers are present.
func TestMSGRecipientsWithHeaders(t *testing.T) {
	hdr := "From: alice@example.com\r\nTo: taro@corp.example\r\nSubject: s\r\nMessage-ID: <h@example.com>\r\n"
	b := buildMSG([]mapi{{pidTransportHeaders, hdr}, {pidSubject, "s"}},
		recip(0, mapi{pidRecipientType, uint32(1)}, mapi{pidSMTPAddress, "taro@corp.example"}),
		recip(1, mapi{pidRecipientType, uint32(3)}, mapi{pidDisplayName, "Boss"}, mapi{pidSMTPAddress, "boss@corp.example"}),
		recip(2, mapi{pidRecipientType, uint32(1)}, mapi{pidSMTPAddress, "hidden@evil.example"}))
	m, err := ParseBytes(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.To) != 1 || m.To[0].Mailboxes[0].Address != "taro@corp.example" {
		t.Fatalf("To must stay the headers': %+v", m.To)
	}
	if len(m.Bcc) != 1 || m.Bcc[0].Mailboxes[0].Address != "boss@corp.example" {
		t.Fatalf("Bcc %+v", m.Bcc)
	}
	got := codes(m.Warnings)
	if got[WarnBccFromMAPI] != 1 || got[WarnHeaderMismatch] != 1 {
		t.Fatalf("%v", m.Warnings)
	}
	// Agreeing table, no Bcc: nothing to report.
	m, _ = ParseBytes(buildMSG([]mapi{{pidTransportHeaders, hdr}, {pidSubject, "s"}},
		recip(0, mapi{pidRecipientType, uint32(1)}, mapi{pidSMTPAddress, "TARO@corp.example"})), Options{})
	if len(m.Warnings) != 0 {
		t.Fatalf("%v", m.Warnings)
	}
}

// Issues #2 and #3: In-Reply-To / References, and display lists.
func TestMSGThreadingAndDisplayLists(t *testing.T) {
	b := buildMSG([]mapi{{pidSubject, "Re: s"}, {pidInReplyToID, "<parent@example.com>"},
		{pidInternetReferences, "<root@example.com> <parent@example.com>"},
		{pidDisplayTo, "Alice; Bob"}, {pidDisplayCc, "Carol"}})
	m, _ := ParseBytes(b, Options{})
	if m.InReplyTo != "<parent@example.com>" || m.References != "<root@example.com> <parent@example.com>" {
		t.Fatalf("%q %q", m.InReplyTo, m.References)
	}
	if len(m.To) != 1 || len(m.To[0].Mailboxes) != 2 || m.To[0].Mailboxes[1].Name != "Bob" || m.To[0].Parsed || len(m.Cc) != 1 {
		t.Fatalf("%+v %+v", m.To, m.Cc)
	}
	if codes(m.Warnings)[WarnRecipientType] != 1 {
		t.Fatalf("%v", m.Warnings)
	}
	eml := "From: a@example.com\r\nMessage-ID: <c@example.com>\r\nIn-Reply-To: <p@example.com>\r\nReferences: <r@example.com>\r\n\t<p@example.com>\r\n\r\nx"
	m, _ = ParseBytes([]byte(eml), Options{})
	if m.InReplyTo != "<p@example.com>" || m.References != "<r@example.com> <p@example.com>" {
		t.Fatalf("eml: %q %q", m.InReplyTo, m.References)
	}
}

// Issue #10: Mailbox.String keeps a spoofed name a name.
func TestMailboxString(t *testing.T) {
	cases := []struct {
		mb   Mailbox
		want string
	}{
		{Mailbox{"Bank <security@bank.example>", "attacker@evil.example"}, `"Bank <security@bank.example>" <attacker@evil.example>`},
		{Mailbox{"Taro Yamada", "taro@corp.example"}, `Taro Yamada <taro@corp.example>`},
		{Mailbox{"山田 太郎", "taro@corp.example"}, `山田 太郎 <taro@corp.example>`},
		{Mailbox{`say "hi" \o/`, "a@example.com"}, `"say \"hi\" \\o/" <a@example.com>`},
		{Mailbox{"line\r\nbreak", "a@example.com"}, `line  break <a@example.com>`}, // control characters become spaces
		{Mailbox{"tab\t<x@y>", "a@example.com"}, `"tab <x@y>" <a@example.com>`},
		{Mailbox{"", "a@example.com"}, `a@example.com`},
		{Mailbox{"broken <<x", ""}, `"broken <<x"`},
		{Mailbox{"", ""}, ``},
	}
	for _, c := range cases {
		if got := c.mb.String(); got != c.want {
			t.Errorf("%+v: got %s, want %s", c.mb, got, c.want)
		}
	}
	// Round trip: what String writes parses back to the same mailbox.
	spoof := Mailbox{"Bank <security@bank.example>", "attacker@evil.example"}
	al := parseAddressList(Field{Name: "From", Raw: spoof.String()}, "", func(Warning) {})
	if len(al.Mailboxes) != 1 || al.Mailboxes[0] != spoof {
		t.Fatalf("round trip: %+v", al)
	}
}

// Issue #9: text/* attachments carry their charset and convert like bodies.
func TestAttachmentText(t *testing.T) {
	cal, _ := japanese.ISO2022JP.NewEncoder().String("BEGIN:VCALENDAR\r\nSUMMARY:会議\r\nURL:https://evil.example/join\r\nEND:VCALENDAR\r\n")
	eml := "From: a@example.com\r\nMessage-ID: <c@example.com>\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n" +
		"--b\r\nContent-Type: text/calendar; charset=ISO-2022-JP; method=REQUEST\r\n\r\n" + cal + "\r\n--b--\r\n"
	m, _ := ParseBytes([]byte(eml), Options{})
	a := m.Attachments[0]
	if a.Charset != "ISO-2022-JP" {
		t.Fatalf("charset %q", a.Charset)
	}
	tx := a.Text()
	if !strings.Contains(tx.Content, "SUMMARY:会議") || tx.Charset != "iso-2022-jp" || tx.CharsetSource != "mime" || len(tx.Warnings) != 0 {
		t.Fatalf("%+v", tx)
	}
}

// Issue #7: Collapsed is Value with whitespace runs made one space.
func TestFieldCollapsed(t *testing.T) {
	m, _ := ParseBytes([]byte("Received: from a\r\n\tby b;\r\n  Fri, 6 Nov 2026 10:00:00 +0900\r\nFrom: x@example.com\r\nMessage-ID: <r@example.com>\r\n\r\nx"), Options{})
	f := m.Header[0]
	if !strings.Contains(f.Value, "\t") || f.Collapsed() != "from a by b; Fri, 6 Nov 2026 10:00:00 +0900" {
		t.Fatalf("%q / %q", f.Value, f.Collapsed())
	}
}

// Issue #6: AssumeEML reads minimal mail Detect refuses.
func TestAssumeEML(t *testing.T) {
	cron := []byte("From: root\r\nSubject: cron\r\n\r\nbackup done\r\n")
	if _, err := ParseBytes(cron, Options{}); !errors.Is(err, ErrNotMessage) {
		t.Fatalf("default: %v", err)
	}
	m, err := ParseBytes(cron, Options{AssumeEML: true})
	if err != nil || m.Subject != "cron" || m.Warnings[0].Code != WarnNotDetected {
		t.Fatalf("%v %+v", err, m)
	}
	if _, err := ParseBytes([]byte("no header at all"), Options{AssumeEML: true}); !errors.Is(err, ErrNotMessage) {
		t.Fatalf("no header: %v", err)
	}
	if DefaultMaxSize != 64<<20 || (Options{}).withDefaults().MaxSize != 64<<20 {
		t.Fatalf("default MaxSize %d", DefaultMaxSize)
	}
}

// Walk, AllWarnings and Body.Origin.
func TestWalkAndOrigin(t *testing.T) {
	inner := "From: c@example.net\r\nMessage-ID: <i@example.net>\r\nContent-Type: text/plain; charset=bogus-charset\r\n\r\nx"
	eml := "From: a@example.com\r\nMessage-ID: <o@example.com>\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nouter\r\n" +
		"--b\r\nContent-Type: message/rfc822\r\n\r\n" + inner + "\r\n--b--\r\n"
	m, _ := ParseBytes([]byte(eml), Options{})
	var paths []string
	m.Walk(func(path string, depth int, msg *Message) bool {
		paths = append(paths, path)
		return true
	})
	if strings.Join(paths, "|") != "|2" {
		t.Fatalf("paths %q", paths)
	}
	ws := m.AllWarnings()
	if len(ws) != 1 || ws[0].Part != "2" || ws[0].Code != WarnUnknownCharset {
		t.Fatalf("%+v", ws)
	}
	if m.Bodies[0].Origin != "mime" {
		t.Fatalf("origin %q", m.Bodies[0].Origin)
	}
	msg, _ := ParseBytes(sampleMSG(), Options{})
	if msg.Bodies[0].Origin != "mapi" || msg.Bodies[1].Origin != "mapi" {
		t.Fatalf("%+v", msg.Bodies)
	}
	rtf, _ := ParseBytes(buildMSG([]mapi{{pidSubject, "x"}, {pidRTFCompressed, compressLiteral([]byte(`{\rtf1 hi}`))}}), Options{})
	if rtf.Bodies[0].Origin != "rtf" {
		t.Fatalf("%+v", rtf.Bodies)
	}
	tn, _ := ParseBytes(tnefStream(tnefAttr(tnefLevelMessage, attBody, []byte("legacy"))), Options{})
	if tn.Bodies[0].Origin != "tnef" {
		t.Fatalf("%+v", tn.Bodies)
	}
}
