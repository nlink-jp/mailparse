package mailparse

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/encoding/japanese"

	"github.com/nlink-jp/mailparse/internal/cfbtest"
)

func enc(e encoding.Encoding, s string) s8 {
	b, err := e.NewEncoder().Bytes([]byte(s))
	if err != nil {
		panic(err)
	}
	return s8(b)
}

func codes(ws []Warning) map[string]int {
	out := map[string]int{}
	for _, w := range ws {
		out[w.Code]++
	}
	return out
}

const msgHeaders = "Received: from mx.example.net (mx.example.net [192.0.2.10])\r\n\tby mail.example.com; Fri, 6 Nov 2026 10:00:00 +0900\r\n" +
	"From: =?UTF-8?B?57WM55CG6YOo?= <alice@example.com>\r\n" +
	"To: bob@example.org\r\n" +
	"Subject: Invoice\r\n" +
	"Message-ID: <m1@example.com>\r\n" +
	"Date: Fri, 6 Nov 2026 10:00:00 +0900\r\n"

const innerEML = "From: carol@example.net\r\nTo: bob@example.org\r\nSubject: forwarded\r\nMessage-ID: <f@example.net>\r\n\r\nforwarded body\r\n"

func sampleMSG() []byte {
	return buildMSG([]mapi{
		{pidTransportHeaders, msgHeaders},
		{pidSubject, "MAPI subject (the header wins)"},
		{pidBody, "plain body"},
		{pidHTML, []byte(`<html><body><a href="http://example.com/x">x</a></body></html>`)},
		{pidInternetCodepage, uint32(65001)},
	},
		attach(0, []mapi{{pidAttachMethod, uint32(attachByValue)}, {pidAttachLongFilename, "invoice.pdf"}, {pidAttachFilename, "INVOIC~1.PDF"}, {pidAttachMIMETag, "application/pdf"}, {pidAttachData, []byte("%PDF-1.4 fake")}}),
		attach(1, []mapi{{pidAttachMethod, uint32(attachByValue)}, {pidAttachLongFilename, "logo.png"}, {pidAttachContentID, "<logo@example.com>"}, {pidAttachmentHidden, true}, {pidAttachData, []byte("\x89PNG\r\n\x1a\n")}}),
		attach(2, []mapi{{pidAttachMethod, uint32(attachEmbedded)}, {pidDisplayName, "Fwd: inner"}},
			embedded([]mapi{{pidSubject, "inner"}, {pidSentRepName, "Carol"}, {pidSentRepSMTP, "carol@example.net"}, {pidBody, "inner body"}})),
		attach(3, []mapi{{pidAttachMethod, uint32(attachByValue)}, {pidAttachLongFilename, "fwd.eml"}, {pidAttachMIMETag, "message/rfc822"}, {pidAttachData, []byte(innerEML)}}),
		attach(4, []mapi{{pidAttachMethod, uint32(attachOLE)}, {pidDisplayName, "Picture"}}),
	)
}

func TestMSGWithHeaders(t *testing.T) {
	b := sampleMSG()
	if Detect(b) != FormatMSG {
		t.Fatal("not detected as .msg")
	}
	m, err := ParseBytes(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Format != FormatMSG || m.Size != int64(len(b)) {
		t.Fatalf("format %s size %d", m.Format, m.Size)
	}
	if len(m.Header.All("Received")) != 1 || m.Subject != "Invoice" || m.MessageID != "<m1@example.com>" || m.Date.IsZero() {
		t.Fatalf("header: %d received, subject %q, id %q, date %v", len(m.Header.All("Received")), m.Subject, m.MessageID, m.Date)
	}
	if len(m.From) != 1 || m.From[0].Mailboxes[0].Address != "alice@example.com" || m.From[0].Mailboxes[0].Name != "経理部" {
		t.Fatalf("from %+v", m.From)
	}
	// The MAPI subject differs on purpose: Outlook shows it, the header says
	// otherwise, and that is reported.
	if got := codes(m.Warnings); len(got) != 2 || got[WarnAttachmentNotExtracted] != 1 || got[WarnHeaderMismatch] != 1 {
		t.Fatalf("warnings %v", m.Warnings)
	}
	if len(m.Bodies) != 2 {
		t.Fatalf("bodies %+v", m.Bodies)
	}
	if bd := m.Bodies[0]; bd.MediaType != "text/plain" || bd.Content != "plain body" || bd.Part != "msg/body" || bd.CharsetSource != "unicode" {
		t.Fatalf("text body %+v", bd)
	}
	if bd := m.Bodies[1]; bd.MediaType != "text/html" || !strings.Contains(bd.Content, "http://example.com/x") || bd.Charset != "utf-8" || bd.CharsetSource != "codepage" || bd.Part != "msg/html" {
		t.Fatalf("html body %+v", bd)
	}
	if len(m.Attachments) != 5 {
		t.Fatalf("attachments %d", len(m.Attachments))
	}
	a := m.Attachments
	if a[0].Filename != "invoice.pdf" || a[0].MediaType != "application/pdf" || string(a[0].Data) != "%PDF-1.4 fake" || a[0].Size != 13 || a[0].Inline || a[0].Part != "msg/attach/0" {
		t.Fatalf("pdf %+v", a[0])
	}
	if !a[1].Inline || a[1].Disposition != "inline" || a[1].ContentID != "logo@example.com" || a[1].MediaType != "application/octet-stream" {
		t.Fatalf("inline image %+v", a[1])
	}
	in := a[2].Message
	if in == nil || in.Format != FormatMSG || in.Subject != "inner" || in.From[0].Mailboxes[0].Address != "carol@example.net" || len(in.Bodies) != 1 {
		t.Fatalf("embedded %+v", in)
	}
	if codes(in.Warnings)[WarnNoTransportHeaders] != 1 || a[2].MediaType != "application/vnd.ms-outlook" || a[2].Data != nil {
		t.Fatalf("embedded warnings %v, type %s", in.Warnings, a[2].MediaType)
	}
	if a[3].Message == nil || a[3].Message.Format != FormatEML || a[3].Message.Subject != "forwarded" {
		t.Fatalf("attached eml %+v", a[3].Message)
	}
	if a[4].Data != nil || a[4].Filename != "Picture" {
		t.Fatalf("ole %+v", a[4])
	}

	// The reader entry points read the same thing.
	for name, parse := range map[string]func() (*Message, error){
		"Parse":    func() (*Message, error) { return Parse(bytes.NewReader(b), Options{}) },
		"ParseMSG": func() (*Message, error) { return ParseMSG(bytes.NewReader(b), Options{}) },
	} {
		if m2, err := parse(); err != nil || m2.Subject != "Invoice" || len(m2.Attachments) != 5 {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMSGFromProps(t *testing.T) {
	sj := japanese.ShiftJIS
	sent := time.Date(2026, 11, 6, 1, 2, 3, 0, time.UTC)
	b := buildMSG([]mapi{
		{pidMessageCodepage, uint32(932)},
		{pidSubject, enc(sj, "請求書のご案内")},
		{pidSentRepName, enc(sj, "経理部")},
		{pidSentRepEmail, s8("/O=EXAMPLE/OU=EXCHANGE/CN=RECIPIENTS/CN=KEIRI")},
		{pidSentRepSMTP, s8("keiri@example.com")},
		{pidSenderName, s8("Mallory")},
		{pidSenderSMTP, s8("mallory@example.net")},
		{pidInternetMessageID, s8("<x@example.com>")},
		{pidClientSubmitTime, sent},
		{pidBody, enc(sj, "本文です")},
	},
		recip(0, mapi{pidRecipientType, uint32(1)}, mapi{pidDisplayName, s8("Bob")}, mapi{pidSMTPAddress, s8("bob@example.org")}),
		recip(1, mapi{pidRecipientType, uint32(2 | 0x10000000)}, mapi{pidDisplayName, enc(sj, "鈴木")}, mapi{pidEmailAddress, s8("suzuki@example.org")}),
		recip(2, mapi{pidRecipientType, uint32(3)}, mapi{pidEmailAddress, s8("dave@example.org")}),
		recip(3, mapi{pidRecipientType, uint32(1)}, mapi{pidDisplayName, s8("Erin")}, mapi{pidEmailAddress, s8("/O=EXAMPLE/CN=ERIN")}),
	)
	m, err := ParseBytes(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Header) != 0 || codes(m.Warnings)[WarnNoTransportHeaders] != 1 {
		t.Fatalf("header %d, warnings %v", len(m.Header), m.Warnings)
	}
	if m.Subject != "請求書のご案内" || m.MessageID != "<x@example.com>" || !m.Date.Equal(sent) {
		t.Fatalf("subject %q id %q date %v", m.Subject, m.MessageID, m.Date)
	}
	f := m.From[0]
	if f.Mailboxes[0].Name != "経理部" || f.Mailboxes[0].Address != "keiri@example.com" || !strings.Contains(f.Raw, "/O=EXAMPLE/OU=EXCHANGE") {
		t.Fatalf("from %+v", f)
	}
	if len(m.Sender) != 1 || m.Sender[0].Mailboxes[0].Address != "mallory@example.net" {
		t.Fatalf("sender %+v", m.Sender)
	}
	if len(m.To) != 1 || len(m.To[0].Mailboxes) != 2 || m.To[0].Mailboxes[0].Address != "bob@example.org" || m.To[0].Parsed {
		t.Fatalf("to %+v", m.To)
	}
	if erin := m.To[0].Mailboxes[1]; erin.Name != "Erin" || erin.Address != "" || !strings.Contains(m.To[0].Raw, "/O=EXAMPLE/CN=ERIN") {
		t.Fatalf("exchange-only recipient %+v (raw %q)", erin, m.To[0].Raw)
	}
	if len(m.Cc) != 1 || m.Cc[0].Mailboxes[0].Name != "鈴木" || m.Cc[0].Mailboxes[0].Address != "suzuki@example.org" {
		t.Fatalf("cc %+v", m.Cc)
	}
	if len(m.Bcc) != 1 || m.Bcc[0].Mailboxes[0].Address != "dave@example.org" {
		t.Fatalf("bcc %+v", m.Bcc)
	}
	if len(m.Bodies) != 1 || m.Bodies[0].Content != "本文です" || m.Bodies[0].Charset != "shift_jis" || m.Bodies[0].CharsetSource != "codepage" {
		t.Fatalf("body %+v", m.Bodies)
	}
}

func TestMSGCodePages(t *testing.T) {
	cases := []struct {
		cp   uint32
		e    encoding.Encoding
		want string
	}{
		{50220, japanese.ISO2022JP, "iso-2022-jp"},
		{50222, japanese.ISO2022JP, "iso-2022-jp"},
		{51932, japanese.EUCJP, "euc-jp"},
	}
	for _, c := range cases {
		b := buildMSG([]mapi{{pidInternetCodepage, c.cp}, {pidSubject, enc(c.e, "ご確認ください")}, {pidBody, enc(c.e, "こんにちは")}})
		m, err := ParseBytes(b, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if m.Subject != "ご確認ください" || m.Bodies[0].Content != "こんにちは" || m.Bodies[0].Charset != c.want {
			t.Errorf("cp %d: subject %q body %+v", c.cp, m.Subject, m.Bodies)
		}
	}
	// Without a code page, 8-bit text is guessed and the guess is reported.
	m, _ := ParseBytes(buildMSG([]mapi{{pidBody, enc(japanese.ShiftJIS, "本文です")}}), Options{})
	if m.Bodies[0].Content != "本文です" || codes(m.Warnings)[WarnCharsetGuessed] != 1 {
		t.Fatalf("guessed body %+v, warnings %v", m.Bodies, m.Warnings)
	}
	for cp, name := range codePageCharsets {
		if _, err := htmlindex.Get(name); err != nil {
			t.Errorf("code page %d maps to %q, which htmlindex does not know", cp, name)
		}
	}
}

func TestMSGDepthLimit(t *testing.T) {
	inner := embedded([]mapi{{pidSubject, "level 2"}},
		attach(0, []mapi{{pidAttachMethod, uint32(attachEmbedded)}}, embedded([]mapi{{pidSubject, "level 3"}})))
	b := buildMSG([]mapi{{pidSubject, "top"}}, attach(0, []mapi{{pidAttachMethod, uint32(attachEmbedded)}}, inner))
	m, err := ParseBytes(b, Options{MaxMessageDepth: 1})
	if err != nil {
		t.Fatal(err)
	}
	l2 := m.Attachments[0].Message
	if l2 == nil || l2.Subject != "level 2" || l2.Attachments[0].Message != nil || codes(l2.Warnings)[WarnMessageDepthLimit] != 1 {
		t.Fatalf("level 2 %+v", l2)
	}
	m, _ = ParseBytes(b, Options{})
	if m.Attachments[0].Message.Attachments[0].Message.Subject != "level 3" {
		t.Fatal("level 3 not opened under the default depth")
	}
}

func TestMSGDamaged(t *testing.T) {
	t.Run("no property stream at the root", func(t *testing.T) {
		b, _ := cfbtest.Build(3, cfbtest.Stream("__substg1.0_0037001F", u16le("x")), recip(0, mapi{pidDisplayName, "x"}))
		if Detect(b) != FormatMSG {
			t.Fatal("not detected")
		}
		if _, err := ParseBytes(b, Options{}); !errors.Is(err, ErrNotMessage) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("truncated file", func(t *testing.T) {
		data := bytes.Repeat([]byte("0123456789"), 1000)
		b := buildMSG([]mapi{{pidSubject, "cut"}}, attach(0, []mapi{{pidAttachData, data}}))
		m, err := ParseBytes(b[:len(b)-3000], Options{})
		if err != nil {
			t.Fatal(err)
		}
		a := m.Attachments[0]
		if codes(m.Warnings)[WarnCFBDamaged] == 0 || a.Size == 0 || a.Size >= len(data) || !bytes.Equal(a.Data, data[:a.Size]) {
			t.Fatalf("warnings %v, kept %d", m.Warnings, a.Size)
		}
	})
	t.Run("short property stream", func(t *testing.T) {
		b := buildMSG([]mapi{{pidSubject, "s"}},
			cfbtest.Dir(attachPrefix+"00000000", cfbtest.Stream(propsStream, []byte{1, 2, 3}), cfbtest.Stream("__substg1.0_37010102", []byte("data"))),
			cfbtest.Dir(attachPrefix+"00000001", cfbtest.Stream("__substg1.0_37010102", []byte("orphan"))),
		)
		m, err := ParseBytes(b, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if codes(m.Warnings)[WarnMSGStructure] != 2 || string(m.Attachments[0].Data) != "data" || string(m.Attachments[1].Data) != "orphan" {
			t.Fatalf("warnings %v, attachments %+v", m.Warnings, m.Attachments)
		}
	})
	t.Run("embedded without storage", func(t *testing.T) {
		b := buildMSG([]mapi{{pidSubject, "s"}}, attach(0, []mapi{{pidAttachMethod, uint32(attachEmbedded)}}))
		m, _ := ParseBytes(b, Options{})
		if codes(m.Warnings)[WarnMSGStructure] != 1 || m.Attachments[0].Message != nil {
			t.Fatalf("warnings %v", m.Warnings)
		}
	})
	t.Run("by-value without data", func(t *testing.T) {
		b := buildMSG([]mapi{{pidSubject, "s"}}, attach(0, []mapi{{pidAttachMethod, uint32(attachByValue)}}))
		m, _ := ParseBytes(b, Options{})
		if codes(m.Warnings)[WarnMSGStructure] != 1 {
			t.Fatalf("warnings %v", m.Warnings)
		}
	})
}

func TestMSGLimits(t *testing.T) {
	var atts []*cfbtest.Node
	for i := range 4 {
		atts = append(atts, attach(i, []mapi{{pidAttachData, bytes.Repeat([]byte{byte('a' + i)}, 5000)}}))
	}
	b := buildMSG([]mapi{{pidSubject, "many"}}, atts...)
	m, err := ParseBytes(b, Options{MaxParts: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Attachments) != 2 || codes(m.Warnings)[WarnPartLimit] != 1 {
		t.Fatalf("attachments %d, warnings %v", len(m.Attachments), m.Warnings)
	}
	m, _ = ParseBytes(b, Options{MaxDecoded: 12000})
	got := codes(m.Warnings)[WarnDecodedLimit]
	if got == 0 || got > 2 || m.Attachments[3].Data != nil || len(m.Attachments[0].Data) != 5000 {
		t.Fatalf("warnings %v, sizes %d %d %d %d", m.Warnings, m.Attachments[0].Size, m.Attachments[1].Size, m.Attachments[2].Size, m.Attachments[3].Size)
	}
}

func TestMSGInsideEML(t *testing.T) {
	msg := sampleMSG()
	eml := "From: a@example.com\r\nTo: b@example.org\r\nSubject: fwd\r\nMessage-ID: <o@example.com>\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n" +
		"--b\r\nContent-Type: application/vnd.ms-outlook; name=\"x.msg\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString(msg) + "\r\n--b--\r\n"
	m, err := ParseBytes([]byte(eml), Options{})
	if err != nil {
		t.Fatal(err)
	}
	in := m.Attachments[0].Message
	if in == nil || in.Format != FormatMSG || in.Subject != "Invoice" || len(in.Attachments) != 5 {
		t.Fatalf("nested .msg %+v", in)
	}
	// A recognized .msg that does not open is reported, not dropped.
	broken := bytes.Clone(msg)
	broken[28] = 0 // the byte order mark: still recognized by its names, no longer opens
	eml2 := strings.Replace(eml, base64.StdEncoding.EncodeToString(msg), base64.StdEncoding.EncodeToString(broken), 1)
	m, _ = ParseBytes([]byte(eml2), Options{})
	if m.Attachments[0].Message != nil || codes(m.Warnings)[WarnNestedUnreadable] != 1 {
		t.Fatalf("warnings %v", m.Warnings)
	}
}

func TestMSGReviewFindings(t *testing.T) {
	cyr := charmap.Windows1251
	koi := charmap.KOI8R
	t.Run("code page per property kind", func(t *testing.T) {
		b := buildMSG([]mapi{
			{pidMessageCodepage, uint32(1251)}, {pidInternetCodepage, uint32(20866)},
			{pidSubject, enc(cyr, "привет мир")}, {pidBody, enc(koi, "тело письма")},
		})
		m, _ := ParseBytes(b, Options{})
		if m.Subject != "привет мир" || m.Bodies[0].Content != "тело письма" || m.Bodies[0].Charset != "koi8-r" {
			t.Fatalf("subject %q body %+v", m.Subject, m.Bodies)
		}
		jp := buildMSG([]mapi{
			{pidMessageCodepage, uint32(932)}, {pidInternetCodepage, uint32(50220)},
			{pidSubject, enc(japanese.ShiftJIS, "件名")}, {pidBody, enc(japanese.ISO2022JP, "本文")},
		})
		m, _ = ParseBytes(jp, Options{})
		if m.Subject != "件名" || m.Bodies[0].Content != "本文" || len(m.Warnings) != 1 {
			t.Fatalf("japanese: %q %+v %v", m.Subject, m.Bodies, m.Warnings)
		}
	})
	t.Run("shown and SMTP addresses differ", func(t *testing.T) {
		b := buildMSG([]mapi{{pidSentRepName, "CEO"}, {pidSentRepEmail, "attacker@evil.example"}, {pidSentRepSMTP, "ceo@corp.example"}})
		m, _ := ParseBytes(b, Options{})
		if codes(m.Warnings)[WarnAddressMismatch] != 1 || m.From[0].Mailboxes[0].Address != "ceo@corp.example" || !strings.Contains(m.From[0].Raw, "attacker@evil.example") {
			t.Fatalf("%v %+v", m.Warnings, m.From)
		}
	})
	t.Run("MAPI sender differs from the headers", func(t *testing.T) {
		b := buildMSG([]mapi{{pidTransportHeaders, msgHeaders}, {pidSubject, "Invoice"}, {pidSentRepSMTP, "ceo@corp.example"}})
		m, _ := ParseBytes(b, Options{})
		if got := codes(m.Warnings); got[WarnHeaderMismatch] != 1 {
			t.Fatalf("%v", m.Warnings)
		}
	})
	t.Run("many recipients are not cut", func(t *testing.T) {
		var rs []*cfbtest.Node
		for i := range 1100 {
			rs = append(rs, recip(i, mapi{pidRecipientType, uint32(1)}, mapi{pidSMTPAddress, fmt.Sprintf("r%d@example.org", i)}))
		}
		m, err := ParseBytes(buildMSG([]mapi{{pidSubject, "all hands"}}, rs...), Options{})
		if err != nil || len(m.To) != 1 || len(m.To[0].Mailboxes) != 1100 || codes(m.Warnings)[WarnCFBDamaged] != 0 {
			t.Fatalf("%v %d %v", err, len(m.To[0].Mailboxes), codes(m.Warnings))
		}
	})
	t.Run("recipient types and empty rows", func(t *testing.T) {
		b := buildMSG([]mapi{{pidSubject, "x"}},
			recip(0, mapi{pidRecipientType, uint32(0)}, mapi{pidSMTPAddress, "orig@example.org"}),
			recip(1, mapi{pidRecipientType, uint32(1)}))
		m, _ := ParseBytes(b, Options{})
		if codes(m.Warnings)[WarnRecipientType] != 2 || len(m.To[0].Mailboxes) != 1 {
			t.Fatalf("%v %+v", m.Warnings, m.To)
		}
	})
	t.Run("attachment with neither method nor data", func(t *testing.T) {
		m, _ := ParseBytes(buildMSG([]mapi{{pidSubject, "x"}}, attach(0, []mapi{{pidAttachLongFilename, "ghost.pdf"}})), Options{})
		if codes(m.Warnings)[WarnMSGStructure] != 1 {
			t.Fatalf("%v", m.Warnings)
		}
	})
	t.Run("embedded message parts and Unicode body size", func(t *testing.T) {
		m, _ := ParseBytes(sampleMSG(), Options{})
		if in := m.Attachments[2].Message; in.Bodies[0].Part != "msg/body" {
			t.Fatalf("part %q", in.Bodies[0].Part)
		}
		if m.Bodies[0].Size != 2*len("plain body") {
			t.Fatalf("size %d", m.Bodies[0].Size)
		}
	})
	t.Run("warnings are capped per code", func(t *testing.T) {
		var rs []*cfbtest.Node
		for i := range 300 {
			rs = append(rs, recip(i, mapi{pidRecipientType, uint32(9)}, mapi{pidSMTPAddress, "x@example.org"}))
		}
		m, _ := ParseBytes(buildMSG([]mapi{{pidSubject, "x"}}, rs...), Options{})
		if got := codes(m.Warnings); got[WarnRecipientType] != maxWarningsPerCode || got[WarnWarningLimit] != 1 {
			t.Fatalf("%v", got)
		}
	})
}
