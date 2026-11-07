package mailparse

import (
	"strings"
	"testing"

	"golang.org/x/text/encoding/japanese"
)

func emlWith(header, body string) []byte {
	return []byte("From: a@example.com\r\nTo: b@example.org\r\nSubject: s\r\nMessage-ID: <r@example.com>\r\n" + header + "\r\n" + body)
}

func TestEMLReviewFindings(t *testing.T) {
	part := func(cd string) []byte {
		return emlWith("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n",
			"--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: "+cd+"\r\n\r\nMZ\r\n--b--\r\n")
	}
	t.Run("a bad parameter does not hide the filename", func(t *testing.T) {
		m, _ := ParseBytes(part(`attachment; filename="invoice.pdf.exe"; x`), Options{})
		a := m.Attachments[0]
		if a.Filename != "invoice.pdf.exe" || a.Disposition != "attachment" || codes(m.Warnings)[WarnInvalidParameters] != 1 {
			t.Fatalf("%+v %v", a, m.Warnings)
		}
	})
	t.Run("duplicate filename keeps the first and warns", func(t *testing.T) {
		m, _ := ParseBytes(part(`attachment; filename="a.exe"; filename="b.pdf"`), Options{})
		if m.Attachments[0].Filename != "a.exe" || codes(m.Warnings)[WarnInvalidParameters] != 1 {
			t.Fatalf("%+v %v", m.Attachments[0], m.Warnings)
		}
	})
	t.Run("RFC 2231 in any charset and continuations", func(t *testing.T) {
		m, _ := ParseBytes(part(`attachment; filename*=shift_jis''%90%BF%8B%81%8F%91.exe`), Options{})
		if m.Attachments[0].Filename != "請求書.exe" || len(m.Warnings) != 0 {
			t.Fatalf("%+v %v", m.Attachments[0], m.Warnings)
		}
		m, _ = ParseBytes(part(`attachment; filename*0*=utf-8''%E8%AB%8B; filename*1*=%E6%B1%82.pdf`), Options{})
		if m.Attachments[0].Filename != "請求.pdf" {
			t.Fatalf("%+v", m.Attachments[0])
		}
	})
	t.Run("an unsplittable multipart keeps its bytes", func(t *testing.T) {
		m, _ := ParseBytes(emlWith("Content-Type: multipart/mixed\r\n", "hidden content\r\n"), Options{})
		if len(m.Attachments) != 1 || string(m.Attachments[0].Data) != "hidden content\r\n" || codes(m.Warnings)[WarnMissingBoundary] != 1 {
			t.Fatalf("%+v %v", m.Attachments, m.Warnings)
		}
		m, _ = ParseBytes(emlWith("Content-Type: multipart/mixed; boundary=b; x\r\n", "--b\r\n\r\nbody\r\n--b--\r\n"), Options{})
		if len(m.Bodies) != 1 || m.Bodies[0].Content != "body" {
			t.Fatalf("a trailing bad parameter lost the boundary: %+v %v", m.Bodies, m.Warnings)
		}
	})
	t.Run("parts after the closing delimiter are read", func(t *testing.T) {
		m, _ := ParseBytes(emlWith("Content-Type: multipart/mixed; boundary=b\r\n",
			"--b\r\n\r\nshown\r\n--b--\r\n--b\r\nContent-Type: application/octet-stream; name=evil.exe\r\n\r\nMZ\r\n--b--\r\n"), Options{})
		if len(m.Attachments) != 1 || m.Attachments[0].Filename != "evil.exe" || codes(m.Warnings)[WarnPartsAfterClose] != 1 {
			t.Fatalf("%+v %v", m.Attachments, m.Warnings)
		}
	})
	t.Run("duplicate Content-Type is warned", func(t *testing.T) {
		m, _ := ParseBytes(emlWith("Content-Type: text/plain\r\nContent-Type: multipart/mixed; boundary=b\r\n", "x"), Options{})
		if codes(m.Warnings)[WarnDuplicateField] != 1 {
			t.Fatalf("%v", m.Warnings)
		}
	})
	t.Run("a part limit hit inside a nested message is told to the outer one", func(t *testing.T) {
		inner := "From: c@example.net\r\nMessage-ID: <i@example.net>\r\nContent-Type: multipart/mixed; boundary=i\r\n\r\n" +
			strings.Repeat("--i\r\n\r\nx\r\n", 10) + "--i--\r\n"
		m, _ := ParseBytes(emlWith("Content-Type: multipart/mixed; boundary=b\r\n",
			"--b\r\nContent-Type: message/rfc822\r\n\r\n"+inner+"\r\n--b\r\nContent-Type: application/octet-stream; name=evil.exe\r\n\r\nMZ\r\n--b--\r\n"), Options{MaxParts: 6})
		if codes(m.Warnings)[WarnPartLimit] != 1 {
			t.Fatalf("outer warnings %v", m.Warnings)
		}
	})
	t.Run("config files and HTTP dumps are not mail", func(t *testing.T) {
		for _, in := range []string{
			"from: alerts@example.com\nto: ops@example.com\nsmtp_host: mail.example.com\n",
			"subject: x\ndate: 2024-01-01\n",
			"Date: Mon, 01 Jan 2024 00:00:00 GMT\nContent-Type: text/html\nServer: nginx\n\n<html>",
		} {
			if Detect([]byte(in)) != FormatUnknown {
				t.Errorf("detected as mail: %q", in)
			}
		}
		if Detect([]byte("From: a@example.com\nTo: b@example.org\nDate: Mon, 01 Jan 2024 00:00:00 +0000\n\nhi")) != FormatEML {
			t.Error("From with an address and a mail Date is mail")
		}
	})
	t.Run("encoded-words in a wrong charset are reported", func(t *testing.T) {
		for _, subj := range []string{"=?utf-8?B?/////w==?=", "=?shift_jis?B?/////w==?="} {
			m, _ := ParseBytes([]byte("From: a@example.com\r\nMessage-ID: <x@example.com>\r\nSubject: "+subj+"\r\n\r\nx"), Options{})
			if codes(m.Warnings)[WarnUndecodableWord] != 1 || !strings.Contains(m.Subject, "\uFFFD") {
				t.Errorf("%s: %q %v", subj, m.Subject, m.Warnings)
			}
		}
	})
	t.Run("folding cannot grow a field past MaxHeaderBytes", func(t *testing.T) {
		b := []byte("From: a@example.com\r\nMessage-ID: <x@example.com>\r\nSubject: start\r\n" + strings.Repeat(" more folding\r\n", 10000) + "\r\nbody")
		m, _ := ParseBytes(b, Options{MaxHeaderBytes: 4096})
		if len(m.Subject) > 4096 || codes(m.Warnings)[WarnHeaderLimit] != 1 {
			t.Fatalf("subject %d bytes, %v", len(m.Subject), m.Warnings)
		}
	})
	t.Run("delimiter floods allocate only what the part budget reads", func(t *testing.T) {
		parts, _, _, cut := splitMultipart([]byte(strings.Repeat("--b\n", 100000)), "b", 11)
		if len(parts) != 11 || !cut {
			t.Fatalf("%d parts, cut %v", len(parts), cut)
		}
	})
	t.Run("raw 8-bit display names are converted", func(t *testing.T) {
		name, _ := japanese.ShiftJIS.NewEncoder().String("日本")
		m, _ := ParseBytes([]byte("From: "+name+" <a@example.com>\r\nMessage-ID: <x@example.com>\r\n\r\nx"), Options{})
		if m.From[0].Mailboxes[0].Name != "日本" || m.From[0].Mailboxes[0].Address != "a@example.com" {
			t.Fatalf("%+v", m.From)
		}
	})
	t.Run("Return-Path is parsed, null path included", func(t *testing.T) {
		m, _ := ParseBytes([]byte("Return-Path: <bounce@example.net>\r\nReturn-Path: <>\r\nFrom: a@example.com\r\nMessage-ID: <x@example.com>\r\n\r\nx"), Options{})
		if len(m.ReturnPath) != 2 || m.ReturnPath[0].Mailboxes[0].Address != "bounce@example.net" || len(m.ReturnPath[1].Mailboxes) != 0 || !m.ReturnPath[1].Parsed || len(m.Warnings) != 0 {
			t.Fatalf("%+v %v", m.ReturnPath, m.Warnings)
		}
	})
}
