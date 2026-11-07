package mailparse

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Phase 0 fixtures (testdata/eml/README.md): each test pins what the
// existing util-series parsers got wrong, or right, and mailparse must keep.

func load(t *testing.T, name string) *Message {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "eml", name))
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseBytes(b, Options{})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return m
}

func hasWarning(m *Message, code string) bool {
	for _, w := range m.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

func addrs(lists []AddressList) []string {
	var out []string
	for _, l := range lists {
		for _, mb := range l.Mailboxes {
			out = append(out, mb.Address)
		}
	}
	return out
}

func TestFixture01ISO2022JP(t *testing.T) {
	m := load(t, "01-iso2022jp.eml")
	if m.Subject != "請求書の送付について" {
		t.Errorf("subject = %q", m.Subject)
	}
	if len(m.From) != 1 || m.From[0].Mailboxes[0].Name != "経理部" || m.From[0].Mailboxes[0].Address != "billing@sender.example.net" {
		t.Errorf("from = %+v", m.From)
	}
	if len(m.Bodies) != 1 || !strings.Contains(m.Bodies[0].Content, "請求書を添付いたします") || m.Bodies[0].Charset != "iso-2022-jp" || m.Bodies[0].CharsetSource != "mime" {
		t.Errorf("body = %+v", m.Bodies)
	}
	if m.Date.IsZero() || m.MessageID != "<fixture-1@sender.example.net>" {
		t.Errorf("date %v id %q", m.Date, m.MessageID)
	}
	if len(m.Header.All("Received")) != 2 {
		t.Errorf("received = %d", len(m.Header.All("Received")))
	}
}

func TestFixture02RepairsBrokenEncodedWord(t *testing.T) {
	m := load(t, "02-broken-b64-word.eml")
	if m.Subject != "重要なお知らせ" {
		t.Errorf("subject = %q", m.Subject)
	}
	if !hasWarning(m, WarnRepairedEncodedWord) {
		t.Errorf("the repair must be recorded: %+v", m.Warnings)
	}
}

func TestFixture03RFC2231Filenames(t *testing.T) {
	m := load(t, "03-rfc2231-filenames.eml")
	if len(m.Attachments) != 2 || m.Attachments[0].Filename != "請求書.pdf" || m.Attachments[1].Filename != "見積書.pdf" {
		t.Fatalf("attachments = %+v", m.Attachments)
	}
	if !strings.HasPrefix(string(m.Attachments[0].Data), "%PDF-1.4") {
		t.Errorf("attachment bytes = %q", m.Attachments[0].Data)
	}
}

func TestFixture04OpensForwardedRFC822(t *testing.T) {
	m := load(t, "04-forwarded-rfc822.eml")
	if len(m.Attachments) != 1 || m.Attachments[0].Message == nil {
		t.Fatalf("the forwarded message must be opened: %+v", m.Attachments)
	}
	in := m.Attachments[0].Message
	if in.Subject != "Account verification" || strings.Join(addrs(in.From), ",") != "support@phish.example" {
		t.Errorf("inner = %q %v", in.Subject, addrs(in.From))
	}
	if len(in.Attachments) != 1 || in.Attachments[0].Filename != "invoice.zip" || len(in.Attachments[0].Data) != 22 {
		t.Errorf("inner attachments = %+v", in.Attachments)
	}
	if len(in.Bodies) != 1 || in.Bodies[0].MediaType != "text/html" {
		t.Errorf("inner bodies = %+v", in.Bodies)
	}
}

func TestFixture05OpensMessageRecognizedByContent(t *testing.T) {
	m := load(t, "05-forwarded-octet-stream.eml")
	if len(m.Attachments) != 1 || m.Attachments[0].MediaType != "application/octet-stream" {
		t.Fatalf("attachments = %+v", m.Attachments)
	}
	in := m.Attachments[0].Message
	if in == nil || in.Subject != "Account verification" {
		t.Fatalf("a message attached as octet-stream must be recognized and opened: %+v", in)
	}
}

func TestFixture06UnclosedBoundaryKeepsWhatWasRead(t *testing.T) {
	m := load(t, "06-unclosed-boundary.eml")
	if len(m.Bodies) != 2 || !strings.Contains(m.Bodies[1].Content, "second part") {
		t.Fatalf("both parts must be kept: %+v", m.Bodies)
	}
	if !hasWarning(m, WarnUnclosedBoundary) {
		t.Error("the missing closing delimiter must be warned about")
	}
}

func TestFixture07KeepsEveryDuplicate(t *testing.T) {
	m := load(t, "07-duplicate-headers.eml")
	if got := strings.Join(addrs(m.From), ","); got != "ceo@example.org,ceo@example.org,attacker@phish.example" {
		t.Errorf("every From and every mailbox must be kept: %s", got)
	}
	if len(m.From) != 2 || strings.Join(addrs(m.Sender), ",") != "attacker@phish.example" {
		t.Errorf("from occurrences %d sender %v", len(m.From), addrs(m.Sender))
	}
	ar := m.Header.All("Authentication-Results")
	if len(ar) != 2 || !strings.Contains(ar[1].Value, "spf=fail") {
		t.Fatalf("both Authentication-Results must be kept, in order: %+v", ar)
	}
	// Order across names is kept: A-R, Received, A-R, Received, From, From...
	var names []string
	for _, f := range m.Header[:6] {
		names = append(names, f.Name)
	}
	if strings.Join(names, ",") != "Authentication-Results,Received,Authentication-Results,Received,From,From" {
		t.Errorf("header order = %v", names)
	}
	if !hasWarning(m, WarnDuplicateField) {
		t.Error("a duplicated From must be warned about")
	}
}

func TestFixture08AddressParsedBeforeDecoding(t *testing.T) {
	m := load(t, "08-rfc2047-address-spoof.eml")
	if len(m.From) != 1 || len(m.From[0].Mailboxes) != 1 {
		t.Fatalf("from = %+v", m.From)
	}
	mb := m.From[0].Mailboxes[0]
	if mb.Address != "attacker@phish.example" {
		t.Errorf("the address must be the real one, not the one in the display name: %+v", mb)
	}
	if mb.Name != "Bank Security <security@bank.example>" {
		t.Errorf("the decoded display name stays a name: %q", mb.Name)
	}
}

func TestFixture09MetaCharset(t *testing.T) {
	m := load(t, "09-meta-charset.eml")
	if len(m.Bodies) != 1 || !strings.Contains(m.Bodies[0].Content, "パスワードの再設定") || m.Bodies[0].CharsetSource != "meta" || m.Bodies[0].Charset != "shift_jis" {
		t.Fatalf("body = %+v", m.Bodies)
	}
}

func TestFixture10MalformedHeaderLineDoesNotStopParsing(t *testing.T) {
	m := load(t, "10-malformed-header-line.eml")
	if m.Subject != "malformed" || strings.Join(addrs(m.To), ",") != "user@example.org" {
		t.Errorf("fields after the bad line must be read: subject %q to %v", m.Subject, addrs(m.To))
	}
	if len(m.Bodies) != 1 || !strings.Contains(m.Bodies[0].Content, "body survives") {
		t.Errorf("bodies = %+v", m.Bodies)
	}
	if !hasWarning(m, WarnMalformedHeaderLine) {
		t.Error("the skipped line must be warned about")
	}
}

func TestFixture11BadBase64IsNotEmpty(t *testing.T) {
	m := load(t, "11-bad-base64-attachment.eml")
	if len(m.Attachments) != 1 {
		t.Fatalf("attachments = %+v", m.Attachments)
	}
	data := m.Attachments[0].Data
	empty := sha256.Sum256(nil)
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) == hex.EncodeToString(empty[:]) || !strings.HasPrefix(string(data), "ABC") {
		t.Errorf("what decoded must be kept, not an empty result: %q", data)
	}
	if !hasWarning(m, WarnInvalidBase64) {
		t.Error("the damage must be warned about")
	}
}

// Every fixture is recognized as a message.
func TestFixturesAreDetected(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "eml", "*.eml"))
	if len(files) != 11 {
		t.Fatalf("%d fixtures", len(files))
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if got := Detect(b); got != FormatEML {
			t.Errorf("%s: Detect = %s", f, got)
		}
	}
}
