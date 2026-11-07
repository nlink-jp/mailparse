package mailparse

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nlink-jp/mailparse/internal/cfbtest"
)

func TestSecondReviewFindings(t *testing.T) {
	t.Run("cfb issues go through the warning cap", func(t *testing.T) {
		var nodes []*cfbtest.Node
		for i := range 400 {
			nodes = append(nodes, cfbtest.Stream(fmt.Sprintf("s%03d", i), []byte("x")))
		}
		b, lay := cfbtest.Build(3, append(msgObject(32, []mapi{{pidSubject, "x"}}), nodes...)...)
		for i := range 400 { // every stream claims mini sector 0
			binary.LittleEndian.PutUint32(b[lay.EntryOffset(lay.IDs[fmt.Sprintf("/s%03d", i)])+116:], 0)
		}
		m, err := ParseBytes(b, Options{})
		if err != nil || codes(m.Warnings)[WarnCFBDamaged] > maxWarningsPerCode+1 {
			t.Fatalf("%v %v", err, codes(m.Warnings))
		}
	})
	t.Run("TNEF recipient rows are capped", func(t *testing.T) {
		rows := make([]byte, 4*20000) // 20,000 empty rows
		m, _ := ParseBytes(tnefStream(tnefAttr(tnefLevelMessage, attRecipTable, append(le32b(20000), rows...))), Options{})
		if codes(m.Warnings)[WarnTNEFDamaged] != 1 {
			t.Fatalf("%v", codes(m.Warnings))
		}
	})
	t.Run("link targets decode as Word reads them", func(t *testing.T) {
		x := extractRTFFull([]byte(`{\rtf1\ansi {\field{\*\fldinst HYPERLINK "https://evil.example\u47?@good.com"}{\fldrslt click}}}`))
		if x.text != "click <https://evil.example/@good.com>" {
			t.Fatalf("%q", x.text)
		}
		x = extractRTFFull([]byte(`{\rtf1\ansi {\field{\*\fldinst HYPERLINK "http://\'e9x.com"}{\fldrslt click}}}`))
		if x.text != "click <http://éx.com>" || !utf8.ValidString(x.text) {
			t.Fatalf("%q", x.text)
		}
	})
	t.Run("an unclosed field keeps its target", func(t *testing.T) {
		x := extractRTFFull([]byte(`{\rtf1 {\field{\*\fldinst HYPERLINK "http://open.example/"}{\fldrslt click}`))
		if x.text != "click <http://open.example/>" {
			t.Fatalf("%q", x.text)
		}
	})
	t.Run("state changes past the depth cap do not leak", func(t *testing.T) {
		in := `{\rtf1\fromhtml1 {\*\htmltag <p>}` + strings.Repeat("{", 1100) + `{\htmlrtf x}` + strings.Repeat("}", 1100) + `{\*\htmltag SHOWN}}`
		if x := extractRTFFull([]byte(in)); !strings.HasSuffix(x.text, "SHOWN") || !x.tooDeep {
			t.Fatalf("%q", x.text)
		}
	})
	t.Run("a Shift_JIS trail byte cannot inject a mailbox", func(t *testing.T) {
		m, _ := ParseBytes([]byte("From: \"\x83\\\" <ceo@corp.example>, \" <attacker@evil.example>\r\nMessage-ID: <x@example.com>\r\n\r\nx"), Options{})
		if len(m.From[0].Mailboxes) == 0 || m.From[0].Mailboxes[0].Address != "attacker@evil.example" || !utf8.ValidString(m.From[0].Mailboxes[0].Name) {
			t.Fatalf("%+v", m.From)
		}
	})
	t.Run("ordinary minimal messages are still mail", func(t *testing.T) {
		for _, in := range []string{
			"From: a@b.example\nTo: c@d.example\nSubject: report\n\nbody",
			"Content-Type: text/plain\nFrom: a@b.example\nSubject: s\n\nbody",
			"From:\n a@b.example\nTo: c@d.example\n\nbody",
			"From: a@b.example\nDate: 2024-01-01T00:00:00Z\nTo: c@d.example\n\nbody",
		} {
			if Detect([]byte(in)) != FormatEML {
				t.Errorf("not detected: %q", in)
			}
		}
		for _, in := range []string{
			"from: a@b.example\nto: c@d.example\n",
			"From: alerts@example.com\nTo: ops@example.com\nsmtp_host: mail.example.com\n",
		} {
			if Detect([]byte(in)) != FormatUnknown {
				t.Errorf("detected as mail: %q", in)
			}
		}
	})
	t.Run("RFC 2231 sections and forms", func(t *testing.T) {
		_, p, problems := parseParams(`attachment; filename*0="a"; filename*00="b"`)
		if p["filename"] != "a" || len(problems) != 1 {
			t.Fatalf("%v %v", p, problems)
		}
		_, p, problems = parseParams(`attachment; filename="invoice.pdf"; filename*=UTF-8''invoice.exe`)
		if p["filename"] != "invoice.exe" || len(problems) != 1 {
			t.Fatalf("%v %v", p, problems)
		}
		_, _, problems = parseParams(`text/plain; filename="same.pdf"; filename*=UTF-8''same.pdf`)
		if len(problems) != 0 {
			t.Fatalf("identical forms warned: %v", problems)
		}
	})
	t.Run("comments in unquoted values are dropped", func(t *testing.T) {
		mt, p, problems := parseParams(`text/plain (body); charset=us-ascii (Plain text); boundary=XX (c)`)
		if mt != "text/plain" || p["charset"] != "us-ascii" || p["boundary"] != "XX" || len(problems) != 0 {
			t.Fatalf("%q %v %v", mt, p, problems)
		}
	})
}
