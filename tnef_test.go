package mailparse

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"

	"github.com/nlink-jp/mailparse/msgtest"
)

// TNEF built from MS-OXTNEF for tests.

type tprop struct {
	tag uint32 // id<<16 | type
	val any    // []byte (variable), uint32, uint16, time.Time, bool, [][]byte (multi-valued)
	// name, when set, makes it a named property with this numeric ID (kind 0)
	// or string name (kind 1).
	nameID  uint32
	nameStr string
}

func le32b(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

func tnefPropList(ps ...tprop) []byte {
	out := make([]msgtest.TNEFProp, len(ps))
	for i, p := range ps {
		out[i] = msgtest.TNEFProp{Tag: p.tag, Value: p.val, NameID: p.nameID, NameString: p.nameStr}
	}
	return msgtest.TNEFProps(out...)
}

func tag(id, typ uint16) uint32 { return msgtest.Tag(id, typ) }

func tnefAttr(level byte, id uint32, data []byte) []byte { return msgtest.TNEFAttr(level, id, data) }

func tnefStream(attrs ...[]byte) []byte { return msgtest.TNEF(attrs...) }

func sampleTNEF() []byte {
	sj := japanese.ShiftJIS
	sjs := func(s string) []byte { return []byte(enc(sj, s)) }
	htmlRTF := `{\rtf1\ansi\ansicpg932\fromhtml1 \deff0{\fonttbl{\f0 Arial;}}{\*\htmltag <a href="http://tnef.example.com/r">}r{\*\htmltag </a>}}`
	inner := tnefStream(
		tnefAttr(tnefLevelMessage, attMsgProps, tnefPropList(tprop{tag: tag(pidSubject, ptUnicode), val: u16le("inner tnef")})),
	)
	return tnefStream(
		tnefAttr(tnefLevelMessage, attOemCodepage, append(le32b(932), le32b(0)...)),
		tnefAttr(tnefLevelMessage, attSubject, append(sjs("件名です"), 0)),
		tnefAttr(tnefLevelMessage, attBody, sjs("旧形式の本文")),
		tnefAttr(tnefLevelMessage, attMsgProps, tnefPropList(
			tprop{tag: tag(pidSenderName, ptString8), val: append(sjs("経理部"), 0)},
			tprop{tag: tag(pidSenderSMTP, ptUnicode), val: u16le("keiri@example.com")},
			tprop{tag: tag(pidClientSubmitTime, ptTime), val: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)},
			tprop{tag: tag(0x8005, ptUnicode), val: u16le("named, skipped"), nameID: 0x8233},
			tprop{tag: tag(0x8006, ptBinary), val: []byte("named by string"), nameStr: "x-custom"},
			tprop{tag: tag(0x0E1F, ptBoolean), val: true},
			tprop{tag: tag(0x0017, ptInt32), val: uint32(1)},
			tprop{tag: tag(0x3A01, 0x0002 /* PtypInteger16 */), val: uint16(7)},
			tprop{tag: tag(0x0E04, ptUnicode|0x1000), val: [][]byte{u16le("a"), u16le("b")}},
			tprop{tag: tag(pidRTFCompressed, ptBinary), val: compressLiteral([]byte(htmlRTF))},
		)),
		tnefAttr(tnefLevelMessage, attRecipTable, append(le32b(2), append(
			tnefPropList(tprop{tag: tag(pidRecipientType, ptInt32), val: uint32(1)}, tprop{tag: tag(pidDisplayName, ptUnicode), val: u16le("Bob")}, tprop{tag: tag(pidSMTPAddress, ptUnicode), val: u16le("bob@example.org")}),
			tnefPropList(tprop{tag: tag(pidRecipientType, ptInt32), val: uint32(2)}, tprop{tag: tag(pidEmailAddress, ptString8), val: []byte("carol@example.org\x00")})...)...)),

		tnefAttr(tnefLevelAttachment, attAttachRendData, make([]byte, 14)),
		tnefAttr(tnefLevelAttachment, attAttachTitle, []byte("DOC~1.PDF\x00")),
		tnefAttr(tnefLevelAttachment, attAttachData, []byte("%PDF-1.4 tnef")),
		tnefAttr(tnefLevelAttachment, attAttachment, tnefPropList(
			tprop{tag: tag(pidAttachLongFilename, ptUnicode), val: u16le("長い名前.pdf")},
			tprop{tag: tag(pidAttachMIMETag, ptString8), val: []byte("application/pdf\x00")},
		)),

		tnefAttr(tnefLevelAttachment, attAttachRendData, make([]byte, 14)),
		tnefAttr(tnefLevelAttachment, attAttachTitle, append(sjs("転送.eml"), 0)),
		tnefAttr(tnefLevelAttachment, attAttachData, []byte(innerEML)),

		tnefAttr(tnefLevelAttachment, attAttachRendData, make([]byte, 14)),
		tnefAttr(tnefLevelAttachment, attAttachment, tnefPropList(
			tprop{tag: tag(pidAttachMethod, ptInt32), val: uint32(attachEmbedded)},
			tprop{tag: tag(pidAttachData, ptObject), val: append(append([]byte{}, iidMessage...), inner...)},
		)),

		tnefAttr(tnefLevelAttachment, attAttachRendData, make([]byte, 14)),
		tnefAttr(tnefLevelAttachment, attAttachTitle, []byte("empty\x00")),
	)
}

func TestTNEF(t *testing.T) {
	b := sampleTNEF()
	if Detect(b) != FormatTNEF {
		t.Fatal("not detected")
	}
	m, err := ParseBytes(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Format != FormatTNEF || m.Subject != "件名です" || m.Date.IsZero() {
		t.Fatalf("format %s subject %q date %v", m.Format, m.Subject, m.Date)
	}
	if len(m.From) != 1 || m.From[0].Mailboxes[0].Name != "経理部" || m.From[0].Mailboxes[0].Address != "keiri@example.com" {
		t.Fatalf("from %+v", m.From)
	}
	if len(m.To) != 1 || m.To[0].Mailboxes[0].Address != "bob@example.org" || len(m.Cc) != 1 || m.Cc[0].Mailboxes[0].Address != "carol@example.org" {
		t.Fatalf("to %+v cc %+v", m.To, m.Cc)
	}
	if got := codes(m.Warnings); len(got) != 1 || got[WarnAttachmentNotExtracted] != 1 {
		t.Fatalf("warnings %v", m.Warnings)
	}
	if len(m.Bodies) != 2 {
		t.Fatalf("bodies %+v", m.Bodies)
	}
	if bd := m.Bodies[0]; bd.Part != "tnef/rtf" || bd.MediaType != "text/html" || !strings.Contains(bd.Content, "http://tnef.example.com/r") {
		t.Fatalf("rtf body %+v", bd)
	}
	if bd := m.Bodies[1]; bd.Part != "tnef/body" || bd.Content != "旧形式の本文" || bd.Charset != "shift_jis" {
		t.Fatalf("legacy body %+v", bd)
	}
	if len(m.Attachments) != 4 {
		t.Fatalf("attachments %d", len(m.Attachments))
	}
	a := m.Attachments
	if a[0].Filename != "長い名前.pdf" || a[0].MediaType != "application/pdf" || string(a[0].Data) != "%PDF-1.4 tnef" || a[0].Part != "tnef/attach/0" {
		t.Fatalf("pdf %+v", a[0])
	}
	if a[1].Filename != "転送.eml" || a[1].Message == nil || a[1].Message.Subject != "forwarded" {
		t.Fatalf("eml %+v", a[1])
	}
	if a[2].Message == nil || a[2].Message.Format != FormatTNEF || a[2].Message.Subject != "inner tnef" {
		t.Fatalf("embedded %+v", a[2].Message)
	}
	if a[3].Filename != "empty" || a[3].Data != nil {
		t.Fatalf("empty %+v", a[3])
	}
	// Attachment bytes are a copy, not a view of the input.
	a[0].Data[0] = 'X'
	if !bytes.Contains(b, []byte("%PDF-1.4 tnef")) {
		t.Fatal("attachment data aliases the input")
	}
	if m2, err := ParseTNEF(bytes.NewReader(b), Options{}); err != nil || m2.Subject != "件名です" {
		t.Fatalf("ParseTNEF: %v", err)
	}
	if _, err := ParseTNEF(strings.NewReader("not tnef"), Options{}); !errors.Is(err, ErrNotMessage) {
		t.Fatalf("garbage: %v", err)
	}
}

func TestTNEFInsideEML(t *testing.T) {
	eml := "From: a@example.com\r\nTo: b@example.org\r\nSubject: outer\r\nMessage-ID: <o@example.com>\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nsee winmail\r\n" +
		"--b\r\nContent-Type: application/ms-tnef; name=\"winmail.dat\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString(sampleTNEF()) + "\r\n--b--\r\n"
	m, err := ParseBytes([]byte(eml), Options{})
	if err != nil {
		t.Fatal(err)
	}
	w := m.Attachments[0]
	if w.Filename != "winmail.dat" || w.Message == nil || w.Message.Format != FormatTNEF || len(w.Message.Attachments) != 4 {
		t.Fatalf("winmail %+v", w)
	}
	// Two layers below the top: the embedded TNEF message is cut at depth 1.
	m, _ = ParseBytes([]byte(eml), Options{MaxMessageDepth: 1})
	in := m.Attachments[0].Message
	if in == nil || in.Attachments[2].Message != nil || codes(in.Warnings)[WarnMessageDepthLimit] < 1 {
		t.Fatalf("depth: %+v", in)
	}
}

func TestTNEFDamaged(t *testing.T) {
	good := tnefAttr(tnefLevelMessage, attSubject, []byte("kept\x00"))
	t.Run("checksum", func(t *testing.T) {
		bad := bytes.Clone(good)
		bad[len(bad)-1] ^= 0xFF
		m, err := ParseBytes(tnefStream(bad, bad), Options{})
		if err != nil || m.Subject != "kept" || codes(m.Warnings)[WarnTNEFDamaged] != 1 {
			t.Fatalf("%v %q %v", err, m.Subject, m.Warnings)
		}
	})
	t.Run("truncated attribute", func(t *testing.T) {
		b := tnefStream(good, tnefAttr(tnefLevelMessage, attBody, bytes.Repeat([]byte("x"), 100)))
		m, err := ParseBytes(b[:len(b)-50], Options{})
		if err != nil || m.Subject != "kept" || codes(m.Warnings)[WarnTNEFDamaged] != 1 || len(m.Bodies) != 0 {
			t.Fatalf("%v %v", err, m.Warnings)
		}
	})
	t.Run("trailing bytes and unknown level", func(t *testing.T) {
		b := tnefStream(good, tnefAttr(9, attSubject, []byte("x")), []byte{1, 2, 3})
		m, _ := ParseBytes(b, Options{})
		if codes(m.Warnings)[WarnTNEFDamaged] != 2 || m.Subject != "kept" {
			t.Fatalf("%v", m.Warnings)
		}
	})
	t.Run("broken property list", func(t *testing.T) {
		list := tnefPropList(tprop{tag: tag(pidSubject, ptUnicode), val: u16le("before")})
		binary.LittleEndian.PutUint32(list, 3) // three declared, one present
		list = append(list, le32b(tag(0x1234, 0x0099))...)
		m, _ := ParseBytes(tnefStream(tnefAttr(tnefLevelMessage, attMsgProps, list)), Options{})
		if m.Subject != "before" || codes(m.Warnings)[WarnTNEFDamaged] != 1 {
			t.Fatalf("%q %v", m.Subject, m.Warnings)
		}
	})
	t.Run("hostile counts", func(t *testing.T) {
		list := le32b(0xFFFFFFFF)
		list = append(list, le32b(tag(0x3001, ptUnicode))...)
		list = append(list, le32b(0xFFFFFFFF)...) // value count
		list = append(list, le32b(0x7FFFFFFF)...) // size
		recips := append(le32b(0xFFFFFFFF), list...)
		m, err := ParseBytes(tnefStream(tnefAttr(tnefLevelMessage, attMsgProps, list), tnefAttr(tnefLevelMessage, attRecipTable, recips)), Options{})
		if err != nil || codes(m.Warnings)[WarnTNEFDamaged] != 2 {
			t.Fatalf("%v %v", err, m.Warnings)
		}
	})
	t.Run("not a TNEF object", func(t *testing.T) {
		b := tnefStream(
			tnefAttr(tnefLevelAttachment, attAttachRendData, nil),
			tnefAttr(tnefLevelAttachment, attAttachment, tnefPropList(tprop{tag: tag(pidAttachData, ptObject), val: append(append([]byte{}, iidMessage...), "junk"...)})),
		)
		m, _ := ParseBytes(b, Options{})
		if codes(m.Warnings)[WarnNestedUnreadable] != 1 {
			t.Fatalf("%v", m.Warnings)
		}
	})
}

func TestTNEFPartLimit(t *testing.T) {
	var attrs [][]byte
	for range 5 {
		attrs = append(attrs, tnefAttr(tnefLevelAttachment, attAttachRendData, nil), tnefAttr(tnefLevelAttachment, attAttachData, []byte("d")))
	}
	m, _ := ParseBytes(tnefStream(attrs...), Options{MaxParts: 2})
	if len(m.Attachments) != 2 || codes(m.Warnings)[WarnPartLimit] != 1 {
		t.Fatalf("%d %v", len(m.Attachments), m.Warnings)
	}
}

func TestTNEFReviewFindings(t *testing.T) {
	t.Run("OEM code page for strings, internet for HTML", func(t *testing.T) {
		b := tnefStream(
			tnefAttr(tnefLevelMessage, attOemCodepage, append(le32b(1251), le32b(0)...)),
			tnefAttr(tnefLevelMessage, attSubject, append([]byte(enc(charmap.Windows1251, "привет")), 0)),
			tnefAttr(tnefLevelMessage, attMsgProps, tnefPropList(
				tprop{tag: tag(pidInternetCodepage, ptInt32), val: uint32(20866)},
				tprop{tag: tag(pidSenderName, ptString8), val: append([]byte(enc(charmap.Windows1251, "отдел")), 0)},
				tprop{tag: tag(pidHTML, ptBinary), val: []byte(enc(charmap.KOI8R, "<p>письмо</p>"))},
			)),
		)
		m, _ := ParseBytes(b, Options{})
		if m.Subject != "привет" || m.From[0].Mailboxes[0].Name != "отдел" || m.Bodies[0].Content != "<p>письмо</p>" {
			t.Fatalf("%q %+v %+v", m.Subject, m.From, m.Bodies)
		}
	})
	t.Run("MAPI values are charged to MaxDecoded", func(t *testing.T) {
		b := tnefStream(tnefAttr(tnefLevelMessage, attMsgProps, tnefPropList(
			tprop{tag: tag(pidHTML, ptBinary), val: bytes.Repeat([]byte("<p>x</p>"), 20000)},
			tprop{tag: tag(pidBody, ptUnicode), val: u16le(strings.Repeat("y", 50000))},
		)))
		m, _ := ParseBytes(b, Options{MaxDecoded: 1000})
		total := 0
		for _, bd := range m.Bodies {
			total += bd.Size
		}
		if codes(m.Warnings)[WarnDecodedLimit] == 0 || total > 1000 {
			t.Fatalf("%v %d", m.Warnings, total)
		}
	})
	t.Run("floods are bounded", func(t *testing.T) {
		var attrs [][]byte
		for range 3000 {
			attrs = append(attrs, tnefAttr(9, attSubject, nil))
		}
		for range 3000 {
			attrs = append(attrs, tnefAttr(tnefLevelAttachment, attAttachRendData, nil))
		}
		m, _ := ParseBytes(tnefStream(attrs...), Options{MaxParts: 10})
		got := codes(m.Warnings)
		if got[WarnTNEFDamaged] != maxWarningsPerCode || got[WarnWarningLimit] != 1 || len(m.Attachments) != 10 || got[WarnPartLimit] != 1 {
			t.Fatalf("%v, %d attachments", got, len(m.Attachments))
		}
	})
	t.Run("attMessageID is not a Message-ID", func(t *testing.T) {
		m, _ := ParseBytes(tnefStream(tnefAttr(tnefLevelMessage, attMessageID, []byte("0000000046A2B8C3D1E2F3A4\x00"))), Options{})
		if m.MessageID != "" {
			t.Fatalf("%q", m.MessageID)
		}
	})
	t.Run("short recipient table and trailing bytes", func(t *testing.T) {
		row := tnefPropList(tprop{tag: tag(pidSMTPAddress, ptUnicode), val: u16le("a@example.org")})
		list := append(tnefPropList(tprop{tag: tag(pidSubject, ptUnicode), val: u16le("s")}), make([]byte, 400)...)
		m, _ := ParseBytes(tnefStream(
			tnefAttr(tnefLevelMessage, attRecipTable, append(le32b(5), row...)),
			tnefAttr(tnefLevelMessage, attMsgProps, list),
		), Options{})
		if codes(m.Warnings)[WarnTNEFDamaged] != 2 || m.Subject != "s" || len(m.To) != 1 {
			t.Fatalf("%v", m.Warnings)
		}
	})
}
