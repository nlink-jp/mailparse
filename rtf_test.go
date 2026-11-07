package mailparse

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func unhexs(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// compressLiteral writes raw as a valid LZFu stream that uses only literals,
// ended by the end marker (a reference to the write offset).
func compressLiteral(raw []byte) []byte {
	var body []byte
	wp := len(rtfDictionaryInit)
	for i := 0; ; {
		ctrl := len(body)
		body = append(body, 0)
		for bit := 0; bit < 8; bit++ {
			if i == len(raw) {
				body[ctrl] |= 1 << bit
				ref := uint16(wp%4096) << 4
				body = append(body, byte(ref>>8), byte(ref))
				return rtfHeader(body, len(raw), rtfCompressed, rtfCRC(body))
			}
			body = append(body, raw[i])
			i++
			wp++
		}
	}
}

func rtfHeader(body []byte, raw int, typ, crc uint32) []byte {
	h := make([]byte, 16, 16+len(body))
	binary.LittleEndian.PutUint32(h[0:], uint32(len(body)+12))
	binary.LittleEndian.PutUint32(h[4:], uint32(raw))
	binary.LittleEndian.PutUint32(h[8:], typ)
	binary.LittleEndian.PutUint32(h[12:], crc)
	return append(h, body...)
}

func TestRTFDictionary(t *testing.T) {
	if len(rtfDictionaryInit) != 207 {
		t.Fatalf("dictionary init is %d bytes; MS-OXRTFCP says the write offset starts at 207", len(rtfDictionaryInit))
	}
}

func TestDecompressRTFSpecVectors(t *testing.T) {
	// MS-OXRTFCP 3.1.1 and 3.1.2.
	cases := []struct{ in, want string }{
		{"2d000000 2b000000 4c5a4675 f1c5c7a7 03000a00 72637067 31323542 320af320 68656c09 00206277 05b06c64 7d0a800f a0",
			"{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n"},
		{"1a000000 1c000000 4c5a4675 e2d44b51 41000420 5758595a 0d6e7d01 0eb0",
			"{\\rtf1 WXYZWXYZWXYZWXYZWXYZ}"},
	}
	for _, c := range cases {
		r, err := decompressRTF(unhexs(t, c.in), 1<<20)
		if err != nil || string(r.data) != c.want || !r.crcOK || r.truncated || r.short {
			t.Errorf("got %q %+v %v", r.data, r, err)
		}
	}
}

func TestDecompressRTFDamage(t *testing.T) {
	good := unhexs(t, "2d000000 2b000000 4c5a4675 f1c5c7a7 03000a00 72637067 31323542 320af320 68656c09 00206277 05b06c64 7d0a800f a0")
	want := "{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n"

	bad := append([]byte{}, good...)
	bad[12] ^= 0xFF
	if r, err := decompressRTF(bad, 1<<20); err != nil || r.crcOK || string(r.data) != want {
		t.Errorf("crc mismatch: %+v %v; the output must be kept", r, err)
	}
	if r, err := decompressRTF(good[:30], 1<<20); err != nil || !r.truncated || !r.short || !strings.HasPrefix(want, string(r.data)) || len(r.data) == 0 {
		t.Errorf("truncated: %q %+v %v", r.data, r, err)
	}
	if _, err := decompressRTF(good, 10); !errors.Is(err, errRTFTooLarge) {
		t.Errorf("RAWSIZE over the cap: %v", err)
	}
	if _, err := decompressRTF(good[:10], 1<<20); !errors.Is(err, errRTFHeader) {
		t.Errorf("short header: %v", err)
	}
	other := append([]byte{}, good...)
	copy(other[8:], "ABCD")
	if _, err := decompressRTF(other, 1<<20); !errors.Is(err, errRTFType) {
		t.Errorf("unknown type: %v", err)
	}
	mela := rtfHeader([]byte(`{\rtf1 plain}`), 13, rtfUncompressed, 0)
	if r, err := decompressRTF(mela, 1<<20); err != nil || string(r.data) != `{\rtf1 plain}` || !r.crcOK {
		t.Errorf("uncompressed: %q %v", r.data, err)
	}
	raw := []byte(strings.Repeat(`{\rtf1 literal only `, 50) + "}")
	if r, err := decompressRTF(compressLiteral(raw), 1<<20); err != nil || string(r.data) != string(raw) || !r.crcOK {
		t.Errorf("literal stream: %v %+v", err, r.crcOK)
	}
}

func TestRTFEncapsulation(t *testing.T) {
	cases := map[string]rtfKind{
		`{\rtf1\ansi\ansicpg1252\fromhtml1 \deff0{\fonttbl}`: rtfHTML,
		`{\rtf1\ansi\fromtext \deff0`:                        rtfText,
		`{\rtf1\ansi\deff0 hello \fromhtml1`:                 rtfPlain, // text before it
		`{\rtf1\a\b\c\d\e\f\g\h\i\j\fromhtml1`:               rtfHTML,  // past 10 tokens, as Outlook may (Appendix A note 14)
		`{\rtf0\fromhtml1`:                                   rtfHTML,  // without \rtf1, as Outlook does (note 13)
		`{\rtf1{\fonttbl{\f0 Arial;}}\fromhtml1`:             rtfPlain, // text came first
		`plain text`:                                         rtfPlain,
	}
	for in, want := range cases {
		if got := rtfEncapsulation([]byte(in)); got != want {
			t.Errorf("%q: got %d, want %d", in, got, want)
		}
	}
}

// The MS-OXRTFEX 3.1 example, without the indentation the published page adds.
const specExampleRTF = `{\rtf1\ANSI\ansicpg1251\fromhtml1 \deff0
{\fonttbl {\f0\fmodern Courier New;}{\f1\fswiss Arial;}{\f2\fswiss\fcharset0 Arial;}}
{\colortbl\red0\green0\blue0;\red0\green0\blue255;}
{\*\htmltag64}
\uc1\pard\plain\deftab360 \f0\fs24
{\*\htmltag <HTML><head>\par
<style>\par
<!--\par
 /* Style Definitions */\par
 p.MsoNormal, li.MsoNormal \{font-family:Arial;\}\par
-->\par
</style>\par
\tab <!-- This is a HTML comment.\par
There is a horizontal tab (%x09) character before the comment, \par
and some new lines inside the comment. -->\par
</head>\par
<body>\par
<p\par
class="MsoNormal">}
{\htmlrtf \f1 \htmlrtf0 Note the line break inside a P tag. {\*\htmltag <b>}{\htmlrtf \b \htmlrtf0 This is a bold text{\*\htmltag </b>}} \htmlrtf\par\htmlrtf0}
\htmlrtf \par \htmlrtf0
{\*\htmltag </p>\par
<p class="MsoNormal">\par}
{\htmlrtf \f1 \htmlrtf0 This is a normal text with a character references:
{\*\htmltag &nbsp;}\htmlrtf \'a0\htmlrtf0  {\*\htmltag &lt;}\htmlrtf <\htmlrtf0  {\*\htmltag &uml;}\htmlrtf {\f2\'a8}\htmlrtf0{\*\htmltag <br>\par}\htmlrtf\line\htmlrtf0
characters which have special meaning in RTF: \{\}\\{\*\htmltag <br>\par}\htmlrtf\line\htmlrtf0\htmlrtf\par\htmlrtf0}
{\*\htmltag </p>\par
<ol>\par
    <li class="MsoNormal">}{\htmlrtf {{\*\pn\pnlvlbody\pndec\pnstart1\pnindent360{\pntxta.}}\li360\fi-360{\pntext 1.\tab} \f1 \htmlrtf0 This is a list item}\htmlrtf\par\htmlrtf0}
{\*\htmltag \par
</ol>\par
</body>\par
</HTML>\par }}`

func TestRTFSpecExample(t *testing.T) {
	kind, html, charset, bad := extractRTF([]byte(specExampleRTF))
	if kind != rtfHTML || charset != "windows-1251" || bad != 0 {
		t.Fatalf("kind %d charset %s bad %d", kind, charset, bad)
	}
	for _, want := range []string{
		"<HTML><head>\r\n<style>\r\n<!--\r\n",
		"p.MsoNormal, li.MsoNormal {font-family:Arial;}\r\n",
		"</style>\r\n\t<!-- This is a HTML comment.\r\n",
		"<p\r\nclass=\"MsoNormal\">Note the line break inside a P tag. <b>This is a bold text</b> </p>\r\n<p class=\"MsoNormal\">\r\n",
		"&nbsp; &lt; &uml;<br>\r\n",
		"characters which have special meaning in RTF: {}\\<br>\r\n",
		"<li class=\"MsoNormal\">This is a list item\r\n</ol>\r\n</body>\r\n</HTML>\r\n",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q in\n%s", want, html)
		}
	}
	for _, not := range []string{"Courier", "fswiss", "1.\t", "\u00a0", "htmlrtf", "blue"} {
		if strings.Contains(html, not) {
			t.Errorf("suppressed or destination text %q leaked into\n%s", not, html)
		}
	}
}

func TestRTFCodePagesAndUnicode(t *testing.T) {
	// あ is 82 A0 in Shift_JIS (code page 932) and U+3042; 😀 is the surrogate
	// pair D83D DE00, written as negative \u values.
	in := `{\rtf1\ansi\ansicpg932\fromhtml1 \deff0{\fonttbl{\f0\fswiss\fcharset0 Arial;}{\f1\fnil\fcharset128 MS Gothic;}}` +
		`{\*\htmltag <p title="\'82\'a0">}` +
		`\f1 \'82\'a0` +
		`\f0 \u12354?` +
		`\u-10179?\u-8704?` +
		`{\*\htmltag </p>}}`
	_, html, charset, bad := extractRTF([]byte(in))
	if html != `<p title="あ">ああ😀</p>` || charset != "shift_jis" || bad != 0 {
		t.Fatalf("got %q %s %d", html, charset, bad)
	}
	// A byte sequence the font's code page cannot decode is replaced, and reported.
	_, _, _, bad = extractRTF([]byte(`{\rtf1\ansi\ansicpg932 \'82}`))
	if bad != 932 {
		t.Fatalf("bad code page %d", bad)
	}
}

func TestRTFPlainAndText(t *testing.T) {
	plain := `{\rtf1\ansi\deff0{\fonttbl{\f0 Arial;}}{\colortbl;\red0\green0\blue0;}{\info{\title secret}}` +
		`{\*\generator gen}\pard Hello\par World\tab!\line {\pict\bin4 ab}cd}x\{y\}}`
	kind, text, _, _ := extractRTF([]byte(plain))
	if kind != rtfPlain || text != "Hello\r\nWorld\t!\r\nx{y}" {
		t.Fatalf("plain: %d %q", kind, text)
	}
	enc := `{\rtf1\ansi\ansicpg1252\fromtext \deff0{\fonttbl{\f0\fswiss Arial;}}\htmlrtf{\*\x hidden}suppressed\htmlrtf0 line1\par line2}`
	kind, text, _, _ = extractRTF([]byte(enc))
	// \htmlrtf is an HTML-encapsulation rule; text encapsulation shows the text.
	if kind != rtfText || text != "suppressedline1\r\nline2" {
		t.Fatalf("fromtext: %d %q", kind, text)
	}
}

func TestMSGCompressedRTF(t *testing.T) {
	htmlRTF := `{\rtf1\ansi\ansicpg1252\fromhtml1 \deff0{\fonttbl{\f0 Arial;}}{\*\htmltag <a href="http://rtf.example.com/x">}link{\*\htmltag </a>}}`
	m, err := ParseBytes(buildMSG([]mapi{{pidSubject, "rtf only"}, {pidRTFCompressed, compressLiteral([]byte(htmlRTF))}}), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Bodies) != 1 {
		t.Fatalf("bodies %+v", m.Bodies)
	}
	b := m.Bodies[0]
	if b.MediaType != "text/html" || b.Content != `<a href="http://rtf.example.com/x">link</a>` || b.Part != "msg/rtf" || b.CharsetSource != "rtf" || b.Charset != "windows-1252" {
		t.Fatalf("body %+v", b)
	}

	bad := compressLiteral([]byte(htmlRTF))
	bad[12] ^= 1
	m, _ = ParseBytes(buildMSG([]mapi{{pidSubject, "x"}, {pidRTFCompressed, bad}}), Options{})
	if codes(m.Warnings)[WarnRTFCRC] != 1 || len(m.Bodies) != 1 {
		t.Fatalf("crc: %v %d", m.Warnings, len(m.Bodies))
	}

	huge := compressLiteral([]byte(htmlRTF))
	binary.LittleEndian.PutUint32(huge[4:], 50<<20)
	m, _ = ParseBytes(buildMSG([]mapi{{pidSubject, "x"}, {pidRTFCompressed, huge}}), Options{MaxDecoded: 1 << 20})
	if codes(m.Warnings)[WarnDecodedLimit] != 1 || len(m.Bodies) != 0 {
		t.Fatalf("budget: %v %d", m.Warnings, len(m.Bodies))
	}

	notRTF := compressLiteral([]byte("not rtf at all"))
	m, _ = ParseBytes(buildMSG([]mapi{{pidSubject, "x"}, {pidRTFCompressed, notRTF}}), Options{})
	if codes(m.Warnings)[WarnRTFDamaged] != 1 || len(m.Bodies) != 0 {
		t.Fatalf("not rtf: %v", m.Warnings)
	}
	m, _ = ParseBytes(buildMSG([]mapi{{pidSubject, "x"}, {pidRTFCompressed, []byte("short")}}), Options{})
	if codes(m.Warnings)[WarnRTFDamaged] != 1 {
		t.Fatalf("short: %v", m.Warnings)
	}
}

func FuzzRTF(f *testing.F) {
	f.Add(compressLiteral([]byte(specExampleRTF)))
	f.Add(compressLiteral([]byte(`{\rtf1\ansi\deff0{\fonttbl{\f0 Arial;}}\pard Hello\parስ4?{\*\x}\bin3 abc}`)))
	vec, _ := hex.DecodeString("2d0000002b0000004c5a4675f1c5c7a703000a00726370673132354232" + "0af32068656c090020627705b06c647d0a800fa0")
	f.Add(vec)
	f.Add(compressLiteral([]byte(`{\rtf1 ` + strings.Repeat("{", 3000) + `{\field{\*\fldinst HYPERLINK "http://x.example/"}{\fldrslt y}}`)))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := decompressRTF(b, 1<<20)
		if err != nil {
			return
		}
		if len(r.data) > 1<<20 {
			t.Fatalf("expanded %d bytes past the cap", len(r.data))
		}
		_, text, _, _ := extractRTF(r.data)
		if len(text) > 4*len(r.data)+16 {
			t.Fatalf("%d bytes of RTF gave %d bytes of text", len(r.data), len(text))
		}
	})
}

func TestRTFReviewFindings(t *testing.T) {
	text := func(in string) rtfExtract { return extractRTFFull([]byte(in)) }
	t.Run("deep groups stay bounded", func(t *testing.T) {
		x := text(`{\rtf1 ` + strings.Repeat("{", 200000) + "a" + strings.Repeat("}", 200000) + "b}")
		if !x.tooDeep || x.text != "ab" {
			t.Fatalf("%v %q", x.tooDeep, x.text)
		}
	})
	t.Run("hyperlink target in plain RTF", func(t *testing.T) {
		x := text(`{\rtf1\ansi {\field{\*\fldinst HYPERLINK "http://evil.example/p" \o "tip"}{\fldrslt click}} after}`)
		if x.text != "click <http://evil.example/p> after" {
			t.Fatalf("%q", x.text)
		}
		x = text(`{\rtf1 {\field{\*\fldinst{HYPERLINK \\l "anchor" http://a.example/}}{\fldrslt here}}}`)
		if x.text != "here <http://a.example/>" {
			t.Fatalf("switch: %q", x.text)
		}
		x = text(`{\rtf1 {\field{\*\fldinst PAGE}{\fldrslt 3}}}`)
		if x.text != "3" {
			t.Fatalf("non-link field: %q", x.text)
		}
	})
	t.Run("htmltag outside encapsulated HTML is skipped", func(t *testing.T) {
		for _, in := range []string{
			`{\rtf0 a{\*\htmltag <a href="http://evil.example/">}b}`,
			`{\rtf1\fromtext a{\*\htmltag <a href="http://evil.example/">}b}`,
		} {
			if x := text(in); x.text != "ab" {
				t.Errorf("%s: %q", in, x.text)
			}
		}
	})
	t.Run("htmltag inside a skipped destination is skipped", func(t *testing.T) {
		x := text(`{\rtf1\fromhtml1 {\*\generator{\*\htmltag <a href="http://inj.example/">}}{\info{\*\htmltag <b>}}{\*\htmltag <p>}}`)
		if x.text != "<p>" {
			t.Fatalf("%q", x.text)
		}
	})
	t.Run("table cells are separated", func(t *testing.T) {
		if x := text(`{\rtf1 http://a.example\cell b.example\cell\row}`); x.text != "http://a.example\tb.example\t\r\n" {
			t.Fatalf("%q", x.text)
		}
	})
	t.Run("over-long control words are consumed", func(t *testing.T) {
		x := text(`{\rtf1 ` + `\` + strings.Repeat("a", 40) + ` evil.example \f0000000000000000065 x}`)
		if x.text != "evil.example x" {
			t.Fatalf("%q", x.text)
		}
	})
	t.Run("unicode escapes out of range or unpaired", func(t *testing.T) {
		x := text(`{\rtf1 h\u967412?tp a\u-10179?b \u-8704?c}`)
		if x.text != "h\uFFFDtp a\uFFFDb \uFFFDc" || !x.badUnicode {
			t.Fatalf("%q %v", x.text, x.badUnicode)
		}
	})
	t.Run("7-bit code pages are decoded", func(t *testing.T) {
		// こんにちは in ISO-2022-JP, as \'hh escapes under \ansicpg50220.
		jis := "\x1b$B$3$s$K$A$O\x1b(B"
		var esc strings.Builder
		for _, c := range []byte(jis) {
			fmt.Fprintf(&esc, `\'%02x`, c)
		}
		if x := text(`{\rtf1\ansi\ansicpg50220 ` + esc.String() + `}`); x.text != "こんにちは" {
			t.Fatalf("%q", x.text)
		}
	})
	t.Run("one bad byte does not spoil the run", func(t *testing.T) {
		x := text(`{\rtf1\ansi\ansicpg932 \'82\'a0\'82\'a2\'82}`)
		if !strings.HasPrefix(x.text, "あい") || x.badCP != 932 {
			t.Fatalf("%q %d", x.text, x.badCP)
		}
	})
}

func TestDecompressRTFBounds(t *testing.T) {
	raw := []byte(`{\rtf1 http://beyond-rawsize.example/}`)
	b := compressLiteral(raw)
	binary.LittleEndian.PutUint32(b[4:], 10) // RAWSIZE smaller than the data
	r, err := decompressRTF(b, 1<<20)
	if err != nil || !r.over || string(r.data) != string(raw) {
		t.Fatalf("%v %+v %q", err, r.over, r.data)
	}
	if r, _ := decompressRTF(b, 20); len(r.data) != 20 {
		t.Fatalf("budget not applied past RAWSIZE: %d", len(r.data))
	}
	big := compressLiteral(raw)
	binary.LittleEndian.PutUint32(big[4:], 100<<20)
	if r, _ := decompressRTF(big, 200<<20); cap(r.data) > 64<<10 {
		t.Fatalf("reserved %d bytes from RAWSIZE", cap(r.data))
	}
	mela := rtfHeader(raw, 100<<20, rtfUncompressed, 0)
	if _, err := decompressRTF(mela, 1<<20); !errors.Is(err, errRTFTooLarge) {
		t.Fatalf("uncompressed over budget: %v", err)
	}
	m, _ := ParseBytes(buildMSG([]mapi{{pidSubject, "x"}, {pidRTFCompressed, b}}), Options{})
	if codes(m.Warnings)[WarnRTFDamaged] != 1 || !strings.Contains(m.Bodies[0].Content, "beyond-rawsize") {
		t.Fatalf("%v %+v", m.Warnings, m.Bodies)
	}
}
