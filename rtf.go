package mailparse

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"
)

// Compressed RTF (MS-OXRTFCP).

const (
	rtfCompressed   = 0x75465A4C // "LZFu"
	rtfUncompressed = 0x414C454D // "MELA"
)

// rtfDictionaryInit is the string the LZ77 dictionary starts with
// (MS-OXRTFCP 2.1.3.1.3); the write offset starts after it, at 207.
const rtfDictionaryInit = `{\rtf1\ansi\mac\deff0\deftab720{\fonttbl;}{\f0\fnil \froman ` +
	`\fswiss \fmodern \fscript \fdecor MS Sans SerifSymbolArialTimes New RomanCourier` +
	"{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx"

var (
	errRTFHeader   = errors.New("compressed RTF header is shorter than 16 bytes")
	errRTFType     = errors.New("compressed RTF has an unknown COMPTYPE")
	errRTFTooLarge = errors.New("compressed RTF declares a RAWSIZE over the remaining decoded budget")
)

// rtfResult is a decompressed RTF stream and what was wrong with it.
type rtfResult struct {
	data      []byte
	crcOK     bool
	truncated bool // the input ended early or the output is shorter than RAWSIZE
	short     bool // the stream holds fewer bytes than COMPSIZE says
	over      bool // the data runs past RAWSIZE; what follows was kept, up to the budget
}

// decompressRTF expands a PidTagRtfCompressed value. maxOut bounds the output:
// a RAWSIZE above it is refused before anything is expanded, and data running
// past RAWSIZE is kept only up to it. A CRC mismatch is reported but the output
// is kept (it is evidence). The output grows as it is produced; nothing is
// reserved from the declared RAWSIZE.
func decompressRTF(b []byte, maxOut int64) (rtfResult, error) {
	var r rtfResult
	if len(b) < 16 {
		return r, errRTFHeader
	}
	compSize := int64(binary.LittleEndian.Uint32(b[0:]))
	rawSize := int64(binary.LittleEndian.Uint32(b[4:]))
	compType := binary.LittleEndian.Uint32(b[8:])
	crc := binary.LittleEndian.Uint32(b[12:])
	end := 4 + compSize
	if end > int64(len(b)) {
		end, r.short = int64(len(b)), true
	}
	in := b[16:max(end, 16)]
	if compType != rtfUncompressed && compType != rtfCompressed {
		return r, errRTFType
	}
	if rawSize > maxOut {
		return r, errRTFTooLarge
	}
	if compType == rtfUncompressed {
		r.data = bytes.Clone(in[:min(int64(len(in)), maxOut)])
		r.crcOK = true // MS-OXRTFCP: the CRC field is not used for uncompressed data
		r.truncated = int64(len(r.data)) < rawSize
		r.over = int64(len(r.data)) > rawSize
		return r, nil
	}
	r.crcOK = rtfCRC(in) == crc

	var dict [4096]byte
	copy(dict[:], rtfDictionaryInit)
	wp := len(rtfDictionaryInit)
	out := make([]byte, 0, min(rawSize, 64<<10))
	i := 0
	for {
		if i >= len(in) {
			r.truncated = true
			break
		}
		ctrl := in[i]
		i++
		for bit := 0; bit < 8; bit++ {
			if ctrl&(1<<bit) == 0 {
				if i >= len(in) {
					r.truncated = true
					goto done
				}
				c := in[i]
				i++
				if int64(len(out)) < maxOut {
					out = append(out, c)
				}
				dict[wp] = c
				wp = (wp + 1) % len(dict)
				continue
			}
			if i+1 >= len(in) {
				r.truncated = true
				goto done
			}
			ref := int(in[i])<<8 | int(in[i+1])
			i += 2
			off, n := ref>>4, ref&0xF+2
			if off == wp {
				goto done // the end marker
			}
			for k := range n {
				c := dict[(off+k)%len(dict)]
				if int64(len(out)) < maxOut {
					out = append(out, c)
				}
				dict[wp] = c
				wp = (wp + 1) % len(dict)
			}
		}
	}
done:
	r.data = out
	if int64(len(out)) < rawSize {
		r.truncated = true
	}
	r.over = int64(len(out)) > rawSize
	return r, nil
}

// rtfCRC is MS-OXRTFCP 2.1.3.2: the standard CRC-32 table, starting at 0 and
// without the final inversion most CRC-32 uses apply.
func rtfCRC(b []byte) uint32 {
	var crc uint32
	for _, c := range b {
		crc = crc32.IEEETable[byte(crc)^c] ^ crc>>8
	}
	return crc
}

// RTF de-encapsulation (MS-OXRTFEX) and plain-text extraction.

type rtfKind int

const (
	rtfPlain rtfKind = iota // ordinary RTF
	rtfHTML                 // \fromhtml: HTML encapsulated by Outlook
	rtfText                 // \fromtext: plain text encapsulated by Outlook
)

// rtfEncapsulation looks for \fromhtml or \fromtext among the group marks and
// control words that open the document (MS-OXRTFEX 2.2.3.1). It reads as
// Outlook does (Appendix A, notes 13 and 14): without requiring \rtf1, and past
// the 10 tokens the specification recommends — up to the first text, at most
// 256 tokens — so a message Outlook de-encapsulates is not read as plain RTF.
func rtfEncapsulation(b []byte) rtfKind {
	if !bytes.HasPrefix(b, []byte(`{`)) {
		return rtfPlain
	}
	i := 0
	for tokens := 0; tokens < 256 && i < len(b); tokens++ {
		for i < len(b) && (b[i] == '\r' || b[i] == '\n') {
			i++
		}
		if i >= len(b) {
			break
		}
		switch {
		case b[i] == '{':
			i++
		case b[i] == '\\' && i+1 < len(b) && isLetter(b[i+1]):
			j := i + 1
			for j < len(b) && isLetter(b[j]) {
				j++
			}
			word := string(b[i+1 : j])
			for j < len(b) && (b[j] == '-' || isDigit(b[j])) {
				j++
			}
			if j < len(b) && b[j] == ' ' {
				j++
			}
			switch word {
			case "fromhtml":
				return rtfHTML
			case "fromtext":
				return rtfText
			}
			i = j
		default:
			return rtfPlain
		}
	}
	return rtfPlain
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool  { return c >= '0' && c <= '9' }

// rtfDestinations are groups that produce no visible text. The font table is
// read for its code pages; the rest are skipped.
var rtfDestinations = map[string]bool{
	"colortbl": true, "stylesheet": true, "info": true, "pict": true, "object": true,
	"header": true, "headerl": true, "headerr": true, "headerf": true,
	"footer": true, "footerl": true, "footerr": true, "footerf": true,
	"listtable": true, "listoverridetable": true, "revtbl": true, "rsidtbl": true,
	"generator": true, "xmlnstbl": true, "themedata": true, "colorschememapping": true,
	"latentstyles": true, "datastore": true, "filetbl": true,
	"bkmkstart": true, "bkmkend": true, "mmathPr": true, "userprops": true,
	"docvar": true, "private": true, "objdata": true,
}

// rtfSymbols are control words that stand for one character (MS-OXRTFEX
// 2.1.3.1.4.2 lists those valid inside HTMLTAG content).
var rtfSymbols = map[string]string{
	"par": "\r\n", "line": "\r\n", "tab": "\t",
	"lquote": "\u2018", "rquote": "\u2019", "ldblquote": "\u201C", "rdblquote": "\u201D",
	"bullet": "\u2022", "endash": "\u2013", "emdash": "\u2014",
	// Table and page breaks separate text that would otherwise run together
	// (a URL followed by the next cell would read as one longer host).
	"cell": "\t", "row": "\r\n", "page": "\r\n", "sect": "\r\n",
}

// maxRTFDepth bounds the group stack. Deeper groups are counted, not stacked,
// so memory stays bounded however many "{" an attacker writes.
const maxRTFDepth = 1024

type rtfGroup struct {
	skip     bool // a destination producing no text, or an ignorable \* group
	fonttbl  bool
	htmltag  bool
	htmlrtf  bool // text suppressed by \htmlrtf
	font     int
	uc       int // fallback characters after \uN
	first    bool
	starred  bool
	fontSeen int  // the font being defined inside the font table
	capture  bool // inside \fldinst: text is the field instruction, collected for HYPERLINK
}

// rtfField is an open \field group. Its \fldinst text is decoded as body
// text is — \'hh by code page, \uN as Unicode — so the target reported is the
// one Word would open.
type rtfField struct {
	depth  int // stack depth of the \field group
	inst   strings.Builder
	pend   []byte
	pendCP uint32
}

// rtfReader turns RTF into text, keeping track of code pages.
type rtfReader struct {
	kind       rtfKind
	defaultCP  uint32
	fontCP     map[int]uint32
	out        strings.Builder
	pending    []byte
	pendingCP  uint32
	skipFall   int    // fallback characters still to drop after \uN
	highSurr   rune   // a UTF-16 high surrogate from \uN waiting for its pair
	badCP      uint32 // a code page that could not decode (0 if none)
	deep       int    // groups opened past maxRTFDepth and not yet closed
	tooDeep    bool   // the depth limit was reached
	badUnicode bool   // a \uN escape was out of range or an unpaired surrogate
	fields     []rtfField
}

// rtfExtract is what extractRTFFull read.
type rtfExtract struct {
	kind       rtfKind
	text       string
	charset    string
	badCP      uint32
	tooDeep    bool
	badUnicode bool
}

// extractRTF returns the text an RTF document carries: the encapsulated HTML
// or plain text, or the visible text of ordinary RTF. The charset named is the
// document's default code page.
func extractRTF(b []byte) (kind rtfKind, text, charset string, badCP uint32) {
	x := extractRTFFull(b)
	return x.kind, x.text, x.charset, x.badCP
}

// extractRTFFull is extractRTF with everything it met. In ordinary and
// \fromtext RTF, a HYPERLINK field is written as its visible text followed by
// " <target>", the way Outlook renders such links as plain text, so the target
// is not lost. Hidden text (\v) is kept: for a reader looking for links, an
// over-report is safer than a gap.
func extractRTFFull(b []byte) rtfExtract {
	r := &rtfReader{kind: rtfEncapsulation(b), defaultCP: 1252, fontCP: map[int]uint32{}}
	stack := []rtfGroup{{uc: 1}}
	cur := func() *rtfGroup { return &stack[len(stack)-1] }
	// Text is copied inside HTMLTAG content, and elsewhere unless it is in a
	// skipped destination, the font table, or (encapsulated) suppressed by
	// \htmlrtf.
	visibleText := func() bool {
		g := cur()
		if g.htmltag {
			return true
		}
		if g.skip || g.fonttbl {
			return false
		}
		if r.kind == rtfHTML && g.htmlrtf {
			return false
		}
		return true
	}
	cp := func() uint32 {
		g := cur()
		if g.htmltag {
			return r.defaultCP
		}
		if c, ok := r.fontCP[g.font]; ok && c != 0 {
			return c
		}
		return r.defaultCP
	}

	i := 0
	for i < len(b) {
		c := b[i]
		switch c {
		case '{':
			i++
			r.skipFall = 0
			if len(stack) >= maxRTFDepth {
				r.deep++
				r.tooDeep = true
				continue
			}
			g := *cur()
			g.first, g.starred = true, false
			stack = append(stack, g)
			continue
		case '}':
			i++
			r.skipFall = 0
			if r.deep > 0 {
				r.deep--
				continue
			}
			if len(stack) > 1 {
				if n := len(r.fields); n > 0 && r.fields[n-1].depth == len(stack) {
					r.closeField(visibleText())
				}
				stack = stack[:len(stack)-1]
			}
			continue
		case '\r', '\n':
			i++
			continue
		case '\\':
		default:
			i++
			if r.dropFallback() {
				continue
			}
			if cur().fonttbl {
				continue
			}
			cur().first = false
			if cur().capture {
				r.capture(c, cp())
			} else if visibleText() {
				r.byte(c, cp())
			}
			continue
		}

		// A control word or symbol.
		if i+1 >= len(b) {
			break
		}
		n := b[i+1]
		if !isLetter(n) {
			i += 2
			g := cur()
			switch n {
			case '*':
				if r.deep == 0 {
					g.starred = true
				}
				continue
			case '\'':
				if i+1 < len(b) {
					if v, err := strconv.ParseUint(string(b[i:i+2]), 16, 8); err == nil {
						i += 2
						if r.dropFallback() || g.fonttbl {
							continue
						}
						g.first = false
						if g.capture {
							r.capture(byte(v), cp())
						} else if visibleText() {
							r.byte(byte(v), cp())
						}
						continue
					}
				}
				continue
			case '{', '}', '\\':
				g.first = false
				if r.dropFallback() {
					continue
				}
				if g.capture {
					r.capture(n, cp())
				} else if visibleText() {
					r.byte(n, cp())
				}
				continue
			case '~':
				if visibleText() {
					r.text("\u00A0")
				}
			case '_':
				if visibleText() {
					r.text("\u00AD")
				}
			case '\r', '\n':
				if visibleText() {
					r.text("\r\n")
				}
			}
			g.first = false
			continue
		}
		// A control word runs to the first non-letter and its parameter to the
		// first non-digit, however long: an over-long word or parameter is
		// consumed (and ignored), never leaked as text.
		j := i + 1
		for j < len(b) && isLetter(b[j]) {
			j++
		}
		word := string(b[i+1 : j])
		if len(word) > 32 {
			word = ""
		}
		param, hasParam := 0, false
		k := j
		if k < len(b) && b[k] == '-' {
			k++
		}
		for k < len(b) && isDigit(b[k]) {
			k++
		}
		if k > j && isDigit(b[k-1]) {
			if k-j <= 11 {
				if v, err := strconv.Atoi(string(b[j:k])); err == nil {
					param, hasParam = v, true
				}
			}
			j = k
		}
		if j < len(b) && b[j] == ' ' {
			j++
		}
		i = j
		r.skipFall = 0
		g := cur()
		first, starred := g.first, g.starred
		g.first = false
		if r.deep > 0 {
			// Past the depth cap, state changes cannot be undone when their
			// group closes, so they are ignored; text is still read.
			switch {
			case word == "bin" && hasParam && param > 0:
				i += min(param, len(b)-i)
			case word == "u" && hasParam:
				if visibleText() {
					r.unicode(param)
				}
				r.skipFall = g.uc
			default:
				if s, ok := rtfSymbols[word]; ok && visibleText() {
					r.text(s)
				}
			}
			continue
		}

		switch word {
		case "bin":
			if hasParam && param > 0 {
				i += min(param, len(b)-i)
			}
			continue
		case "ansicpg":
			if hasParam && param > 0 {
				r.defaultCP = uint32(param)
			}
			continue
		case "mac":
			r.defaultCP = 10000
			continue
		case "f":
			if g.fonttbl {
				g.fontSeen = param
			} else {
				g.font = param
			}
			continue
		case "deff":
			if hasParam {
				g.font = param
			}
			continue
		case "fcharset":
			if g.fonttbl {
				if c, ok := fontCharsetCodePage[param]; ok {
					r.fontCP[g.fontSeen] = c
				}
			}
			continue
		case "cpg":
			if g.fonttbl && hasParam && param > 0 {
				r.fontCP[g.fontSeen] = uint32(param)
			}
			continue
		case "uc":
			if hasParam && param >= 0 && param < 10 {
				g.uc = param
			}
			continue
		case "u":
			if hasParam {
				if g.capture {
					r.captureUnicode(param)
				} else if visibleText() {
					r.unicode(param)
				}
				r.skipFall = g.uc
			}
			continue
		case "htmlrtf":
			g.htmlrtf = !hasParam || param != 0
			continue
		case "htmltag":
			// HTMLTAG content is copied only in encapsulated HTML, and not from
			// inside a destination that is skipped as a whole.
			if first && starred && r.kind == rtfHTML && !g.skip && !g.fonttbl {
				g.htmltag = true
			} else if first {
				g.skip = true
			}
			continue
		case "field":
			if first && r.kind != rtfHTML && len(r.fields) < maxRTFDepth {
				r.fields = append(r.fields, rtfField{depth: len(stack)})
			}
			continue
		case "fldinst":
			if first {
				g.skip = true
				g.capture = len(r.fields) > 0 && r.fields[len(r.fields)-1].depth < len(stack)
			}
			continue
		case "fonttbl":
			if first {
				g.fonttbl = true
			}
			continue
		}
		if first && starred && !g.htmltag {
			g.skip = true // an ignorable destination other than HTMLTAG
			continue
		}
		if first && rtfDestinations[word] {
			g.skip = true
			continue
		}
		if s, ok := rtfSymbols[word]; ok && visibleText() {
			r.text(s)
		}
	}
	for len(r.fields) > 0 { // a field left open still names its target
		r.closeField(visibleText())
	}
	r.flushSurrogate()
	r.flush()
	charset := codePageCharset(r.defaultCP)
	if charset == "" {
		charset = "cp" + strconv.FormatUint(uint64(r.defaultCP), 10)
	}
	return rtfExtract{kind: r.kind, text: r.out.String(), charset: charset, badCP: r.badCP, tooDeep: r.tooDeep, badUnicode: r.badUnicode}
}

const maxFieldInst = 4096

// capture adds a byte of \fldinst text to the innermost open field.
func (r *rtfReader) capture(c byte, cp uint32) {
	f := &r.fields[len(r.fields)-1]
	if f.inst.Len()+len(f.pend) >= maxFieldInst {
		return
	}
	if len(f.pend) > 0 && cp != f.pendCP {
		r.flushField(f)
	}
	f.pendCP = cp
	f.pend = append(f.pend, c)
}

// captureUnicode adds a \uN character to the innermost open field.
func (r *rtfReader) captureUnicode(n int) {
	f := &r.fields[len(r.fields)-1]
	r.flushField(f)
	if f.inst.Len() >= maxFieldInst {
		return
	}
	if n < 0 {
		n += 65536
	}
	v := rune(n)
	if n > 65535 || utf16.IsSurrogate(v) {
		v = utf8.RuneError // pairs are not needed in a link target; reported as a bad escape
		r.badUnicode = true
	}
	f.inst.WriteRune(v)
}

func (r *rtfReader) flushField(f *rtfField) {
	if len(f.pend) == 0 {
		return
	}
	s, bad := decodeRun(f.pend, f.pendCP)
	if bad && r.badCP == 0 {
		r.badCP = f.pendCP
	}
	f.inst.WriteString(s)
	f.pend = f.pend[:0]
}

// closeField ends the innermost field and, for a HYPERLINK, writes its target.
func (r *rtfReader) closeField(visible bool) {
	f := &r.fields[len(r.fields)-1]
	r.flushField(f)
	inst := f.inst.String()
	r.fields = r.fields[:len(r.fields)-1]
	if target := hyperlinkTarget(inst); target != "" && visible {
		r.text(" <" + target + ">")
	}
}

// decodeRun decodes bytes in a code page, replacing only bytes that do not
// decode; bad says some did not.
func decodeRun(b []byte, cp uint32) (s string, bad bool) {
	if isASCII(b) && asciiCompatible(cp) {
		return string(b), false
	}
	if name := codePageCharset(cp); name != "" {
		if enc, err := htmlindex.Get(name); err == nil {
			if s, ok := decodeStrict(enc, b); ok {
				return s, false
			}
			if s, err := enc.NewDecoder().Bytes(b); err == nil {
				return strings.ToValidUTF8(string(s), "\uFFFD"), true
			}
		}
	}
	return strings.ToValidUTF8(string(b), "\uFFFD"), true
}

// hyperlinkTarget reads the target of a HYPERLINK field instruction:
// HYPERLINK "target" or HYPERLINK target, with switches (\l, \o, ...) skipped.
func hyperlinkTarget(inst string) string {
	f := strings.Fields(inst)
	if len(f) < 2 || !strings.EqualFold(f[0], "HYPERLINK") {
		return ""
	}
	rest := strings.TrimSpace(inst[strings.Index(strings.ToUpper(inst), "HYPERLINK")+len("HYPERLINK"):])
	for rest != "" {
		if strings.HasPrefix(rest, `\`) { // a switch, and its argument when quoted
			sw := rest
			if sp := strings.IndexAny(sw, " \t"); sp >= 0 {
				rest = strings.TrimSpace(sw[sp:])
			} else {
				return ""
			}
			if strings.HasPrefix(rest, `"`) {
				if e := strings.Index(rest[1:], `"`); e >= 0 {
					rest = strings.TrimSpace(rest[e+2:])
				} else {
					return ""
				}
			}
			continue
		}
		if strings.HasPrefix(rest, `"`) {
			if e := strings.Index(rest[1:], `"`); e >= 0 {
				return rest[1 : e+1]
			}
			return rest[1:]
		}
		return strings.Fields(rest)[0]
	}
	return ""
}

// dropFallback consumes one fallback character after \uN.
func (r *rtfReader) dropFallback() bool {
	if r.skipFall > 0 {
		r.skipFall--
		return true
	}
	return false
}

func (r *rtfReader) byte(c byte, cp uint32) {
	r.flushSurrogate()
	if len(r.pending) > 0 && cp != r.pendingCP {
		r.flush()
	}
	r.pendingCP = cp
	r.pending = append(r.pending, c)
}

func (r *rtfReader) text(s string) {
	r.flushSurrogate()
	r.flush()
	r.out.WriteString(s)
}

// flushSurrogate writes a high surrogate that found no low one as U+FFFD.
func (r *rtfReader) flushSurrogate() {
	if r.highSurr != 0 {
		r.highSurr = 0
		r.badUnicode = true
		r.flush()
		r.out.WriteRune(utf8.RuneError)
	}
}

// unicode writes a \uN character: N is a signed 16-bit value; one out of that
// range, or an unpaired surrogate, becomes U+FFFD and is reported.
func (r *rtfReader) unicode(n int) {
	if n < -32768 || n > 65535 {
		r.flushSurrogate()
		r.badUnicode = true
		r.text(string(utf8.RuneError))
		return
	}
	if n < 0 {
		n += 65536
	}
	v := rune(n)
	if utf16.IsSurrogate(v) {
		if v < 0xDC00 {
			r.flushSurrogate()
			r.highSurr = v
			return
		}
		if r.highSurr == 0 {
			r.badUnicode = true
			r.text(string(utf8.RuneError))
			return
		}
		v = utf16.DecodeRune(r.highSurr, v)
		r.highSurr = 0
	}
	r.text(string(v))
}

// noteBadCP records the first code page whose bytes did not decode.
func (r *rtfReader) noteBadCP() {
	if r.badCP == 0 {
		r.badCP = r.pendingCP
	}
}

// asciiCompatible reports whether ASCII bytes stand for themselves in a code
// page — not so for ISO-2022-JP (escape sequences) or UTF-16.
func asciiCompatible(cp uint32) bool {
	switch codePageCharset(cp) {
	case "iso-2022-jp", "utf-16le", "utf-16be":
		return false
	}
	return true
}

// flush decodes the pending bytes with their code page.
func (r *rtfReader) flush() {
	if len(r.pending) == 0 {
		return
	}
	s, bad := decodeRun(r.pending, r.pendingCP)
	r.pending = r.pending[:0]
	if bad {
		r.noteBadCP()
	}
	r.out.WriteString(s)
}

// rtfBody decompresses a PidTagRtfCompressed value and adds the body it
// carries: encapsulated HTML as text/html, encapsulated or extracted plain text
// as text/plain.
func (st *state) rtfBody(m *Message, comp []byte, part string, warn func(Warning)) {
	left := st.opt.MaxDecoded - st.decoded
	res, err := decompressRTF(comp, max(left, 0))
	switch {
	case errors.Is(err, errRTFTooLarge):
		warn(Warning{Code: WarnDecodedLimit, Detail: fmt.Sprintf("compressed RTF declaring %d bytes was not expanded: over the remaining decoded budget", binary.LittleEndian.Uint32(comp[4:])), Part: part})
		return
	case err != nil:
		warn(Warning{Code: WarnRTFDamaged, Detail: err.Error() + "; it was not read", Part: part})
		return
	}
	if !res.crcOK {
		warn(Warning{Code: WarnRTFCRC, Detail: "compressed RTF failed its CRC check; the expanded text was kept", Part: part})
	}
	if res.truncated || res.short {
		warn(Warning{Code: WarnRTFDamaged, Detail: fmt.Sprintf("compressed RTF ended early; %d bytes were expanded", len(res.data)), Part: part})
	}
	if res.over {
		warn(Warning{Code: WarnRTFDamaged, Detail: fmt.Sprintf("compressed RTF expands past its RAWSIZE of %d bytes; the %d bytes produced were kept", binary.LittleEndian.Uint32(comp[4:]), len(res.data)), Part: part})
	}
	data := st.budgeted(res.data, part, warn)
	if !bytes.HasPrefix(data, []byte(`{\rtf`)) {
		warn(Warning{Code: WarnRTFDamaged, Detail: "expanded RTF does not start with {\\rtf; it was not read as RTF", Part: part})
		return
	}
	x := extractRTFFull(data)
	if x.badCP != 0 {
		warn(Warning{Code: WarnUndecodableText, Detail: fmt.Sprintf("RTF text in code page %d did not decode; invalid bytes were replaced", x.badCP), Part: part})
	}
	if x.badUnicode {
		warn(Warning{Code: WarnUndecodableText, Detail: "RTF held a \\u escape out of range or an unpaired surrogate; it was replaced", Part: part})
	}
	if x.tooDeep {
		warn(Warning{Code: WarnRTFDamaged, Detail: fmt.Sprintf("RTF groups nested deeper than %d; the deeper ones were read with the formatting of that depth", maxRTFDepth), Part: part})
	}
	mt := "text/plain"
	if x.kind == rtfHTML {
		mt = "text/html"
	}
	m.Bodies = append(m.Bodies, Body{MediaType: mt, Content: x.text, Charset: x.charset, CharsetSource: "rtf", Size: len(data), Part: part})
}
