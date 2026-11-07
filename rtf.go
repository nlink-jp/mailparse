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
}

// decompressRTF expands a PidTagRtfCompressed value. maxOut bounds the output:
// a RAWSIZE above it is refused before anything is expanded. A CRC mismatch
// is reported but the output is kept (it is evidence).
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
	switch compType {
	case rtfUncompressed:
		r.data = bytes.Clone(in[:min(int64(len(in)), rawSize, maxOut)])
		r.crcOK = true // MS-OXRTFCP: the CRC field is not used for uncompressed data
		r.truncated = int64(len(r.data)) < rawSize
		return r, nil
	case rtfCompressed:
	default:
		return r, errRTFType
	}
	if rawSize > maxOut {
		return r, errRTFTooLarge
	}
	r.crcOK = rtfCRC(in) == crc

	var dict [4096]byte
	copy(dict[:], rtfDictionaryInit)
	wp := len(rtfDictionaryInit)
	out := make([]byte, 0, rawSize)
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
				if int64(len(out)) < rawSize {
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
				if int64(len(out)) < rawSize {
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

// rtfEncapsulation inspects the first 10 tokens (MS-OXRTFEX 2.2.3.1). Only
// group marks and control words may come before \fromhtml or \fromtext.
func rtfEncapsulation(b []byte) rtfKind {
	if !bytes.HasPrefix(b, []byte(`{\rtf1`)) {
		return rtfPlain
	}
	i := 0
	for tokens := 0; tokens < 10 && i < len(b); tokens++ {
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
	"latentstyles": true, "datastore": true, "filetbl": true, "fldinst": true,
	"bkmkstart": true, "bkmkend": true, "mmathPr": true, "userprops": true,
	"docvar": true, "private": true, "objdata": true,
}

// rtfSymbols are control words that stand for one character (MS-OXRTFEX
// 2.1.3.1.4.2 lists those valid inside HTMLTAG content).
var rtfSymbols = map[string]string{
	"par": "\r\n", "line": "\r\n", "tab": "\t",
	"lquote": "\u2018", "rquote": "\u2019", "ldblquote": "\u201C", "rdblquote": "\u201D",
	"bullet": "\u2022", "endash": "\u2013", "emdash": "\u2014",
}

type rtfGroup struct {
	skip     bool // a destination producing no text, or an ignorable \* group
	fonttbl  bool
	htmltag  bool
	htmlrtf  bool // text suppressed by \htmlrtf
	font     int
	uc       int // fallback characters after \uN
	first    bool
	starred  bool
	fontSeen int // the font being defined inside the font table
}

// rtfReader turns RTF into text, keeping track of code pages.
type rtfReader struct {
	kind      rtfKind
	defaultCP uint32
	fontCP    map[int]uint32
	out       strings.Builder
	pending   []byte
	pendingCP uint32
	skipFall  int    // fallback characters still to drop after \uN
	highSurr  rune   // a UTF-16 high surrogate from \uN waiting for its pair
	badCP     uint32 // a code page that could not decode (0 if none)
}

// extractRTF returns the text an RTF document carries: the encapsulated HTML
// or plain text, or the visible text of ordinary RTF. The charset named is the
// document's default code page.
func extractRTF(b []byte) (kind rtfKind, text, charset string, badCP uint32) {
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
		if r.kind != rtfPlain && g.htmlrtf {
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
			g := *cur()
			g.first, g.starred = true, false
			stack = append(stack, g)
			r.skipFall = 0
			continue
		case '}':
			i++
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			r.skipFall = 0
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
			if visibleText() {
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
				g.starred = true
				continue
			case '\'':
				if i+1 < len(b) {
					if v, err := strconv.ParseUint(string(b[i:i+2]), 16, 8); err == nil {
						i += 2
						if r.dropFallback() || g.fonttbl {
							continue
						}
						g.first = false
						if visibleText() {
							r.byte(byte(v), cp())
						}
						continue
					}
				}
				continue
			case '{', '}', '\\':
				g.first = false
				if !r.dropFallback() && visibleText() {
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
		j := i + 1
		for j < len(b) && j-i <= 32 && isLetter(b[j]) {
			j++
		}
		word := string(b[i+1 : j])
		param, hasParam := 0, false
		k := j
		if k < len(b) && b[k] == '-' {
			k++
		}
		for k < len(b) && k-j <= 11 && isDigit(b[k]) {
			k++
		}
		if k > j && isDigit(b[k-1]) {
			if v, err := strconv.Atoi(string(b[j:k])); err == nil {
				param, hasParam = v, true
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
				if visibleText() {
					r.unicode(param)
				}
				r.skipFall = g.uc
			}
			continue
		case "htmlrtf":
			g.htmlrtf = !hasParam || param != 0
			continue
		case "htmltag":
			if first && starred && r.kind == rtfHTML {
				g.htmltag, g.skip = true, false
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
	r.flush()
	charset = codePageCharset(r.defaultCP)
	if charset == "" {
		charset = "cp" + strconv.FormatUint(uint64(r.defaultCP), 10)
	}
	return r.kind, r.out.String(), charset, r.badCP
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
	if len(r.pending) > 0 && cp != r.pendingCP {
		r.flush()
	}
	r.pendingCP = cp
	r.pending = append(r.pending, c)
}

func (r *rtfReader) text(s string) {
	r.flush()
	r.out.WriteString(s)
}

func (r *rtfReader) unicode(n int) {
	if n < 0 {
		n += 65536
	}
	v := rune(n)
	if utf16.IsSurrogate(v) {
		if v < 0xDC00 {
			r.highSurr = v
			return
		}
		if r.highSurr != 0 {
			v = utf16.DecodeRune(r.highSurr, v)
			r.highSurr = 0
		} else {
			v = utf8.RuneError
		}
	}
	r.text(string(v))
}

// flush decodes the pending bytes with their code page.
func (r *rtfReader) flush() {
	if len(r.pending) == 0 {
		return
	}
	b := r.pending
	r.pending = r.pending[:0]
	if isASCII(b) {
		r.out.Write(b)
		return
	}
	name := codePageCharset(r.pendingCP)
	if name != "" {
		if enc, err := htmlindex.Get(name); err == nil {
			if s, ok := decodeStrict(enc, b); ok {
				r.out.WriteString(s)
				return
			}
		}
	}
	if r.badCP == 0 {
		r.badCP = r.pendingCP
	}
	r.out.WriteString(strings.ToValidUTF8(string(b), "\uFFFD"))
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
	data := st.budgeted(res.data, part, warn)
	if !bytes.HasPrefix(data, []byte(`{\rtf`)) {
		warn(Warning{Code: WarnRTFDamaged, Detail: "expanded RTF does not start with {\\rtf; it was not read as RTF", Part: part})
		return
	}
	kind, text, charset, bad := extractRTF(data)
	if bad != 0 {
		warn(Warning{Code: WarnUndecodableText, Detail: fmt.Sprintf("RTF text in code page %d did not decode; invalid bytes were replaced", bad), Part: part})
	}
	mt := "text/plain"
	if kind == rtfHTML {
		mt = "text/html"
	}
	m.Bodies = append(m.Bodies, Body{MediaType: mt, Content: text, Charset: charset, CharsetSource: "rtf", Size: len(data), Part: part})
}
