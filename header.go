package mailparse

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

// Field is one header field as it appeared.
type Field struct {
	Name string `json:"name"`
	// Raw is the value exactly as written after the colon, folding included.
	Raw string `json:"raw"`
	// Value is Raw unfolded, trimmed, and with RFC 2047 encoded-words decoded.
	Value string `json:"value"`
}

// Header is every field of one header block, in order, duplicates kept.
type Header []Field

// All returns every field named name (case-insensitive), in order.
func (h Header) All(name string) []Field {
	var out []Field
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			out = append(out, f)
		}
	}
	return out
}

// First returns the first field named name, and whether there was one.
func (h Header) First(name string) (Field, bool) {
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			return f, true
		}
	}
	return Field{}, false
}

// splitField splits "Name: value" when Name is a valid field name (printable
// ASCII without a colon; obsolete whitespace before the colon is tolerated).
func splitField(line []byte) (name string, value []byte, ok bool) {
	i := bytes.IndexByte(line, ':')
	if i <= 0 {
		return "", nil, false
	}
	n := bytes.TrimRight(line[:i], " \t")
	if len(n) == 0 {
		return "", nil, false
	}
	for _, c := range n {
		if c < 33 || c > 126 {
			return "", nil, false
		}
	}
	return string(n), line[i+1:], true
}

// readHeader reads the header block at the start of b and returns it with the
// body that follows the first empty line. It never fails: lines that are
// neither a field nor a continuation are skipped with a warning, and fields
// beyond the limits are dropped with a warning — unlike net/textproto, which
// rejects the whole message over one bad line and keeps only a map by name.
func (st *state) readHeader(b []byte, part string, warn func(Warning)) (Header, []byte) {
	var h Header
	var cur *Field
	var curRaw []byte
	total, dropped := 0, false
	flush := func() {
		if cur == nil {
			return
		}
		cur.Raw = string(curRaw)
		cur.Value = st.decodeHeaderValue(cur.Name, curRaw, part, warn)
		h = append(h, *cur)
		cur, curRaw = nil, nil
	}
	lineNo := 0
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		var line, rest []byte
		if i < 0 {
			line, rest = b, nil
		} else {
			line, rest = b[:i], b[i+1:]
		}
		lineNo++
		trimmed := bytes.TrimSuffix(line, []byte("\r"))
		if len(trimmed) == 0 {
			flush()
			return h, rest // the empty line ends the header block
		}
		if lineNo == 1 && part == "" && bytes.HasPrefix(trimmed, []byte("From ")) {
			warn(Warning{Code: WarnMboxFromLine, Detail: "a leading mbox \"From \" separator line was skipped", Part: part})
			b = rest
			continue
		}
		total += len(line) + 1
		fields := len(h)
		if cur != nil {
			fields++ // the field still being read counts too
		}
		isField := trimmed[0] != ' ' && trimmed[0] != '\t'
		over := (isField && fields >= st.opt.MaxHeaders) || total > st.opt.MaxHeaderBytes || dropped
		if over && !dropped {
			dropped = true
			warn(Warning{Code: WarnHeaderLimit, Detail: fmt.Sprintf("header content after %d fields / %d bytes was not kept", len(h), st.opt.MaxHeaderBytes), Part: part})
		}
		switch {
		case !isField:
			if cur != nil && !over { // past the limit, a long field is cut too
				curRaw = append(curRaw, '\n')
				curRaw = append(curRaw, trimmed...)
			} else if !over {
				warn(Warning{Code: WarnMalformedHeaderLine, Detail: fmt.Sprintf("header line %d is a continuation with no field before it", lineNo), Part: part})
			}
		default:
			name, value, ok := splitField(trimmed)
			if !ok {
				flush()
				if !over {
					warn(Warning{Code: WarnMalformedHeaderLine, Detail: fmt.Sprintf("header line %d is not a field and was skipped", lineNo), Part: part})
				}
				break
			}
			flush()
			if over {
				break
			}
			cur = &Field{Name: name}
			curRaw = append([]byte(nil), value...)
		}
		b = rest
	}
	flush()
	return h, nil
}

// unfold removes folding (a line break followed by whitespace) and trims.
func unfold(raw []byte) string {
	s := strings.ReplaceAll(string(raw), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", "")
	return strings.TrimSpace(s)
}

// decodeHeaderValue unfolds a value, guesses the charset of raw 8-bit bytes,
// and decodes RFC 2047 encoded-words (repairing ones broken by whitespace).
func (st *state) decodeHeaderValue(name string, raw []byte, part string, warn func(Warning)) string {
	v := unfold(raw)
	if !utf8.ValidString(v) {
		if s, cs, ok := guessJapanese([]byte(v)); ok {
			v = s
			warn(Warning{Code: WarnRaw8BitHeader, Detail: fmt.Sprintf("%s held raw 8-bit bytes, read as %s", safeToken(name), cs), Part: part})
		} else {
			v = strings.ToValidUTF8(v, "\uFFFD")
			warn(Warning{Code: WarnRaw8BitHeader, Detail: fmt.Sprintf("%s held raw 8-bit bytes in no recognized charset; invalid bytes were replaced", safeToken(name)), Part: part})
		}
	}
	if !strings.Contains(v, "=?") {
		return v
	}
	return decodeWords(v, safeToken(name), part, warn)
}

var wordDecoder = &mime.WordDecoder{CharsetReader: charsetReader}

func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	enc, err := htmlindex.Get(normalizeCharset(charset))
	if err != nil {
		return nil, fmt.Errorf("unknown charset %q", safeToken(charset))
	}
	return transform.NewReader(input, enc.NewDecoder()), nil
}

// decodeWords decodes RFC 2047 encoded-words in s. Go's decoder sometimes
// returns its input unchanged with no error when a word is malformed (spaces
// injected into a Base64 payload by a broken MUA or folding), so leftover
// "=?" is treated as a failure and a repair is tried (from mail-analyzer).
func decodeWords(s, what, part string, warn func(Warning)) string {
	out, err := wordDecoder.DecodeHeader(s)
	if err == nil && !strings.Contains(out, "=?") {
		return checkDecodedWords(s, out, what, part, warn)
	}
	if fixed := repairEncodedWords(s); fixed != s {
		if out2, err2 := wordDecoder.DecodeHeader(fixed); err2 == nil && !strings.Contains(out2, "=?") {
			warn(Warning{Code: WarnRepairedEncodedWord, Detail: what + " held an encoded-word broken by whitespace; it was repaired", Part: part})
			return checkDecodedWords(s, out2, what, part, warn)
		}
	}
	if err != nil {
		warn(Warning{Code: WarnUndecodableWord, Detail: what + " held an encoded-word that could not be decoded (" + err.Error() + "); it is kept as written", Part: part})
		return s
	}
	// Decoded what it could; something that looks like an encoded-word remains.
	return checkDecodedWords(s, out, what, part, warn)
}

// checkDecodedWords catches what Go's decoder lets through: bytes that are not
// UTF-8 (a utf-8 word holding invalid bytes comes back as they are) and
// replacement characters a charset decoder put in for bytes it could not read.
func checkDecodedWords(in, out, what, part string, warn func(Warning)) string {
	switch {
	case !utf8.ValidString(out):
		warn(Warning{Code: WarnUndecodableWord, Detail: what + " held an encoded-word whose bytes are not valid in its charset; they were replaced", Part: part})
		return strings.ToValidUTF8(out, "\uFFFD")
	case strings.Count(out, "\uFFFD") > strings.Count(in, "\uFFFD"):
		warn(Warning{Code: WarnUndecodableWord, Detail: what + " held an encoded-word whose bytes are not valid in its charset; they were replaced", Part: part})
	}
	return out
}

// repairEncodedWords removes whitespace inside encoded-word payloads:
// "=?iso-2022-jp?B?abc def?=" becomes "=?iso-2022-jp?B?abcdef?=".
func repairEncodedWords(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		start := strings.Index(s, "=?")
		if start < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:start])
		s = s[start:]
		// =?charset?encoding?payload?= — find the two '?' after "=?", then "?=".
		q1 := strings.IndexByte(s[2:], '?')
		if q1 < 0 {
			b.WriteString(s)
			break
		}
		q2 := strings.IndexByte(s[2+q1+1:], '?')
		if q2 < 0 {
			b.WriteString(s)
			break
		}
		payloadStart := 2 + q1 + 1 + q2 + 1
		end := strings.Index(s[payloadStart:], "?=")
		if end < 0 {
			b.WriteString(s)
			break
		}
		payload := s[payloadStart : payloadStart+end]
		payload = strings.NewReplacer(" ", "", "\t", "").Replace(payload)
		b.WriteString(s[:payloadStart])
		b.WriteString(payload)
		b.WriteString("?=")
		s = s[payloadStart+end+2:]
	}
	return b.String()
}

// safeToken reduces attacker text to a short token for a warning's Detail.
func safeToken(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 40 {
			b.WriteString("…")
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('?')
		}
	}
	return b.String()
}
