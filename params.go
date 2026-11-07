package mailparse

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"
)

// parseParams reads a Content-Type or Content-Disposition value leniently:
// "type; name=value; name*=charset'lang'percent-encoded; name*0=...". Go's
// mime.ParseMediaType drops every parameter when one is malformed and decodes
// RFC 2231 only for UTF-8 and US-ASCII, so an attacker could hide an
// attachment's name; here every parameter that can be read is kept, the first
// of a duplicate wins, RFC 2231 is decoded in any known charset, and each
// problem is returned (in our own words) for a Warning.
func parseParams(v string) (mediaType string, params map[string]string, problems []string) {
	params = map[string]string{}
	segs, unclosed := splitParams(v)
	if unclosed {
		problems = append(problems, "a quoted string is not closed; it runs to the end of the field")
	}
	if len(segs) == 0 {
		return "", params, problems
	}
	mediaType = strings.ToLower(strings.TrimSpace(segs[0]))
	if strings.Contains(mediaType, "=") {
		problems = append(problems, "the value starts with a parameter, not a type")
		mediaType = ""
		segs = append([]string{""}, segs...)
	}

	type piece struct {
		val      string
		extended bool
	}
	continued := map[string]map[int]piece{}
	extendedSingle := map[string]string{}
	seen := map[string]bool{}
	for _, seg := range segs[1:] {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		eq := strings.IndexByte(seg, '=')
		if eq <= 0 {
			problems = append(problems, fmt.Sprintf("a parameter without a value (%s) was skipped", safeToken(seg)))
			continue
		}
		key := strings.ToLower(strings.TrimSpace(seg[:eq]))
		val := unquoteParam(strings.TrimSpace(seg[eq+1:]))
		if seen[key] {
			problems = append(problems, fmt.Sprintf("parameter %s appears more than once; the first was kept", safeToken(key)))
			continue
		}
		seen[key] = true
		name, rest, star := strings.Cut(key, "*")
		switch {
		case !star:
			params[name] = val
		case rest == "":
			extendedSingle[name] = val
		default:
			ext := strings.HasSuffix(rest, "*")
			n, err := strconv.Atoi(strings.TrimSuffix(rest, "*"))
			if err != nil || n < 0 || n > 999 {
				problems = append(problems, fmt.Sprintf("parameter %s has an invalid RFC 2231 section; it was skipped", safeToken(key)))
				continue
			}
			if continued[name] == nil {
				continued[name] = map[int]piece{}
			}
			continued[name][n] = piece{val, ext}
		}
	}
	decode := func(name, charset string, raw []byte) (string, bool) {
		s, ok := decodeParamCharset(charset, raw)
		if !ok {
			problems = append(problems, fmt.Sprintf("parameter %s is in charset %s, which did not decode; it was kept as bytes", safeToken(name), safeToken(charset)))
		}
		return s, ok
	}
	for name, val := range extendedSingle {
		charset, raw, ok := split2231(val)
		if !ok {
			problems = append(problems, fmt.Sprintf("parameter %s* is not in RFC 2231 form; it was kept as written", safeToken(name)))
			params[name] = val
			continue
		}
		params[name], _ = decode(name, charset, raw)
	}
	for name, pieces := range continued {
		idx := make([]int, 0, len(pieces))
		for n := range pieces {
			idx = append(idx, n)
		}
		sort.Ints(idx)
		var charset string
		var buf []byte
		for k, n := range idx {
			if n != k {
				problems = append(problems, fmt.Sprintf("parameter %s skips RFC 2231 section %d; the sections before it were kept", safeToken(name), k))
				break
			}
			p := pieces[n]
			if !p.extended {
				buf = append(buf, p.val...)
				continue
			}
			v := p.val
			if n == 0 {
				cs, raw, ok := split2231(v)
				if !ok {
					problems = append(problems, fmt.Sprintf("parameter %s*0* is not in RFC 2231 form; it was kept as written", safeToken(name)))
					buf = append(buf, v...)
					continue
				}
				charset = cs
				buf = append(buf, raw...)
				continue
			}
			raw, err := url.PathUnescape(v)
			if err != nil {
				raw = v
			}
			buf = append(buf, raw...)
		}
		params[name], _ = decode(name, charset, buf)
	}
	return mediaType, params, problems
}

// splitParams splits on ";" outside quoted strings.
func splitParams(v string) (segs []string, unclosed bool) {
	var b strings.Builder
	quoted, escaped := false, false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case escaped:
			escaped = false
		case quoted && c == '\\':
			escaped = true
		case c == '"':
			quoted = !quoted
		case c == ';' && !quoted:
			segs = append(segs, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	segs = append(segs, b.String())
	return segs, quoted
}

// unquoteParam removes the quotes of a quoted-string and its backslash escapes.
func unquoteParam(v string) string {
	if len(v) < 1 || v[0] != '"' {
		return v
	}
	v = v[1:]
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '\\' && i+1 < len(v):
			i++
			b.WriteByte(v[i])
		case c == '"':
			return b.String()
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// split2231 splits charset'language'percent-encoded and unescapes the value.
func split2231(v string) (charset string, raw []byte, ok bool) {
	parts := strings.SplitN(v, "'", 3)
	if len(parts) != 3 {
		return "", nil, false
	}
	s, err := url.PathUnescape(parts[2])
	if err != nil {
		return "", nil, false
	}
	return strings.ToLower(parts[0]), []byte(s), true
}

func decodeParamCharset(charset string, raw []byte) (string, bool) {
	switch normalizeCharset(charset) {
	case "", "us-ascii", "utf-8":
		if utf8.Valid(raw) {
			return string(raw), true
		}
		return strings.ToValidUTF8(string(raw), "\uFFFD"), false
	}
	if enc, err := htmlindex.Get(normalizeCharset(charset)); err == nil {
		if s, ok := decodeStrict(enc, raw); ok {
			return s, true
		}
	}
	return strings.ToValidUTF8(string(raw), "\uFFFD"), false
}
