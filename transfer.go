package mailparse

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// decodeTransfer undoes a Content-Transfer-Encoding. It never returns nothing
// for damaged input: Base64 skips characters outside the alphabet and decodes
// the rest, quoted-printable keeps a broken escape as written — each with a
// warning. (The existing parsers handed back an empty result for one bad
// character, so an attachment was hashed as empty data.)
func decodeTransfer(cte string, b []byte, part string, warn func(Warning)) []byte {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		return decodeBase64(b, part, warn)
	case "quoted-printable":
		return decodeQP(b, part, warn)
	case "", "7bit", "8bit", "binary":
		return append([]byte(nil), b...)
	default:
		warn(Warning{Code: WarnUnknownEncoding, Detail: "Content-Transfer-Encoding " + safeToken(cte) + " is not known; the data was kept as is", Part: part})
		return append([]byte(nil), b...)
	}
}

func isB64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

func decodeBase64(b []byte, part string, warn func(Warning)) []byte {
	clean := make([]byte, 0, len(b))
	skipped := 0
	padded := false
	for _, c := range b {
		switch {
		case isB64(c):
			if padded {
				skipped++ // data after the padding
				continue
			}
			clean = append(clean, c)
		case c == '=':
			padded = true
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
		default:
			skipped++
		}
	}
	tail := len(clean) % 4
	if tail == 1 {
		clean = clean[:len(clean)-1] // one leftover character carries no whole byte
		skipped++
	}
	out := make([]byte, base64.RawStdEncoding.DecodedLen(len(clean)))
	n, err := base64.RawStdEncoding.Decode(out, clean)
	if err != nil {
		// Cannot happen for an alphabet-only input of valid length; keep what decoded.
		skipped++
	}
	if skipped > 0 {
		warn(Warning{Code: WarnInvalidBase64, Detail: fmt.Sprintf("%d characters outside the Base64 alphabet or after the padding were skipped; the data may be damaged", skipped), Part: part})
	}
	return out[:n]
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

func decodeQP(b []byte, part string, warn func(Warning)) []byte {
	out := make([]byte, 0, len(b))
	broken := 0
	for len(b) > 0 {
		// One line at a time, so trailing whitespace can be dropped (RFC 2045 §6.7).
		i := 0
		for i < len(b) && b[i] != '\n' {
			i++
		}
		line := b[:i]
		nl := i < len(b)
		if i < len(b) {
			b = b[i+1:]
		} else {
			b = nil
		}
		line = trimRightBytes(line, " \t\r")
		soft := false
		for j := 0; j < len(line); j++ {
			c := line[j]
			if c != '=' {
				out = append(out, c)
				continue
			}
			if j == len(line)-1 {
				soft = true // "=" at the end of a line: a soft line break
				break
			}
			if j+2 < len(line) {
				h, ok1 := unhex(line[j+1])
				l, ok2 := unhex(line[j+2])
				if ok1 && ok2 {
					out = append(out, h<<4|l)
					j += 2
					continue
				}
			}
			broken++
			out = append(out, c) // keep the broken escape as written
		}
		if nl && !soft {
			out = append(out, '\r', '\n')
		}
	}
	if broken > 0 {
		warn(Warning{Code: WarnInvalidQP, Detail: fmt.Sprintf("%d broken quoted-printable escapes were kept as written", broken), Part: part})
	}
	return out
}

func trimRightBytes(b []byte, cut string) []byte {
	for len(b) > 0 && strings.IndexByte(cut, b[len(b)-1]) >= 0 {
		b = b[:len(b)-1]
	}
	return b
}
