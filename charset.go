package mailparse

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/transform"
)

// charsetAliases maps labels mailers use that the WHATWG index lacks.
var charsetAliases = map[string]string{
	"cp932":         "shift_jis",
	"x-sjis":        "shift_jis",
	"shift-jis":     "shift_jis",
	"ms_kanji":      "shift_jis",
	"x-euc-jp":      "euc-jp",
	"iso-2022-jp-1": "iso-2022-jp",
	"iso-2022-jp-2": "iso-2022-jp",
	"iso-2022-jp-3": "iso-2022-jp",
	"utf8":          "utf-8",
	"ascii":         "us-ascii",
}

func normalizeCharset(s string) string {
	n := strings.ToLower(strings.Trim(strings.TrimSpace(s), "\"'"))
	if a, ok := charsetAliases[n]; ok {
		return a
	}
	return n
}

// decodeStrict decodes b with enc and reports failure when the decoder had to
// replace anything — x/text decoders replace invalid input instead of failing.
func decodeStrict(enc encoding.Encoding, b []byte) (string, bool) {
	out, _, err := transform.Bytes(enc.NewDecoder(), b)
	if err != nil {
		return "", false
	}
	s := string(out)
	if strings.ContainsRune(s, utf8.RuneError) && !bytes.Contains(b, []byte("\xEF\xBF\xBD")) {
		return "", false
	}
	return s, true
}

func hasJISEscape(b []byte) bool {
	return bytes.Contains(b, []byte("\x1b$B")) || bytes.Contains(b, []byte("\x1b$@")) || bytes.Contains(b, []byte("\x1b(J"))
}

// guessJapanese reads undeclared non-UTF-8 bytes as ISO-2022-JP (by its escape
// sequences), then Shift_JIS, then EUC-JP, accepting the first that decodes
// without replacement.
func guessJapanese(b []byte) (string, string, bool) {
	if hasJISEscape(b) {
		if s, ok := decodeStrict(japanese.ISO2022JP, b); ok {
			return s, "iso-2022-jp", true
		}
	}
	if s, ok := decodeStrict(japanese.ShiftJIS, b); ok {
		return s, "shift_jis", true
	}
	if s, ok := decodeStrict(japanese.EUCJP, b); ok {
		return s, "euc-jp", true
	}
	return "", "", false
}

// textResult is a decoded text part.
type textResult struct {
	content, charset, source string
}

// toUTF8 converts a text part. The declared charset wins when it is known and
// fits the bytes; HTML without one (or with a wrong one) is read by its
// <meta charset>; otherwise undeclared non-ASCII is guessed. Every fallback is
// warned about.
func toUTF8(mediaType, declared string, data []byte, part string, warn func(Warning)) textResult {
	return decodeText(mediaType, declared, "mime", data, part, warn)
}

// decodeText is toUTF8 with the origin of the declared charset named: "mime"
// for a MIME charset parameter, "codepage" for a .msg or TNEF code page, "rtf"
// for an RTF \ansicpg or \fcharset.
func decodeText(mediaType, declared, source string, data []byte, part string, warn func(Warning)) textResult {
	ascii := isASCII(data)
	if d := normalizeCharset(declared); d != "" {
		switch d {
		case "us-ascii", "utf-8":
			if ascii || (d == "utf-8" && utf8.Valid(data)) {
				return textResult{string(data), d, source}
			}
			warn(Warning{Code: WarnCharsetMismatch, Detail: "the declared " + d + " does not fit the bytes; the charset was guessed", Part: part})
		default:
			if enc, err := htmlindex.Get(d); err == nil {
				if s, ok := decodeStrict(enc, data); ok {
					return textResult{s, d, source}
				}
				warn(Warning{Code: WarnCharsetMismatch, Detail: "the declared " + safeToken(d) + " does not fit the bytes; the charset was guessed", Part: part})
			} else {
				warn(Warning{Code: WarnUnknownCharset, Detail: "the declared charset " + safeToken(d) + " is not known; the charset was guessed", Part: part})
			}
		}
	} else if ascii && !hasJISEscape(data) {
		return textResult{string(data), "us-ascii", "default"}
	}
	// ISO-2022-JP is 7-bit: undeclared, it passes for ASCII and for UTF-8, so
	// its escape sequences are tried before either.
	if declared == "" && hasJISEscape(data) {
		if s, ok := decodeStrict(japanese.ISO2022JP, data); ok {
			warn(Warning{Code: WarnCharsetGuessed, Detail: "no charset was declared; the text was read as iso-2022-jp", Part: part})
			return textResult{s, "iso-2022-jp", "guessed"}
		}
	}
	if mediaType == "text/html" {
		if m := metaCharset(data); m != "" {
			if enc, err := htmlindex.Get(normalizeCharset(m)); err == nil {
				if s, ok := decodeStrict(enc, data); ok {
					return textResult{s, normalizeCharset(m), "meta"}
				}
			}
		}
	}
	if utf8.Valid(data) {
		if declared == "" {
			warn(Warning{Code: WarnCharsetGuessed, Detail: "no charset was declared; the text was read as utf-8", Part: part})
		}
		return textResult{string(data), "utf-8", "guessed"}
	}
	if s, cs, ok := guessJapanese(data); ok {
		if declared == "" {
			warn(Warning{Code: WarnCharsetGuessed, Detail: "no charset was declared; the text was read as " + cs, Part: part})
		}
		return textResult{s, cs, "guessed"}
	}
	warn(Warning{Code: WarnUndecodableText, Detail: fmt.Sprintf("%d bytes of text fit no candidate charset; invalid bytes were replaced", len(data)), Part: part})
	return textResult{strings.ToValidUTF8(string(data), "\uFFFD"), "unknown", "guessed"}
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

// metaCharset finds the charset an HTML document declares in <meta charset> or
// <meta http-equiv="Content-Type" content="...charset=...">, within the first
// 4 KiB (the HTML Standard's prescan looks at 1024 bytes; mailers put comments
// and styles first). The tokenizer is golang.org/x/net/html.
func metaCharset(data []byte) string {
	if len(data) > 4<<10 {
		data = data[:4<<10]
	}
	z := html.NewTokenizer(bytes.NewReader(data))
	for {
		switch z.Next() {
		case html.ErrorToken:
			return ""
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			if string(name) != "meta" || !hasAttr {
				continue
			}
			var charset, httpEquiv, content string
			for {
				k, v, more := z.TagAttr()
				switch strings.ToLower(string(k)) {
				case "charset":
					charset = string(v)
				case "http-equiv":
					httpEquiv = strings.ToLower(string(v))
				case "content":
					content = string(v)
				}
				if !more {
					break
				}
			}
			if charset != "" {
				return charset
			}
			if httpEquiv == "content-type" {
				if i := strings.Index(strings.ToLower(content), "charset="); i >= 0 {
					return strings.Trim(strings.TrimSpace(content[i+len("charset="):]), "\"';")
				}
			}
		}
	}
}
