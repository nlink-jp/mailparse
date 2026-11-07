package mailparse

import (
	"net/mail"
	"strings"
	"unicode/utf8"
)

// parseAddressList reads one occurrence of an address field. The address is
// parsed from the raw value first and the display name decoded afterwards — the
// order matters: decoding RFC 2047 first (as the existing parsers did) lets an
// encoded display name such as "Bank <security@bank.example>" become part of
// the address list. net/mail's AddressParser decodes the phrase only after it
// has tokenized it, which keeps an injected "<...>" inside the name.
func parseAddressList(field Field, part string, warn func(Warning)) AddressList {
	raw := unfold([]byte(field.Raw))
	// Raw 8-bit bytes (not RFC 2047) are tokenized as bytes and only the
	// display names are converted afterwards: converting first would let a
	// Shift_JIS trail byte 0x5C swallow a quoted-string escape and change
	// where the addresses are.
	al := AddressList{Raw: text8(raw), Mailboxes: []Mailbox{}}
	if raw == "" {
		al.Parsed = true
		return al
	}
	p := mail.AddressParser{WordDecoder: wordDecoder}
	if list, err := p.ParseList(raw); err == nil {
		al.Parsed = true
		for _, a := range list {
			name := text8(a.Name)
			if strings.Contains(name, "=?") {
				name = decodeWords(name, "a display name in "+safeToken(field.Name), part, warn)
			}
			al.Mailboxes = append(al.Mailboxes, Mailbox{Name: name, Address: a.Address})
		}
		return al
	}
	warn(Warning{Code: WarnInvalidAddress, Detail: safeToken(field.Name) + " did not parse as RFC 5322; a lenient reading was used", Part: part})
	for _, mb := range readLenient(raw, field.Name, part, warn) {
		mb.Name = text8(mb.Name)
		// Not text8: a Japanese guess can take the '@' into a character
		// (Shift_JIS 0x81 0x40 is U+3000); only invalid bytes are replaced.
		mb.Address = strings.ToValidUTF8(mb.Address, "\uFFFD")
		al.Mailboxes = append(al.Mailboxes, mb)
	}
	return al
}

// text8 turns raw 8-bit bytes into text (a Japanese guess, else replacement);
// decodeHeaderValue has already warned about them for the field.
func text8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	if t, _, ok := guessJapanese([]byte(s)); ok {
		return t
	}
	return strings.ToValidUTF8(s, "\uFFFD")
}

// displayName reads a display name: quoted-strings are unquoted (quoted-pairs
// undone) and joined with the words around them, as net/mail does; RFC 2047
// words outside quotes are decoded.
func displayName(s, fieldName, part string, warn func(Warning)) string {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, `"`) {
		if strings.Contains(s, "=?") {
			return decodeWords(s, "a display name in "+safeToken(fieldName), part, warn)
		}
		return s
	}
	var words []string
	for rest := s; rest != ""; rest = strings.TrimSpace(rest) {
		if rest[0] == '"' {
			end := closingQuote(rest)
			if end < 0 { // unclosed: the quote is literal text
				words = append(words, rest)
				break
			}
			words = append(words, unquoteParam(rest[:end+1]))
			rest = rest[end+1:]
			continue
		}
		q := strings.IndexByte(rest, '"')
		if q < 0 {
			q = len(rest)
		}
		words = append(words, strings.TrimSpace(rest[:q]))
		rest = rest[q:]
	}
	return strings.Join(words, " ")
}

// closingQuote returns the index of the quote closing the quoted-string that
// starts s, or -1.
func closingQuote(s string) int {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return -1
}
