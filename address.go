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
	for _, item := range splitAddresses(raw) {
		if mb, ok := lenientMailbox(item, field.Name, part, warn); ok {
			mb.Name = text8(mb.Name)
			al.Mailboxes = append(al.Mailboxes, mb)
		}
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

// splitAddresses splits on commas outside quotes, angle brackets and comments.
func splitAddresses(s string) []string {
	var out []string
	depthAngle, depthParen := 0, 0
	inQuote, escaped := false, false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case c == '"':
			inQuote = !inQuote
		case inQuote:
		case c == '<':
			if depthAngle == 0 {
				depthAngle++ // addresses do not nest; a second '<' is just text
			}
		case c == '>':
			if depthAngle > 0 {
				depthAngle--
			}
		case c == '(':
			depthParen++
		case c == ')':
			if depthParen > 0 {
				depthParen--
			}
		case (c == ',' || c == ';') && depthAngle > 0 && strings.IndexByte(s[i:], '>') < 0:
			// An angle bracket that never closes must not swallow the rest of the list.
			depthAngle = 0
			out = append(out, s[start:i])
			start = i + 1
		case (c == ',' || c == ';') && depthAngle == 0 && depthParen == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// lenientMailbox takes the last <...> as the address and what precedes it as
// the name; without brackets, the token holding an "@".
func lenientMailbox(item, fieldName, part string, warn func(Warning)) (Mailbox, bool) {
	item = strings.TrimSpace(item)
	if item == "" {
		return Mailbox{}, false
	}
	// Structure ('<', '>', '@') is searched outside quoted strings: a quoted
	// display name is attacker text, and "CEO <ceo@corp.example>" in quotes is
	// a name, never an address.
	mask := outsideQuotes(item)
	if lt := strings.LastIndexByte(mask, '<'); lt >= 0 && strings.IndexByte(mask[lt:], '>') < 0 {
		// An unclosed '<': the address is what follows it, the name what
		// precedes the first one.
		addr := strings.TrimSpace(item[lt+1:])
		if strings.Contains(outsideQuotes(addr), "@") {
			name := displayName(item[:strings.IndexByte(mask, '<')], fieldName, part, warn)
			return Mailbox{Name: name, Address: addr}, true
		}
	}
	if lt := strings.LastIndexByte(mask, '<'); lt >= 0 {
		if gt := strings.IndexByte(mask[lt:], '>'); gt > 0 {
			addr := strings.TrimSpace(item[lt+1 : lt+gt])
			name := displayName(item[:lt], fieldName, part, warn)
			return Mailbox{Name: name, Address: addr}, addr != "" || name != ""
		}
	}
	fields := strings.Fields(mask)
	pos := 0
	for _, f := range fields {
		at := strings.Index(mask[pos:], f) + pos
		pos = at + len(f)
		if strings.Contains(f, "@") {
			return Mailbox{Address: strings.Trim(item[at:pos], "<>\"(),;")}, true
		}
	}
	// Neither form: keep the text as an address-less name (Exchange /O= forms
	// and the like stay visible instead of vanishing).
	return Mailbox{Name: displayName(item, fieldName, part, warn)}, true
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

// outsideQuotes returns s, byte for byte, with every byte inside a
// quoted-string or a comment (delimiters included) replaced by '_', so its
// structure can be searched without matching display text. A quote or
// parenthesis that never closes is literal: the bytes after it are not masked.
func outsideQuotes(s string) string {
	b := []byte(s)
	quoted, escaped := false, false
	depth, start := 0, -1
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case escaped:
			escaped = false
		case (quoted || depth > 0) && c == '\\':
			escaped = true
		case !quoted && c == '(':
			if depth == 0 {
				start = i
			}
			depth++
		case !quoted && depth > 0 && c == ')':
			depth--
			if depth == 0 {
				for k := start; k <= i; k++ {
					b[k] = '_'
				}
			}
			continue
		case depth == 0 && c == '"':
			if !quoted {
				start = i
				quoted = true
				continue
			}
			quoted = false
			for k := start; k <= i; k++ {
				b[k] = '_'
			}
			continue
		}
	}
	if quoted || depth > 0 {
		// Unclosed: treat the opening delimiter as text and mask what follows
		// it on its own terms.
		return string(b[:start+1]) + outsideQuotes(string(b[start+1:]))
	}
	return string(b)
}
