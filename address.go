package mailparse

import (
	"net/mail"
	"strings"
)

// parseAddressList reads one occurrence of an address field. The address is
// parsed from the raw value first and the display name decoded afterwards — the
// order matters: decoding RFC 2047 first (as the existing parsers did) lets an
// encoded display name such as "Bank <security@bank.example>" become part of
// the address list. net/mail's AddressParser decodes the phrase only after it
// has tokenized it, which keeps an injected "<...>" inside the name.
func parseAddressList(field Field, part string, warn func(Warning)) AddressList {
	raw := unfold([]byte(field.Raw))
	al := AddressList{Raw: raw, Mailboxes: []Mailbox{}}
	if raw == "" {
		al.Parsed = true
		return al
	}
	p := mail.AddressParser{WordDecoder: wordDecoder}
	if list, err := p.ParseList(raw); err == nil {
		al.Parsed = true
		for _, a := range list {
			name := a.Name
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
			al.Mailboxes = append(al.Mailboxes, mb)
		}
	}
	return al
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
	if lt := strings.LastIndexByte(item, '<'); lt >= 0 && strings.IndexByte(item[lt:], '>') < 0 {
		// An unclosed '<': the address is what follows it, the name what
		// precedes the first one.
		addr := strings.TrimSpace(item[lt+1:])
		if strings.Contains(addr, "@") {
			name := strings.Trim(strings.TrimSpace(item[:strings.IndexByte(item, '<')]), "\"")
			return Mailbox{Name: name, Address: addr}, true
		}
	}
	if lt := strings.LastIndexByte(item, '<'); lt >= 0 {
		if gt := strings.IndexByte(item[lt:], '>'); gt > 0 {
			addr := strings.TrimSpace(item[lt+1 : lt+gt])
			name := strings.Trim(strings.TrimSpace(item[:lt]), "\"")
			if strings.Contains(name, "=?") {
				name = decodeWords(name, "a display name in "+safeToken(fieldName), part, warn)
			}
			return Mailbox{Name: name, Address: addr}, addr != "" || name != ""
		}
	}
	for _, tok := range strings.Fields(item) {
		if strings.Contains(tok, "@") {
			return Mailbox{Address: strings.Trim(tok, "<>\"(),;")}, true
		}
	}
	// Neither form: keep the text as an address-less name (Exchange /O= forms
	// and the like stay visible instead of vanishing).
	return Mailbox{Name: item}, true
}
