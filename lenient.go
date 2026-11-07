package mailparse

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// The lenient reader: what an address field yields when net/mail refuses it.
//
// The field is cut into RFC 5322 lexical tokens once (lexAddress), and a small
// grammar over the tokens finds the mailboxes (readLenient). Nothing is found
// by searching or slicing the raw string, and the output is held to one
// contract:
//
//   - An Address is the text of a run of tokens that is an addr-spec as
//     written: a local part of words and dots with at least one word (the
//     obsolete forms Japanese carriers issued, "taro.@docomo.ne.jp",
//     included) or one quoted-string, then "@", then a domain of words joined
//     by single dots, or an IP literal. Words are atext; nothing holds a
//     control or format character; whitespace stands only inside a quoted
//     local part (and, within <...>, beside a dot or the "@", where it is left
//     out). A comment may stand only beside a dot, the "@" or the edge —
//     between two words the run is no address — and its text is never part
//     of the Address. Every label of the Address is therefore a whole word of
//     the field: nothing is made up, cut or glued.
//   - <...> holding one addr-spec gives it. One that is an Exchange DN —
//     words, dots, spaces and comments, no "@", control or format character —
//     is kept exactly as written. Any other gives the addr-specs among it,
//     read as bare addresses, or no address.
//   - A Name is the display text before a <...> (decoded by displayName),
//     given to the first address the <...> yields; a bare address has none,
//     and a bare address before a <...> is part of its display text. An item with no address and no <...> is kept as
//     an address-less name.
//   - Every token that fits none of these stays in AddressList.Raw only; the
//     field already carries an invalid_address warning.
//
// An earlier version found structure by searching a masked copy of the string
// and cut addresses out by byte position, trimming and dropping comments to
// fit. Each repair of that kind let some other text through (a comment's
// domain, a quoted name, two words glued), which is why the shape is now a
// grammar and the contract a property test (lenient_test.go).

type tokKind byte

const (
	tSpace   tokKind = iota // a run of whitespace
	tWord                   // a run of bytes that are no special, no space
	tQuoted                 // a closed quoted-string, quotes included
	tComment                // a closed comment, nesting included
	tLiteral                // a closed domain literal [...]
	tSpecial                // one of < > @ , ; : .
	tStray                  // one byte that opens nothing or closes nothing: ( ) " [ ] \
)

type token struct {
	kind       tokKind
	start, end int // raw[start:end]
}

func (t token) is(c byte, raw string) bool {
	return t.kind == tSpecial && raw[t.start] == c
}

func isSpaceByte(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// spaceAt returns the width of the whitespace character at raw[i], or 0.
// Besides ASCII whitespace, only the ideographic space (U+3000, which Japanese
// senders type between addresses) and NBSP separate words; the other Unicode
// spaces are rare in addresses, U+2028/U+2029/U+0085 are control characters
// here, and a wider set lets a raw Shift_JIS run that happens to spell one
// cut a word.
func spaceAt(raw string, i int) int {
	if isSpaceByte(raw[i]) {
		return 1
	}
	if raw[i] < utf8.RuneSelf {
		return 0
	}
	if r, w := utf8.DecodeRuneInString(raw[i:]); r == '\u3000' || r == '\u00a0' {
		return w
	}
	return 0
}

func isSpecialByte(c byte) bool { return strings.IndexByte("<>@,;:.", c) >= 0 }

// lexAddress cuts raw into tokens in linear time. Where a quoted-string,
// comment or literal closes is computed beforehand, so a delimiter that never
// closes is one stray byte and costs no rescan.
func lexAddress(raw string) []token {
	n := len(raw)
	// live[i]: raw[i] follows an even run of backslashes, so inside a
	// quoted-string or comment it is not escaped (the run cannot reach past
	// the opening delimiter, which is no backslash).
	live := make([]bool, n)
	run := 0
	for i := 0; i < n; i++ {
		live[i] = run%2 == 0
		if raw[i] == '\\' {
			run++
		} else {
			run = 0
		}
	}
	// nextQuote[i]: the first live '"' at or after i. closeAfter[i]: reading a
	// comment's inside from i, where it closes — the first live ')' that the
	// live parentheses from i on leave unmatched. nextClose/nextOpen: the next
	// ']' and '[' at or after i. -1 for none.
	nextQuote := make([]int32, n+1)
	closeAfter := make([]int32, n+2)
	nextClose := make([]int32, n+1)
	nextOpen := make([]int32, n+1)
	nextQuote[n], closeAfter[n], closeAfter[n+1], nextClose[n], nextOpen[n] = -1, -1, -1, -1, -1
	for i := n - 1; i >= 0; i-- {
		nextQuote[i], nextClose[i], nextOpen[i] = nextQuote[i+1], nextClose[i+1], nextOpen[i+1]
		switch raw[i] {
		case '"':
			if live[i] {
				nextQuote[i] = int32(i)
			}
		case ']':
			nextClose[i] = int32(i)
		case '[':
			nextOpen[i] = int32(i)
		}
		switch {
		case raw[i] == ')' && live[i]:
			closeAfter[i] = int32(i)
		case raw[i] == '(' && live[i]:
			if c := closeAfter[i+1]; c >= 0 {
				closeAfter[i] = closeAfter[c+1]
			} else {
				closeAfter[i] = -1
			}
		default:
			closeAfter[i] = closeAfter[i+1]
		}
	}
	var toks []token
	for i := 0; i < n; {
		c := raw[i]
		end := -1
		var kind tokKind
		switch {
		case spaceAt(raw, i) > 0:
			j := i
			for j < n {
				w := spaceAt(raw, j)
				if w == 0 {
					break
				}
				j += w
			}
			toks = append(toks, token{tSpace, i, j})
			i = j
			continue
		case c == '"':
			end, kind = int(nextQuote[i+1]), tQuoted
		case c == '(':
			end, kind = int(closeAfter[i+1]), tComment
		case c == '[':
			// A domain literal stands only after "@" (comments between are
			// allowed) and holds no '[' (dtext excludes it); a '[' anywhere
			// else is a stray byte, so it hides nothing.
			if afterAt(toks, raw) {
				if cl := nextClose[i+1]; cl >= 0 && (nextOpen[i+1] < 0 || nextOpen[i+1] > cl) {
					end, kind = int(cl), tLiteral
				}
			}
		case isSpecialByte(c):
			toks = append(toks, token{tSpecial, i, i + 1})
			i++
			continue
		case c == ')' || c == ']' || c == '\\':
			toks = append(toks, token{tStray, i, i + 1})
			i++
			continue
		default:
			j := i
			for j < n && spaceAt(raw, j) == 0 && !isSpecialByte(raw[j]) && strings.IndexByte(`()"[]\`, raw[j]) < 0 {
				j++
			}
			toks = append(toks, token{tWord, i, j})
			i = j
			continue
		}
		if end < 0 { // never closes: the delimiter is one stray byte
			toks = append(toks, token{tStray, i, i + 1})
			i++
			continue
		}
		toks = append(toks, token{kind, i, end + 1})
		i = end + 1
	}
	return toks
}

// afterAt says whether the last token that is no comment is "@".
func afterAt(toks []token, raw string) bool {
	for i := len(toks) - 1; i >= 0; i-- {
		if toks[i].kind != tComment {
			return toks[i].is('@', raw)
		}
	}
	return false
}

// readLenient reads a field net/mail refused, by the contract above.
func readLenient(raw, fieldName, part string, warn func(Warning)) []Mailbox {
	toks := lexAddress(raw)
	r := lenientReader{raw: raw, fieldName: fieldName, part: part, warn: warn}
	// closes[i] for a '<' token: the index of its '>' — the next '<' or '>'
	// token after it is a '>' — or -1. Commas inside a closed <...> do not
	// split the list; inside one that never closes they do.
	closes := make([]int, len(toks))
	next := -1
	for i := len(toks) - 1; i >= 0; i-- {
		closes[i] = -1
		switch {
		case toks[i].is('<', raw):
			if next >= 0 && toks[next].is('>', raw) {
				closes[i] = next
			}
			next = i
		case toks[i].is('>', raw):
			next = i
		}
	}
	start := 0
	for i := 0; i < len(toks); i++ {
		switch {
		case toks[i].is('<', raw) && closes[i] >= 0:
			i = closes[i]
		case toks[i].is(',', raw) || toks[i].is(';', raw):
			r.item(toks[start:i], closes[start:i], start)
			start = i + 1
		}
	}
	r.item(toks[start:], closes[start:], start)
	return r.out
}

type lenientReader struct {
	raw, fieldName, part string
	warn                 func(Warning)
	out                  []Mailbox
}

// item reads one comma-separated item. closes holds the '<' matches as
// indexes into the whole token list; base is the item's first index there.
func (r *lenientReader) item(toks []token, closes []int, base int) {
	before := len(r.out)
	angle := false
	nameFrom := 0     // first token of the display text the next <...> takes
	pendingName := "" // a name an unclosed '<' left for the address after it
	havePending := false
	emit := func(name, addr string) {
		if name != "" || addr != "" {
			r.out = append(r.out, Mailbox{Name: name, Address: addr})
		}
	}
	// emitAll gives the name to the first address; with none, the name alone.
	emitAll := func(name string, addrs []string) {
		if len(addrs) == 0 {
			emit(name, "")
			return
		}
		emit(name, addrs[0])
		for _, a := range addrs[1:] {
			emit("", a)
		}
	}
	for i := 0; i < len(toks); i++ {
		switch {
		case toks[i].is('<', r.raw):
			angle = true
			name := r.name(toks[nameFrom:i])
			if havePending {
				name, havePending = pendingName, false
			}
			if c := closes[i]; c >= 0 {
				emitAll(name, r.angleAddresses(toks[i+1:c-base]))
				i = c - base
				nameFrom = i + 1
				continue
			}
			// Unclosed '<'. If another '<' follows, what lies between is read
			// for bare addresses, the first of which takes the name;
			// otherwise the rest of the item is this <...>'s address.
			k := i + 1
			for k < len(toks) && !toks[k].is('<', r.raw) {
				k++
			}
			if k == len(toks) {
				emitAll(name, r.angleAddresses(toks[i+1:]))
				i = len(toks)
				nameFrom = i
				continue
			}
			if addrs := r.bare(toks[i+1 : k]); len(addrs) > 0 {
				emitAll(name, addrs)
			} else {
				pendingName, havePending = name, true
			}
			i = k - 1
			nameFrom = k
		case toks[i].is('>', r.raw):
			// A '>' with nothing to close: the text before it holds no name.
			for _, a := range r.bare(toks[nameFrom:i]) {
				emit("", a)
			}
			nameFrom = i + 1
		}
	}
	for _, a := range r.bare(toks[nameFrom:]) {
		emit("", a)
	}
	if len(r.out) == before && !angle && len(toks) > 0 {
		// Neither form: the text as an address-less name (an Exchange DN and
		// the like stay visible instead of vanishing).
		emit(r.name(toks), "")
	}
}

// name decodes the display text the tokens span.
func (r *lenientReader) name(toks []token) string {
	if len(toks) == 0 {
		return ""
	}
	return displayName(r.raw[toks[0].start:toks[len(toks)-1].end], r.fieldName, r.part, r.warn)
}

// angleAddresses reads what <...> holds: one addr-spec (comments and the
// whitespace RFC 5322 allows around it, a dot or the "@" may stand there); an
// Exchange DN — words, dots, spaces and comments, no "@", control or format
// character anywhere — kept exactly as written; or else the addr-specs among
// it, read as bare addresses ("<a@x.example b@y.example>" gives both).
func (r *lenientReader) angleAddresses(toks []token) []string {
	toks = trimSpaceToks(toks)
	if len(toks) == 0 {
		return nil
	}
	if a, ok := addrSpecTokens(trimCFWS(toks), r.raw, true); ok {
		return []string{a}
	}
	// A DN keeps even the comments at its ends, as written.
	if dn, ok := r.exchangeDN(toks); ok {
		return []string{dn}
	}
	return r.bare(toks)
}

// exchangeDN returns the text the tokens span when it can be an Exchange DN
// ("/O=EXCHANGE/OU=... (FYDIBOHF23SPDLT)/CN=..."), parentheses included.
func (r *lenientReader) exchangeDN(toks []token) (string, bool) {
	for _, t := range toks {
		if t.kind != tWord && t.kind != tSpace && t.kind != tComment && !t.is('.', r.raw) {
			return "", false
		}
	}
	dn := r.raw[toks[0].start:toks[len(toks)-1].end]
	if strings.ContainsRune(dn, '@') || hasControl(dn) {
		return "", false
	}
	return dn, true
}

// bare returns the addresses among tokens outside <...>: every run between
// whitespace and the specials that end one (, ; : < >) that is an addr-spec.
func (r *lenientReader) bare(toks []token) []string {
	var out []string
	start := 0
	flush := func(end int) {
		if a, ok := addrSpecTokens(toks[start:end], r.raw, false); ok {
			out = append(out, a)
		}
	}
	for i, t := range toks {
		if t.kind == tSpace || t.is(':', r.raw) || t.is('<', r.raw) || t.is('>', r.raw) || t.is(',', r.raw) || t.is(';', r.raw) {
			flush(i)
			start = i + 1
		}
	}
	flush(len(toks))
	return out
}

// trimSpaceToks drops whitespace at both ends.
func trimSpaceToks(toks []token) []token {
	for len(toks) > 0 && toks[0].kind == tSpace {
		toks = toks[1:]
	}
	for n := len(toks); n > 0 && toks[n-1].kind == tSpace; n = len(toks) {
		toks = toks[:n-1]
	}
	return toks
}

// trimCFWS drops whitespace and comments at both ends.
func trimCFWS(toks []token) []token {
	for len(toks) > 0 && (toks[0].kind == tSpace || toks[0].kind == tComment) {
		toks = toks[1:]
	}
	for n := len(toks); n > 0 && (toks[n-1].kind == tSpace || toks[n-1].kind == tComment); n = len(toks) {
		toks = toks[:n-1]
	}
	return toks
}

// addrSpecTokens reports whether the tokens are exactly an addr-spec by the
// contract at the top of this file, and returns its text (comments left out).
//
// Inside <...> (angle), whitespace beside a dot or the "@" is allowed too
// ("ceo @ corp.example", the obsolete CFWS RFC 5322 still reads); outside, it
// separates addresses.
func addrSpecTokens(toks []token, raw string, angle bool) (string, bool) {
	// Comments may stand only beside a dot, the "@" or the edge.
	var core []token
	for i, t := range toks {
		if t.kind == tSpace && angle && (i > 0 && dotOrAt(toks[i-1], raw) || i+1 < len(toks) && dotOrAt(toks[i+1], raw)) {
			continue
		}
		if t.kind != tComment {
			core = append(core, t)
			continue
		}
		prevWord := i > 0 && wordLike(toks[i-1])
		nextWord := i+1 < len(toks) && wordLike(toks[i+1])
		if prevWord && nextWord {
			return "", false
		}
	}
	at := -1
	for i, t := range core {
		switch {
		case t.is('@', raw):
			if at >= 0 {
				return "", false
			}
			at = i
		case t.kind == tSpace, t.kind == tStray, t.kind == tSpecial && !t.is('.', raw):
			return "", false
		}
	}
	if at <= 0 || at == len(core)-1 {
		return "", false
	}
	if !localPart(core[:at], raw) || !domainPart(core[at+1:], raw) {
		return "", false
	}
	var b strings.Builder
	for _, t := range core {
		b.WriteString(raw[t.start:t.end])
	}
	return b.String(), true
}

func dotOrAt(t token, raw string) bool { return t.is('.', raw) || t.is('@', raw) }

// wordLike is a token a comment between two of would glue.
func wordLike(t token) bool {
	return t.kind == tWord || t.kind == tQuoted || t.kind == tLiteral || t.kind == tComment
}

// localPart: one quoted-string, or words and dots with at least one word and
// no two words side by side.
func localPart(toks []token, raw string) bool {
	if len(toks) == 1 && toks[0].kind == tQuoted {
		return !hasControl(raw[toks[0].start:toks[0].end])
	}
	words := 0
	prevWord := false
	for _, t := range toks {
		switch {
		case t.is('.', raw):
			prevWord = false
		case t.kind == tWord && atextWord(raw[t.start:t.end]):
			if prevWord {
				return false
			}
			prevWord = true
			words++
		default:
			return false
		}
	}
	return words > 0
}

// domainPart: words joined by single dots, or one IP literal.
func domainPart(toks []token, raw string) bool {
	if len(toks) == 1 && toks[0].kind == tLiteral {
		_, ok := addrSpec("x@" + raw[toks[0].start:toks[0].end])
		return ok
	}
	for i, t := range toks {
		if i%2 == 1 {
			if !t.is('.', raw) {
				return false
			}
			continue
		}
		if t.kind != tWord || !atextWord(raw[t.start:t.end]) {
			return false
		}
	}
	return len(toks)%2 == 1
}

// atextWord: every rune is atext (8-bit bytes read as runes, invalid ones as
// U+FFFD, which is atext), none a control character.
func atextWord(s string) bool {
	for _, r := range s {
		if !isAtext(r) || isControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return s != ""
}

// hasControl reports control characters and format characters (bidi
// overrides, zero-width joiners), which would reach a terminal or a display.
func hasControl(s string) bool {
	for _, r := range s {
		if isControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}
