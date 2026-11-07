package mailparse

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// Every address in a malformed item becomes a mailbox: one address must not
// vanish because a comma is missing (a From an attacker shapes to hide one).
func TestLenientKeepsEveryAddress(t *testing.T) {
	for _, c := range []struct{ raw, want string }{
		{`ceo@example.com attacker@evil.example`, "|ceo@example.com;|attacker@evil.example"},
		{`CEO <ceo@example.com> attacker@evil.example`, "CEO|ceo@example.com;|attacker@evil.example"},
		{`A <a@example.com> B <b@evil.example>`, "A|a@example.com;B|b@evil.example"},
		{`>a@x.example b@y.example`, "|a@x.example;|b@y.example"},
		// Unchanged readings: the text before <...> is the name, a quoted or
		// commented address is display text, an unclosed '<' takes the rest.
		{`ceo@example.com <attacker@evil.example>`, "ceo@example.com|attacker@evil.example"},
		{`x@a.example <<b@example.net`, "x@a.example|b@example.net"},
		{`broken <<a@example.net`, "broken|a@example.net"},
		{`"CEO <ceo@corp.example>"`, "CEO <ceo@corp.example>|"},
		{`Real Name (ceo@corp.example) real@x.example`, "|real@x.example"},
		{`/O=EXCHANGE/OU=FIRST/CN=USER`, "/O=EXCHANGE/OU=FIRST/CN=USER|"},
		// Findings of the review of this change.
		{`CEO <ceo@example.com <attacker@evil.example`, "CEO|ceo@example.com;|attacker@evil.example"},
		{`CEO <attacker@evil.example <ceo@example.com`, "CEO|attacker@evil.example;|ceo@example.com"},
		{`<a@x.example <b@y.example>`, "|a@x.example;|b@y.example"},
		{`A <a@x.example> B <b@y.example`, "A|a@x.example;B|b@y.example"},
		{`a@x.example>b@y.example>c@z.example`, "|a@x.example;|b@y.example;|c@z.example"},
		{`ceo@corp.example(@evil.example) b@y.example`, "|ceo@corp.example;|b@y.example"},
		{`A <ceo@corp.example(x)@evil.example> b@y.example`, "A|;|b@y.example"}, // two "@": no address
		{`(c)a@x.example b@y.example`, "|a@x.example;|b@y.example"},
		{`"x"@evil.example b@y.example`, `|"x"@evil.example;|b@y.example`},
		{`@ @ @`, "@ @ @|"},
		{`<> b@y.example`, "|b@y.example"},
		// Second review round.
		{strings.Repeat("(", 16) + ` "Bank <security@bank.example>" <attacker@evil.example>`, strings.Repeat("(", 16) + " Bank <security@bank.example>|attacker@evil.example"},
		{strings.Repeat("(", 16) + ` attacker@evil.example (security@bank.example)`, "|attacker@evil.example"},
		{`ceo@corp.example((x)"@evil.example) b@y.example`, "|ceo@corp.example;|b@y.example"},
		{`A <ceo@corp.example((x)"@evil.example)> b@y.example`, "A|ceo@corp.example;|b@y.example"},
		{`ceo"(x)"@corp.example b@y.example`, "|b@y.example"}, // local part neither dot-atom nor one quoted-string
		{`a@@ @b.example`, "a@@ @b.example|"},
		// Third review round: an underscore of the input is no comment.
		{`john_doe@example.com b@y.example`, "|john_doe@example.com;|b@y.example"},
		{`A <john_doe@example.com> b@y.example`, "A|john_doe@example.com;|b@y.example"},
		{`a@my_host.example b@y.example`, "|a@my_host.example;|b@y.example"},
		{`ad_min@corp.example(c) b@y.example`, "|ad_min@corp.example;|b@y.example"},
		{`A <@> b@y.example`, "A|;|b@y.example"},
		{`A <a@> b@y.example`, "A|;|b@y.example"},
		// Fourth and fifth review rounds: a comment between two characters is
		// a space, so no domain is made up and the token is no address;
		// beside a dot or an "@" it is dropped. A comment's "@" never counts.
		{`ceo@co(x)rp.example b@y.example`, "|b@y.example"},
		{`A <ceo@co(x)rp.example> b@y.example`, "A|;|b@y.example"},
		{`A <c(x)eo@corp.example> b@y.example`, "A|;|b@y.example"},
		{`ceo@corp.example(x@evil.example)) b@y.example`, "|b@y.example"},
		{`ceo@corp.example(x@evil.example)( b@y.example`, "|b@y.example"},
		{`@a(x@evil.example)) b@y.example`, "|b@y.example"},
		{`@co(x@y.example)rp b@z.example`, "|b@z.example"},
		{`ceo(x)@corp.example b@y.example`, "|ceo@corp.example;|b@y.example"},
		{`"a b"@x.example c@y.example`, `|"a b"@x.example;|c@y.example`},
		{`a,""`, "a|"}, // '""' alone gives no mailbox
		// Sixth review round.
		{`A <"ceo@corp.example"> b@y.example`, "A|;|b@y.example"},
		{`A <"ceo@corp.example" junk>`, "A|"},
		{`Taro <taro.@docomo.ne.jp>`, "Taro|taro.@docomo.ne.jp"},
		{`taro..hanako@docomo.ne.jp .taro@ezweb.ne.jp`, "|taro..hanako@docomo.ne.jp;|.taro@ezweb.ne.jp"},
		{`taro.@docomo.ne.jp b@y.example`, "|taro.@docomo.ne.jp;|b@y.example"},
		{`... @docomo.ne.jp b@y.example`, "|b@y.example"},
		{"ceo\u009b@corp.example b@y.example", "|b@y.example"},
		{"\"a\x1b[31m\"@corp.example b@y.example", "|b@y.example"},
		{`A </O=EXCHANGE/CN=USER>`, "A|/O=EXCHANGE/CN=USER"},
		// Review of the rewrite: a <...> holding two addresses gives both; a
		// real Exchange DN keeps its parentheses; an ideographic space
		// separates; a comment gluing two addresses leaves none; control and
		// format characters never reach an Address; CFWS inside <...>.
		{`CEO <ceo@corp.example attacker@evil.example>`, "CEO|ceo@corp.example;|attacker@evil.example"},
		{`CEO <ceo@corp.example, attacker@evil.example>`, "CEO|ceo@corp.example;|attacker@evil.example"},
		{`CEO <ceo@corp.example attacker@evil.example`, "CEO|ceo@corp.example;|attacker@evil.example"},
		{`User </O=EXCHANGE/OU=EXCHANGE ADMINISTRATIVE GROUP (FYDIBOHF23SPDLT)/CN=RECIPIENTS/CN=USER>`, "User|/O=EXCHANGE/OU=EXCHANGE ADMINISTRATIVE GROUP (FYDIBOHF23SPDLT)/CN=RECIPIENTS/CN=USER"},
		{"taro@example.jp\u3000hanako@example.jp", "|taro@example.jp;|hanako@example.jp"},
		{"taro@example.jp\u00a0hanako@example.jp", "|taro@example.jp;|hanako@example.jp"},
		{"ceo@corp\u200a.example b@y.example", "|b@y.example"},            // a hair space is no separator
		{"\x93\xfa\xe2\x80\xa8abc@x.example b@y.example", "|b@y.example"}, // Shift_JIS spelling U+2028 cuts nothing
		{`Org </O=Org/OU=Exchange Administrative Group (FYDIBOHF23SPDLT)>`, "Org|/O=Org/OU=Exchange Administrative Group (FYDIBOHF23SPDLT)"},
		{`ceo@corp.example(x)attacker@evil.example`, "ceo@corp.example(x)attacker@evil.example|"},
		{"A <x\x1bcy> b@y.example", "A|;|b@y.example"},
		{"A <\u202eelpmaxe.lroc> b@y.example", "A|;|b@y.example"},
		{"\"a\u202eb\"@x.example c@y.example", "|c@y.example"},
		{`A <ceo@corp.example (x)>, x"`, `A|ceo@corp.example;x "|`},
		{`A <ceo @ corp.example>, x"`, `A|ceo@corp.example;x "|`},
		{`ceo@corp(x).example b@y.example`, "|ceo@corp.example;|b@y.example"},
		{`N <a@x.example <@`, "N|a@x.example"},
	} {
		var ws []Warning
		al := parseAddressList(Field{Name: "From", Raw: c.raw}, "", func(w Warning) { ws = append(ws, w) })
		var got []string
		for _, mb := range al.Mailboxes {
			got = append(got, mb.Name+"|"+mb.Address)
		}
		if strings.Join(got, ";") != c.want {
			t.Errorf("%s:\n got  %q\n want %q", c.raw, strings.Join(got, ";"), c.want)
		}
		if al.Parsed || len(ws) != 1 || ws[0].Code != WarnInvalidAddress {
			t.Errorf("%s: parsed=%v warnings=%+v", c.raw, al.Parsed, ws)
		}
	}
}

// Through the whole parse: both addresses of the malformed From are in
// Message.From, with the invalid_address warning.
func TestMalformedFromKeepsBothAddresses(t *testing.T) {
	m, err := ParseBytes([]byte("From: ceo@example.com attacker@evil.example\r\nTo: a@example.com\r\nSubject: s\r\nMessage-ID: <1@example.com>\r\n\r\nbody\r\n"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.From) != 1 || len(m.From[0].Mailboxes) != 2 || m.From[0].Mailboxes[1].Address != "attacker@evil.example" || codes(m.Warnings)[WarnInvalidAddress] != 1 {
		t.Fatalf("From %+v warnings %v", m.From, m.Warnings)
	}
}

// An empty "<>" alone gives no mailbox, as before the change.
func TestLenientEmptyAngle(t *testing.T) {
	al := parseAddressList(Field{Name: "To", Raw: `<> ,`}, "", func(Warning) {})
	if len(al.Mailboxes) != 0 {
		t.Fatalf("%+v", al.Mailboxes)
	}
}

// A Latin-1 byte between two addresses leaves no invalid UTF-8 in Address.
func TestLenientAddressIsValidUTF8(t *testing.T) {
	al := parseAddressList(Field{Name: "From", Raw: "a\xa0b@x.example c@z.example"}, "", func(Warning) {})
	for _, mb := range al.Mailboxes {
		if !utf8.ValidString(mb.Address) {
			t.Fatalf("%q", mb.Address)
		}
	}
	if len(al.Mailboxes) != 2 || al.Mailboxes[0].Address != "a\uFFFDb@x.example" {
		t.Fatalf("%+v", al.Mailboxes)
	}
}

// A Japanese guess must not take the '@' of an address: Shift_JIS 0x81 0x40
// is U+3000, which would swallow it.
func TestLenientAddressKeepsAt(t *testing.T) {
	m, err := ParseEML(strings.NewReader("From: attacker\x81@evil.example b@y.example\r\nMessage-ID: <1@example.com>\r\n\r\nx"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.From) != 1 || len(m.From[0].Mailboxes) != 2 || !strings.HasSuffix(m.From[0].Mailboxes[0].Address, "@evil.example") {
		t.Fatalf("%+v", m.From)
	}
}

// Unclosed parentheses cost linear time: where each delimiter closes is
// computed beforehand (the earlier masker rescanned after each one,
// recursively — 200,000 took a minute).
func TestLexerUnclosedIsLinear(t *testing.T) {
	start := time.Now()
	if toks := lexAddress(strings.Repeat("(", 1<<18)); len(toks) != 1<<18 {
		t.Fatalf("%d tokens", len(toks))
	}
	m, err := ParseEML(strings.NewReader("From: "+strings.Repeat("(", 200000)+" a@x.example b@y.example\r\nMessage-ID: <1@example.com>\r\n\r\nx"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v", d)
	}
	if len(m.From) != 1 || len(m.From[0].Mailboxes) != 2 {
		t.Fatalf("%+v", m.From)
	}
}

// Many commas inside a <...> read in linear time.
func TestLenientCommasLinear(t *testing.T) {
	start := time.Now()
	readLenient("<"+strings.Repeat(",", 400000)+">", "To", "", func(Warning) {})
	readLenient("<"+strings.Repeat(",", 400000), "To", "", func(Warning) {})
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
}

// classesRef masks like v0.2.0's recursive outsideQuotes (the delimiter that
// never closes is literal; the rest is read again after it), filling
// comments with 1 and quoted-strings with 2 — the reference the lexer's
// quoted-string and comment tokens must agree with.
func classesRef(s string) []byte {
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
					b[k] = 1
				}
			}
		case depth == 0 && c == '"':
			if !quoted {
				start = i
				quoted = true
				continue
			}
			quoted = false
			for k := start; k <= i; k++ {
				b[k] = 2
			}
		}
	}
	if quoted || depth > 0 {
		return append(b[:start+1], classesRef(string(b[start+1:]))...)
	}
	return b
}

// The lexer's quoted-strings and comments are exactly the reference's.
func TestLexerMatchesReference(t *testing.T) {
	alphabet := []byte(`()"\a@<> _~`)
	seed := uint32(7)
	next := func(n int) int { seed = seed*1664525 + 1013904223; return int(seed>>8) % n }
	for range 300000 {
		b := make([]byte, next(24))
		for i := range b {
			b[i] = alphabet[next(len(alphabet))]
		}
		ref := classesRef(string(b))
		got := make([]byte, len(b))
		for _, tk := range lexAddress(string(b)) {
			for k := tk.start; k < tk.end; k++ {
				switch tk.kind {
				case tComment:
					got[k] = 1
				case tQuoted:
					got[k] = 2
				}
			}
		}
		for i := range b {
			want := byte(0)
			if ref[i] == 1 || ref[i] == 2 {
				want = ref[i]
			}
			if got[i] != want {
				t.Fatalf("%q at %d: reference %v, lexer %v", b, i, ref, got)
			}
		}
	}
}

// The contract, checked on hostile input: every Address the lenient reader
// returns is an addr-spec, and each part of it is a whole word (or one whole
// quoted-string, or one literal) written in the field outside any comment or
// quoted name — nothing made up from a comment, a quoted name, or words cut
// or glued together.
func TestLenientContract(t *testing.T) {
	alphabet := []string{"a", "b", "x", "ex", "@", ".", " ", "<", ">", ",", ";", ":", "(", ")", `"`, `\`, "1", "_", "\u00e9", "\x81", "\t",
		"\u3000", "\u00a0", "\u202e", "\x00", "(c)", "[192.0.2.1]", "a@x.example"}
	// No lone '[' or ']': the reference masker does not know domain literals
	// (the lexer reads "[...]" after "@" as one, as RFC 5322 does), so it
	// would misread a quote inside one. "[192.0.2.1]" brings literals in.
	seed := uint32(11)
	if v := os.Getenv("LENIENT_SEED"); v != "" {
		n, _ := strconv.Atoi(v)
		seed = uint32(n)
	}
	next := func(n int) int { seed = seed*1664525 + 1013904223; return int(seed>>8) % n }
	for range 300000 {
		var sb strings.Builder
		for range next(28) {
			sb.WriteString(alphabet[next(len(alphabet))])
		}
		raw := sb.String()
		for _, mb := range readLenient(raw, "From", "", func(Warning) {}) {
			if hasControl(mb.Address) {
				t.Fatalf("%q -> %q: control or format character", raw, mb.Address)
			}
			if mb.Address == "" || !strings.Contains(mb.Address, "@") {
				continue
			}
			if msg := contractViolation(raw, mb.Address); msg != "" {
				t.Fatalf("%q -> %q: %s", raw, mb.Address, msg)
			}
		}
	}
}

// contractViolation checks addr against raw independently of the lexer.
func contractViolation(raw, addr string) string {
	// Bytes that are free text: outside comments and quoted-strings (by the
	// reference masker, not by the code under test).
	ref := classesRef(raw)
	isWordByte := func(c byte) bool {
		return !isSpaceByte(c) && strings.IndexByte(`<>@,;:.()"[]\`, c) < 0
	}
	at := strings.LastIndexByte(addr, '@')
	local, domain := addr[:at], addr[at+1:]
	var parts []string
	if strings.HasPrefix(local, `"`) {
		parts = append(parts, local)
	} else {
		if strings.ContainsFunc(local, unicode.IsSpace) {
			return "whitespace in an unquoted local part"
		}
		for _, w := range strings.Split(local, ".") {
			if w != "" {
				parts = append(parts, w)
			}
		}
		if len(strings.Trim(local, ".")) == 0 {
			return "local part has no word"
		}
	}
	if strings.ContainsFunc(domain, unicode.IsSpace) {
		return "whitespace in the domain"
	}
	if strings.HasPrefix(domain, "[") {
		parts = append(parts, domain)
	} else {
		parts = append(parts, strings.Split(domain, ".")...)
	}
	// Each part is found after the one before it: in the field's order.
	from := 0
	for _, p := range parts {
		if p == "" {
			return "empty label"
		}
		found := false
		for i := indexFrom(raw, p, from); i >= 0; {
			end := i + len(p)
			// A Unicode space (U+3000, U+00A0) bounds a word as ASCII space does.
			spaceBefore := func() bool { r, _ := utf8.DecodeLastRuneInString(raw[:i]); return unicode.IsSpace(r) }
			spaceAfter := func() bool { r, _ := utf8.DecodeRuneInString(raw[end:]); return unicode.IsSpace(r) }
			whole := (i == 0 || !isWordByte(raw[i-1]) || spaceBefore() || p[0] == '"' || p[0] == '[') &&
				(end == len(raw) || !isWordByte(raw[end]) || spaceAfter() || p[len(p)-1] == '"' || p[len(p)-1] == ']')
			free := true
			for k := i; k < end; k++ {
				if ref[k] == 1 || (ref[k] == 2 && p[0] != '"') {
					free = false
				}
			}
			if whole && free {
				found = true
				from = end
				break
			}
			j := strings.Index(raw[i+1:], p)
			if j < 0 {
				break
			}
			i += 1 + j
		}
		if !found {
			return "part " + strconvQuote(p) + " is no whole free word of the field"
		}
	}
	return ""
}

func strconvQuote(s string) string { return `"` + s + `"` }

func indexFrom(s, sub string, from int) int {
	if i := strings.Index(s[from:], sub); i >= 0 {
		return from + i
	}
	return -1
}
