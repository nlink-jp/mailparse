package mailparse

// DecodedText is a text converted to UTF-8, with how its charset was decided
// (the same rules and warnings as bodies).
type DecodedText struct {
	Content       string    `json:"content"`
	Charset       string    `json:"charset"`
	CharsetSource string    `json:"charset_source"`
	Warnings      []Warning `json:"warnings"`
}

// Text converts the attachment's bytes to UTF-8 the way bodies are converted:
// its declared Charset, a byte order mark, an HTML <meta charset> for
// text/html, or a guess (Japanese included), each reported. It is meant for
// text/* attachments — text/calendar invitations, text/csv — which are not
// bodies; for other types the result is whatever the bytes decode to.
func (a Attachment) Text() DecodedText {
	var ws []Warning
	r := decodeText(a.MediaType, a.Charset, "mime", a.Data, a.Part, func(w Warning) { ws = append(ws, w) })
	if ws == nil {
		ws = []Warning{}
	}
	return DecodedText{Content: r.content, Charset: r.charset, CharsetSource: r.source, Warnings: ws}
}

// Walk calls fn for m and then for every nested message (an attached
// message/rfc822, .msg, winmail.dat), depth first, in attachment order. path
// names where the message sits: "" for m itself, and for a nested message the
// Part of each attachment on the way joined with ">" ("2>1" is the message
// attached as part 1 of the message attached as part 2). Part names inside a
// nested message are relative to it; join them to path to make them absolute.
// fn returning false stops the walk.
func (m *Message) Walk(fn func(path string, depth int, msg *Message) bool) {
	m.walk("", 0, fn)
}

func (m *Message) walk(path string, depth int, fn func(string, int, *Message) bool) bool {
	if !fn(path, depth, m) {
		return false
	}
	for _, a := range m.Attachments {
		if a.Message == nil {
			continue
		}
		p := a.Part
		if path != "" {
			p = path + ">" + a.Part
		}
		if !a.Message.walk(p, depth+1, fn) {
			return false
		}
	}
	return true
}

// AllWarnings returns the warnings of m and of every nested message, in Walk
// order, with each nested warning's Part made absolute: the path of its
// message, then ">" and its own Part when it has one.
func (m *Message) AllWarnings() []Warning {
	out := []Warning{}
	m.Walk(func(path string, _ int, msg *Message) bool {
		for _, w := range msg.Warnings {
			switch {
			case path == "":
			case w.Part == "":
				w.Part = path
			default:
				w.Part = path + ">" + w.Part
			}
			out = append(out, w)
		}
		return true
	})
	return out
}
