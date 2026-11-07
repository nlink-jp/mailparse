# mailparse

A Go library that reads email messages into one shape every tool can read the same way: header fields in
order with duplicates kept, every sender and recipient list, the MIME tree, bodies converted to UTF-8,
attachment bytes, nested messages, and warnings about everything it met along the way.

It is written for messages composed by an attacker:

- **Order and duplicates are kept.** A forged `Authentication-Results: ... pass` placed on top must not hide
  the real `fail` after it, and a second `From:` is a fact, not noise.
- **Addresses are parsed before display names are decoded,** so an encoded display name cannot smuggle in an
  address.
- **Nothing is dropped silently.** A malformed header line, an unclosed boundary, damaged Base64, an unknown
  charset or a limit that cut something becomes a `Warning` with a stable code — never an empty result and
  never a failed parse.
- **Limits** on size, nesting, part count and decoded bytes are shared across one parse, nested messages
  included. It never panics on input; fuzz tests hold it to that.

> Status: in development (v0.x, not yet released). `.eml` is supported; `.msg` and winmail.dat (TNEF) come in
> the next phase.

[日本語版 README](README.ja.md)

## Use

```go
m, err := mailparse.Parse(r, mailparse.Options{}) // zero Options = defaults
switch {
case errors.Is(err, mailparse.ErrNotMessage): // not recognized as a message — nothing was read as one
case errors.Is(err, mailparse.ErrTooLarge):
case err != nil:
}
for _, f := range m.Header.All("Received") { /* every hop, in order */ }
for _, from := range m.From { /* one entry per From field */ }
for _, a := range m.Attachments {
	if a.Message != nil { /* a forwarded message, opened */ }
}
for _, w := range m.Warnings { /* what the parse met */ }
```

`Detect(b)` recognizes a message positively by content (`eml` / `msg` / `tnef` / `unknown`); a config or key file
is `unknown` and is never "parsed" as mail.

## What it reads, and what it leaves to you

Reads: header fields (raw and decoded), address lists, the MIME tree, RFC 2047 / 2231, transfer encodings,
charsets (declared, HTML `<meta charset>`, or guessed for undeclared Japanese), nested messages
(message/rfc822 and messages recognized by content), attachment bytes.

Leaves to the consumer: the meaning of Received or Authentication-Results, URL extraction, attachment type
detection, hashing.

## Limits (Options, defaults)

| Option | Default |
|---|---|
| `MaxSize` | 30 MiB |
| `MaxMessageDepth` | 3 nested layers |
| `MaxMIMEDepth` | 32 |
| `MaxParts` | 1,000 across every layer |
| `MaxDecoded` | 120 MiB across every layer |
| `MaxHeaders` / `MaxHeaderBytes` | 2,000 / 1 MiB per header block |

## Dependencies

The standard library and two Go-team packages: `golang.org/x/text` (Japanese and other charsets) and
`golang.org/x/net/html` (HTML `<meta charset>`). No community dependencies.

## Documentation

[RFP](docs/en/mailparse-rfp.md) · [Phase 0 record](docs/en/mailparse-phase0.md) · [AGENTS.md](AGENTS.md)

## License

MIT — see [LICENSE](LICENSE).
