# AGENTS.md — mailparse

## Summary

A Go library (lib-series) that reads email messages into one Message shape: header fields in order with
duplicates, address lists per occurrence, the MIME tree, UTF-8 bodies, attachment bytes, nested messages and
Warnings. Written for attacker-composed input. Consumers: the four util-series mail tools (mail-analyzer,
mail-analyzer-local, eml-to-jsonl, msg-to-jsonl). Its planned first consumer, mail-dissect, was withdrawn on
2026-11-08 before release.

Module path: `github.com/nlink-jp/mailparse`. Design authority:
[docs/ja/mailparse-rfp.ja.md](docs/ja/mailparse-rfp.ja.md) (English beside it); the comparison with the three
existing util-series parsers and the measured defects: [docs/ja/mailparse-phase0.ja.md](docs/ja/mailparse-phase0.ja.md).

**Status: v0.3.1. The API is v0.x until its consumers (the four util-series mail tools) settle it.**

## Build / test

```bash
make build   # compiles the packages only (a library leaves no binary)
make test    # go test -race -cover ./... — fixtures and every fuzz seed
make lint    # golangci-lint — before every commit
make fuzz    # FUZZTIME=60s by default
```

Go 1.26+. Dependencies: `golang.org/x/text`, `golang.org/x/net/html` (Go team; owner-approved exceptions).

## Layout

```
doc.go        Package documentation
mailparse.go  Format, errors, Options and defaults, Message types, Parse / ParseBytes / ParseEML
detect.go     Positive recognition: CFB + MSG stream names, TNEF signature, an EML header block
header.go     Lenient header reader (order, duplicates, raw + decoded, limits); RFC 2047 with repair
address.go    Address lists: net/mail AddressParser first (decodes the phrase after tokenizing); display names
lenient.go    The lenient fallback for fields net/mail refuses: RFC 5322 lexer + small grammar, one output contract
entity.go     parseEML, identity fields, the MIME walk, own multipart splitter, nested messages, the shared budget
transfer.go   Base64 / quoted-printable that keep what decodes and warn about damage
charset.go    Declared charset, HTML <meta charset> (x/net/html tokenizer), Japanese guessing, strict decoding
warnings.go   Warning codes
codepage.go   Windows code page -> charset (incl. 50220-50222, 51932)
params.go     Lenient Content-Type / Content-Disposition parameters (RFC 2231 in any charset); replaces mime.ParseMediaType
api.go        Consumer helpers: Attachment.Text, Message.Walk, Message.AllWarnings
msg.go        .msg (MS-OXMSG): property streams, transport headers or MAPI identity, bodies, attachments, embedded
rtf.go        Compressed RTF (MS-OXRTFCP) and de-encapsulation / text extraction (MS-OXRTFEX), explicit group stack
tnef.go       TNEF (MS-OXTNEF): attributes with checksums, encapsulated MAPI property lists, recipient table, attachments
msgtest/      Exported test support: builders for .msg, TNEF, compressed RTF, compound files (used by our own tests)
cfb/          Exported MS-CFB reader (FAT/DIFAT/mini-FAT, directory tree; loops and ranges cut)
testdata/eml/ The Phase 0 fixtures (fictional; byte-exact Japanese encodings)
docs/{en,ja}/ RFP and the Phase 0 record
```

## Gotchas

- **Never use net/textproto for headers.** It keeps a map by name (order lost, duplicates collapsed behind
  `Get`) and rejects the whole message over one bad line — the defects fixture 07 and 10 measured.
- **Parse addresses before decoding.** Decoding RFC 2047 first lets `=?UTF-8?B?...?=` become
  `Bank <security@bank.example> <attacker@...>` (fixture 08).
- **Go's mime.WordDecoder can return its input unchanged with no error** for a malformed word; leftover
  `=?` is treated as failure and `repairEncodedWords` is tried, with a warning.
- **x/text decoders replace instead of failing.** `decodeStrict` treats an introduced U+FFFD as failure.
- **No silent fallbacks.** Every guess, repair, skip or cut gets a Warning code; a new fallback without one
  is a bug.
- **Recursion is bounded** by MaxMIMEDepth and MaxMessageDepth; keep it that way (a Go stack overflow is not a
  recoverable panic).
- **Every .msg stream read is charged to MaxDecoded before it happens** (`msgReader.read`): directory entries can
  all point at one large chain, so an unbudgeted read multiplies the work.
- **ISO-2022-JP is 7-bit** and passes for ASCII and UTF-8; `decodeText` tries its escapes first.
- **RTF code pages: HTMLTAG content uses the document default (`\ansicpg`); text outside it uses the current
  font's code page** (MS-OXRTFEX, "Extracting Encapsulated HTML from RTF"). `\fN` is tracked even inside `\htmlrtf`-suppressed text.
- **MAPI properties are one `props` shape whatever the container** (.msg storage or TNEF list); identity, bodies
  and attachments are filled from it by the same functions (`identityFromProps`, `propBodies`, `mapiAttachment`).
- **TNEF has no real sample yet**: only spec-built fixtures. Measure on a real winmail.dat when one is available.
- **`make lint` checks gofmt itself**: golangci-lint here does not.
- **Consumers reimplemented the same things when the API lacked them** (v0.2.0, issues #1–#10): before adding a
  field, ask what a consumer would otherwise have to rebuild — a safe formatter, a charset conversion, a walk.
- **msgtest must not import mailparse** (mailparse's tests import msgtest); its own tests are an external package.
- **Warnings go through `warner(m)`** (capped at 100 per code); never append to `m.Warnings` directly.
- **Never use `mime.ParseMediaType` for parameters**: one bad parameter makes it drop all of them (an attacker
  hides the filename that way) and it decodes RFC 2231 only for UTF-8/US-ASCII. Use `parseParams`.
- **TNEF values are read through `tnefLoader`**, which charges MaxDecoded and copies; do not read the maps directly.
- **Code pages**: .msg 8-bit strings use PidTagMessageCodepage, bodies PidTagInternetCodepage (MS-OXCMSG); TNEF
  strings use attOemCodepage (MS-OXTNEF 2.3.3.2).
- **Detect needs a mail-only field, or a From with an address among mail-like field names** (no `_`, not all
  lowercase). Requiring a Date rejected minimal script mail (second review); keep both directions tested.
- **The lenient address reader is a lexer and a grammar, held to the contract at the top of lenient.go**
  (an Address is a run of tokens that is an addr-spec as written; every part is a whole word of the field).
  Never find structure by searching the string or cut an address out by byte position: six review rounds of
  such repairs each let other text through (2026-11-07). `TestLenientContract` checks the contract on random input
  — extend the contract and the test together.
- **Address fields are tokenized on the raw bytes; only display names are converted from 8-bit afterwards** — a
  Shift_JIS trail byte 0x5C converted first swallows a quoted-string escape and injects a mailbox.
- **The independent pre-release review found ~45 issues** (all fixed, see CHANGELOG Security): rerun one before
  each release; the classes were memory bounds, hidden content and misleading values.
- **Fuzz with `-fuzzminimizetime 1x`** (the Makefile does): minimizing tens-of-KB inputs stalls the run for seconds.
- **Writing escapes through a tool can turn them into raw characters** (`\uFFFD`, bidi controls, a soft hyphen,
  and even `\u1235` inside a raw string such as an RTF `\u12354`). `source_test.go` refuses control and format
  characters, NBSP and U+FFFD; check other non-ASCII by eye.

## Decisions (from the RFP — do not silently reverse)

- Reads the container only; header semantics, URLs, type detection and hashing belong to consumers.
- Attachments come back as bytes (a copy).
- CFB is read from MS-CFB in-house and exported as `cfb`; no community dependencies.
- A .msg returns every body it holds (text, HTML, compressed RTF); a client's choice among them is not guessed.
