# AGENTS.md — mailparse

## Summary

A Go library (lib-series) that reads email messages into one Message shape: header fields in order with
duplicates, address lists per occurrence, the MIME tree, UTF-8 bodies, attachment bytes, nested messages and
Warnings. Written for attacker-composed input. First consumer: mail-dissect (cybersecurity-series).

Module path: `github.com/nlink-jp/mailparse`. Design authority:
[docs/ja/mailparse-rfp.ja.md](docs/ja/mailparse-rfp.ja.md) (English beside it); the comparison with the three
existing util-series parsers and the measured defects: [docs/ja/mailparse-phase0.ja.md](docs/ja/mailparse-phase0.ja.md).

**Status: in development. Phase 1 (.eml) done; Phase 2 (.msg, CFB, compressed RTF, TNEF) next.**

## Build / test

```bash
make build   # compiles the packages only (a library leaves no binary)
make test    # go test -race -cover ./... — fixtures and every fuzz seed
make lint    # golangci-lint — before every commit
make fuzz    # FUZZTIME=60s by default
```

Go 1.25+. Dependencies: `golang.org/x/text`, `golang.org/x/net/html` (Go team; owner-approved exceptions).

## Layout

```
doc.go        Package documentation
mailparse.go  Format, errors, Options and defaults, Message types, Parse / ParseBytes / ParseEML
detect.go     Positive recognition: CFB + MSG stream names, TNEF signature, an EML header block
header.go     Lenient header reader (order, duplicates, raw + decoded, limits); RFC 2047 with repair
address.go    Address lists: net/mail AddressParser first (decodes the phrase after tokenizing), lenient fallback
entity.go     parseEML, identity fields, the MIME walk, own multipart splitter, nested messages, the shared budget
transfer.go   Base64 / quoted-printable that keep what decodes and warn about damage
charset.go    Declared charset, HTML <meta charset> (x/net/html tokenizer), Japanese guessing, strict decoding
warnings.go   Warning codes
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
- **Writing escapes through a tool can turn them into raw characters** (`\uFFFD`, bidi controls).
  `source_test.go` refuses them; re-escape.

## Decisions (from the RFP — do not silently reverse)

- Reads the container only; header semantics, URLs, type detection and hashing belong to consumers.
- Attachments come back as bytes (a copy).
- CFB will be read from MS-CFB in-house (Phase 2) and exported as `cfb`; no community dependencies.
