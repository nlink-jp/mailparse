# RFP: mailparse

> Generated: 2026-11-07
> Status: Draft (all 7 items agreed with the owner; independent design review applied)
>
> Note (2026-11-08): mail-dissect, named here as the first consumer, was withdrawn before release (its design broke
> down; the origin of organization ADR-029). The text is left as the design record of its time. The current consumers
> are the four util-series mail tools.

## 1. Problem Statement

A Go library that turns .eml, .msg and winmail.dat (TNEF) into one shape every tool can read the same way
— headers, senders and recipients, the MIME tree, bodies converted to UTF-8, attachment bytes, nested
messages, and warnings about what happened while parsing. The organization already has three email parsers
(mail-analyzer = mail-analyzer-local, eml-to-jsonl, msg-to-jsonl); their fixes are scattered, and the .msg
readers rely on community dependencies (`github.com/richardlehane/mscfb`, `msoleps` transitively). None of
them reads a .msg's compressed RTF (property 0x1009) or winmail.dat, so an Outlook message that keeps its
HTML body only inside compressed RTF loses its links, and attachments wrapped in winmail.dat are missed
entirely. This library makes one foundation of them that does not break on messages written by an
attacker.

The first consumer is mail-dissect (cybersecurity-series, its own RFP). Whether the four existing tools
move onto it is each tool's own decision, handled separately.

## 2. Functional Specification

### Commands / API Surface

```go
kind := mailparse.Detect(b)                         // eml / msg / tnef / unknown (positive recognition by content)
m, err := mailparse.Parse(r, mailparse.Options{})   // detect, then read; unknown is ErrNotMessage
m, err := mailparse.ParseEML(r, opts)
m, err := mailparse.ParseMSG(r, opts)
m, err := mailparse.ParseTNEF(r, opts)

// Exported subpackage (so nobody makes a copy)
f, err := cfb.Open(r, cfb.Limits{})                 // MS-CFB reader (for consumers looking inside OLE Office documents)
```

**Detection (`Detect`)**: .msg by the CFB signature plus the MSG root property stream; TNEF by its
signature (0x223E9F78); .eml by a start that holds together as headers (field names and separators).
Anything else is `unknown` — a lenient reader never turns a config or key file into a "message".

| `Message` field | Content |
|---|---|
| `Format` | `eml` / `msg` / `tnef` |
| `Header` | Every field **in order, duplicates kept**, both raw (with folding) and decoded |
| Addresses | From, Sender, Reply-To, Return-Path, To, Cc, Bcc **per header occurrence and per mailbox** (several addresses in one From, and duplicated From headers — all of them). **Addresses are parsed first and display names decoded from RFC 2047 afterwards** (decoding first lets an encoded display name smuggle a fake `<addr>`). An unreadable field keeps its raw value with a warning. Exchange `/O=` forms are kept raw, not blanked |
| `Subject`, `MessageID`, `Date` | Decoded. An unreadable date keeps its raw value with a warning |
| Bodies | Text and HTML converted to UTF-8, the charset decided and on what basis (MIME charset, HTML `<meta charset>`, the .msg code page, RTF `\ansicpg`), size, origin (MIME part, .msg property, HTML extracted from compressed RTF, TNEF) |
| `Attachments` | Name (RFC 2231 / 2047 decoded), type, disposition, Content-ID, inline or not, size, **bytes**. Attached messages (message/rfc822, a .msg's embedded message, winmail.dat, and **messages recognized by content** — including ones attached as `application/octet-stream`) are nested as parsed `Message`s within the same parse |
| `Parts` | The MIME tree (type, boundary, children) — for consumers that need the structure itself |
| `Warnings` | What happened while parsing (broken charsets, truncated MIME, unclosed boundaries, limits that cut something, a .msg without headers, a repair of RFC 2047 Base64 broken by folding, a compressed-RTF CRC mismatch), as codes and descriptions |

**Limits** (`Options`, defaults):

| Limit | Default | Meaning |
|---|---|---|
| `MaxSize` | 30 MiB | The whole input; beyond it, `ErrTooLarge` |
| `MaxMessageDepth` | 3 | Nesting depth of messages (layers of attached messages); the same "three layers" as mail-dissect |
| `MaxMIMEDepth` | 32 | Depth of the MIME tree within one message |
| `MaxParts` | 1,000 | Parts across all layers |
| `MaxDecoded` | 120 MiB | Total decoded size across all layers (Base64, QP, compressed RTF and TNEF contents included) |
| `MaxHeaders` / `MaxHeaderBytes` | 2,000 / 1 MiB | Field count and total size per layer |
| CFB | derived from the input size | Sector count, directory entries (4,096), claimed stream sizes |

- Depth and decoded size **share one budget across a single parse, nested messages included**
- Reaching a limit stops there and records a warning (not an error — errors are only an input beyond
  `MaxSize` and an input that cannot be recognized)

**.msg headers**: read from `PR_TRANSPORT_MESSAGE_HEADERS` (0x007D, the original internet headers). When
absent (drafts, saved sent items), sender, recipients, subject and date are filled from MAPI properties,
with a warning that there are no internet headers (and so no Received). String8 properties are decoded by
`PR_INTERNET_CPID` and the message code page (ISO-2022-JP (50220-50222) and EUC-JP (51932) included —
missing from the existing implementations' tables).

### Input / Output

Input is an `io.Reader` (read whole into memory, within `MaxSize`) or a `[]byte`. Output is the `Message`
above. Hashing and detecting attachment types are the consumer's.

### Configuration

None (a library; limits come through `Options`).

### External Dependencies

The standard library and two Go-team packages (approved by the owner 2026-11-07; mermaid-render is the
lib-series precedent):

- `golang.org/x/text` — ISO-2022-JP, Shift_JIS, EUC-JP and other charsets
- `golang.org/x/net/html` — detecting HTML `<meta charset>` (`html/charset`). Reading links is the
  consumer's (mail-dissect uses the same package)

No community dependencies.

## 3. Design Decisions

- **It reads the container, and no further** — headers, addresses, MIME, RFC 2047 / 2231, charsets (HTML
  `<meta charset>`, RTF `\ansicpg` and `\'hh` included) and transfer encodings, .eml, .msg and TNEF, nesting
  (messages recognized by content included), attachment bytes, limits. The meaning of Received or
  Authentication-Results, extracting URLs, and detecting attachment types belong to the consumer
  (interpretations differ per consumer)
- **Starting code — the union of the three** (compared in Phase 0)
  - mail-analyzer: repairing RFC 2047 Base64 broken by folding (now recorded as a warning), the skeleton
    of .msg reading
  - eml-to-jsonl: address parsing through `mail.ParseAddressList` (mail-analyzer regressed to splitting on
    commas)
  - msg-to-jsonl: handling of MAPI properties
  - Not taken over, or corrected: decoding RFC 2047 before parsing addresses (a spoofing hole), blanking
    `/O=` addresses, the gaps in the code-page table
- **CFB read from MS-CFB, and exported** — instead of the community mscfb. **Cycles in FAT, mini-FAT and
  DIFAT chains**, **cycles in the directory tree**, out-of-range sectors and claimed giant streams are
  detected and cut. Exported as the `cfb` package so consumers looking inside OLE Office documents (for
  macros) need no copy
- **Compressed RTF is read** — MS-OXRTFCP (LZFu decompression) and MS-OXRTFEX (extracting HTML
  encapsulated in RTF), implemented from Microsoft's open specifications. The output is bounded by the
  header's RAWSIZE and by `MaxDecoded`; a RAWSIZE beyond the limit is not decompressed. **A CRC mismatch
  is warned about and the decompressed result is still used** (kept as evidence). None of the existing
  three has it
- **TNEF (winmail.dat) is read** — from MS-OXTNEF. Its attachments, bodies (compressed RTF included) and
  properties come back as ordinary attachments and bodies
- **Standard-library parts, read leniently** — `net/mail`, `mime`, `mime/multipart`,
  `mime/quotedprintable` and the like are used, with lenient readers of our own for the shapes they are
  too strict for (deliberately broken headers, unclosed boundaries, bogus charset names). It reads as far
  as it can and returns warnings
- **No panics, and no stack overflow** — a Go stack overflow is a fatal stop, not a recoverable panic, so
  **every recursion is depth-capped or an iterative walk with an explicit stack** (the MIME tree, nested
  messages, the CFB directory tree, RTF groups). Work is roughly linear in the input within the limits,
  and there is no time limit. Go fuzzing checks that broken input neither panics nor hangs
- **Attachments are returned as bytes** (owner's decision) — hashing and detection belong to the consumer,
  keeping the library to reading. Size is bounded by the limits
- **Versions start at v0.x** — the shape is settled together with the first consumer (mail-dissect)

**Out of scope**

- Interpreting header semantics (Received, Authentication-Results, DKIM), extracting URLs, verdicts,
  hashing
- Mailbox bulk processing (mbox, PST); writing, composing or sending messages
- General RTF rendering (only HTML extraction, and text from RTF that encapsulates nothing)
- Moving the four existing tools onto it (each tool's decision); removing the existing tools' mscfb
  dependency (an issue for each tool)

## 4. Development Plan

### Phase 0: comparison and fixtures (no code)

- Compare the three implementations' tests and fixes into one list (which fix from which implementation,
  how it is taken in, and what is corrected)
- .eml fixtures with fictional values (RFC 2606 / 5737): ISO-2022-JP, broken Base64, RFC 2231 names,
  nesting, a message attached as `application/octet-stream`, unclosed boundaries, duplicated headers, a
  multi-mailbox From, a display name spoofing an address through RFC 2047, HTML whose charset is given
  only by `<meta charset>`
- If msg-to-jsonl or another tool has test .msg files, check their origin and terms (licence, content)
- **Local check material** (kept out of the repository):
  - the outlook.jp welcome message as a .msg, provided by the owner (it holds Microsoft's text and the
    owner's address). **It likely carries its HTML body in `PR_HTML`, so it may not exercise the
    compressed-RTF-only path** — compressed RTF and TNEF are checked with fictional fixtures assembled per
    the specifications
  - the 13 real messages in `util-series/mail-analyzer-local/testdata/eval/{safe,unsafe}/` (gitignored)

### Phase 1: EML

`Detect`, headers (order, duplicates, raw and decoded), addresses (per occurrence, parsed before decoding),
the MIME tree, charsets (`<meta charset>` included), RFC 2047 / 2231, transfer encodings, broken Base64
repair, nesting (messages recognized by content included), limits and the shared budget, warnings. Tests
and fuzzing.

### Phase 2: MSG and TNEF

CFB (MS-CFB, exported as `cfb`), MAPI properties (MS-OXMSG) — internet headers, bodies (text, HTML),
attachments, embedded messages, code pages. Compressed RTF decompression (MS-OXRTFCP) and HTML extraction
(MS-OXRTFEX, `\ansicpg`, `\'hh`). TNEF (MS-OXTNEF). Local checks. Tests and fuzzing.

### Phase 3: Release

README in English and Japanese, AGENTS, CHANGELOG, the pre-release independent review, the v0.1.0 release,
registration in lib-series.

Two independent reviews — when this RFP is settled (done and applied 2026-11-07), and before release.

## 5. Required API Scopes / Permissions

None (a library; no network traffic).

## 6. Series Placement

Series: lib-series
Reason: a foundation shared across series (next to toml and pathguard). The first consumer is
cybersecurity-series' mail-dissect; later, util-series' email tools.

## 7. External Platform Constraints

No external service. Specifications followed (all open):

- Mail: RFC 5322, MIME (RFC 2045-2049), RFC 2047, RFC 2231
- HTML charset detection: the HTML Standard (followed by `golang.org/x/net/html/charset`)
- .msg: MS-CFB, MS-OXMSG (MAPI properties), MS-OXRTFCP, MS-OXRTFEX
- winmail.dat: MS-OXTNEF

Where real Outlook output departs from the specifications, a local .msg is the check.

---

## Discussion Log

- **Origin (2026-11-07)**: designing mail-dissect showed that the organization's email parser exists as
  three implementations. The owner chose "shared library + new MCP" (the owner was also told that the
  rules had diverged; re-checked after the independent review, they are identical apart from the import
  line — duplicated, not diverged; corrected here)
- **Dependencies**: the existing .msg readers depend on the community mscfb, so MS-CFB is read in-house.
  The owner approved `golang.org/x/text`
- **Compressed RTF**: none of the three implementations reads property 0x1009, so in-house MS-OXRTFCP /
  MS-OXRTFEX came into scope — approved by the owner
- **Problem statement and scope**: the name `mailparse`; it reads the container only (header semantics
  belong to consumers); the starting code is the union of the three — approved by the owner
- **Functional specification**: attachments returned as bytes — approved by the owner
- **Outlook fixtures**: the owner rarely uses Outlook and will provide the outlook.jp welcome message as a
  .msg, kept out of the repository and used for local checks
- **Independent design review (2026-11-07)**: all findings adopted — positive recognition by content
  (`Detect`); default limits and one shared budget; a cap on LZFu output and the CRC-mismatch policy;
  cycle detection in FAT, mini-FAT and DIFAT chains and in the directory tree; recursion caps (a stack
  overflow cannot be recovered); TNEF; addresses per occurrence, parsed before decoding; `/O=` kept; the
  code-page gaps (50220-50222, 51932); ownership of `<meta charset>` and RTF code pages; ownership of
  messages recognized by content; exporting `cfb`; an accurate account of the union; local check material
  (the welcome message may not exercise compressed RTF; mail-analyzer-local's 13 messages). **Owner's
  decisions**: `golang.org/x/net/html` adopted (an exception); winmail.dat (TNEF) brought into scope
