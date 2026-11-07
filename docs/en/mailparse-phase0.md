# mailparse Phase 0 record

> Done 2026-11-07. Subjects: util-series' three implementations (mail-analyzer's `internal/parser` —
> byte-identical to mail-analyzer-local's — eml-to-jsonl, msg-to-jsonl). Fixtures: 11 fictional messages
> in `testdata/eml/` (RFC 2606 domains, RFC 5737 addresses). The existing implementations' behaviour was
> **measured** by running the installed mail-analyzer (`--offline` — rules only, no network) and
> eml-to-jsonl over the fixtures.

## How the three relate

mail-analyzer's CLAUDE.md says its parser was built "from eml-to-jsonl + msg-to-jsonl". mail-analyzer is
indeed the merge of the two, with the RFC 2047 repair added and address parsing regressed.

| Item | mail-analyzer | eml-to-jsonl | msg-to-jsonl |
|---|---|---|---|
| Formats | .eml, .msg | .eml | .msg |
| Header reading | `net/mail` → `textproto` (a map by name) | same | splits `PR_TRANSPORT_MESSAGE_HEADERS` itself |
| Addresses | **decodes RFC 2047, then splits on commas** | decodes RFC 2047, then `mail.ParseAddressList` | splits on `;` |
| Repair of RFC 2047 Base64 broken by folding | yes (`fixBrokenEncodedWords`) | no | — |
| Charsets | `x/text/encoding/htmlindex`; failure silently returns raw bytes | same | a code-page table (no 50220-50222, 51932) |
| MIME depth cap | 10 | 10 | — |
| Part size cap | 25 MiB (`LimitReader` — a cut part is parsed on silently) | similar | stream cap |
| Attachments | hash only (no bytes returned) | same | same |
| Nested messages | not opened (hashed as one attachment) | not opened | **embedded .msg dropped** (as "no name and no data") |
| CFB | `github.com/richardlehane/mscfb` (community) | — | same |
| Compressed RTF (0x1009) | not read | — | not read |
| Fixed-length properties (`__properties_version1.0`) | **not read** | — | **not read** |

## Defects confirmed by measurement (fixture numbers)

| Fixture | Existing behaviour | What mailparse does instead |
|---|---|---|
| 01 ISO-2022-JP, 02 broken Base64 word, 03 RFC 2231 names | **read correctly** | taken over as is (02 now records the repair as a warning) |
| 04 forwarded as message/rfc822, 05 forwarded as `application/octet-stream` | inner message not opened; hashed as one attachment | opened as a nested message (05 recognized by content) |
| 06 unclosed boundary | the second part **silently dropped** | returns what was read, with a warning |
| 07 duplicated headers | only the first From; the second From (with the attacker's address) and Sender lost. **Only the first Authentication-Results (pass) read; the later `spf=fail` ignored** | every field returned in order, duplicates kept |
| 08 display name spoofing an address through RFC 2047 | From became `Bank Security <security@bank.example> <attacker@phish.example>` (a fake address surfacing from the display name) | addresses parsed first, display names decoded afterwards |
| 09 HTML whose Shift_JIS is declared only by `<meta charset>` | **garbled** | charset decided from `<meta charset>` (`x/net/html/charset`) |
| 10 a header line with no colon | **the whole message failed to parse** (`malformed header line`) | a lenient header reader of our own; the line is recorded as a warning and parsing continues |
| 11 Base64 attachment with invalid characters | hash `e3b0c442…` (**the SHA-256 of empty data**), no warning | returns what decoded, with a decoding warning |

## Defects read from the code (awaiting a real file — PLAUSIBLE)

- **Fixed-length properties are never read**: both .msg readers look only at `__substg1.0_` streams. Per
  MS-OXMSG, times (`PR_CLIENT_SUBMIT_TIME` and the like), the attachment method (`PR_ATTACH_METHOD`), sizes
  and other fixed-length values live in the `__properties_version1.0` stream, so `getTime` / `getInt` are
  expected never to succeed on a real .msg (dates come only from internet headers). To be checked with the
  owner's .msg
- **An embedded message leaks into the outer one**: a storage's owner is decided by the last path element
  only. Attachments inside an embedded .msg (`__substg1.0_3701000D`) carry the same names as the outer ones
  (`__attach_version1.0_#00000000`), so they can overwrite the outer attachment's values. To be checked with
  a fixture containing an embedded .msg
- **Addresses split naively on `;` or commas** — a quoted display name containing a comma breaks

## Checked on a real .msg (2026-11-07, the owner's outlook.jp welcome message)

No content was shown — only CFB stream names and sizes, and whether the existing implementation's output
fields were empty or present.

- **Fixed-length properties are not read — confirmed**: a `__properties_version1.0` stream sits at the root
  (1,920 bytes) and in every one of the 21 attachments (280 bytes each). mail-analyzer (`--offline`)
  returned **an empty date**
- **No internet headers**: neither `PR_TRANSPORT_MESSAGE_HEADERS` (0x007D) nor a text body (0x1000) exists,
  so not a single Received is available. The RFP's "fill from MAPI properties and warn" is needed for real
- **The HTML body is in `PR_HTML` (0x1013, 12,742 bytes); there is no compressed RTF (0x1009)** — as
  expected, this file cannot exercise the compressed-RTF-only path; Phase 2 checks it with fixtures built
  per the specifications
- 21 attachments (apparently inline images, with Content-IDs), 1 recipient, no embedded message (the
  embedded-message leak cannot be checked with this file)

## The union

- **Take over**: mail-analyzer's RFC 2047 repair, charset-name resolution through `htmlindex`, stripping
  whitespace from Base64, RFC 2231 names (`mime.ParseMediaType`), msg-to-jsonl's handling of MAPI property
  types and UTF-16LE BOMs
- **Replace**: `net/mail` / `textproto` header reading (it loses order and duplicates, and one broken line
  fails the whole message) with a lenient reader of our own. Addresses through `net/mail`'s address parser,
  with display names decoded **after** parsing. CFB in-house (MS-CFB)
- **Add**: nested messages (rfc822, recognized by content, embedded .msg, TNEF), fixed-length properties,
  compressed RTF, `<meta charset>`, the missing code pages, and a warning wherever the existing code
  silently drops or cuts

## Fixtures and check material

- The 11 messages in `testdata/eml/` (table above). Generated with fictional values only, by a script, so
  the Japanese-charset bytes are exact
- No existing repository has test .msg files (msg-to-jsonl's tests build properties in code)
- **.msg fixtures are built in Phase 2**: fictional .msg assembled per the specifications (MS-CFB, MS-OXMSG,
  MS-OXRTFCP, MS-OXTNEF) — an embedded message, fixed-length properties, a compressed-RTF-only body — and a
  winmail.dat
- **Local check material** (kept out of the repository): the outlook.jp welcome message as a .msg from the
  owner (not yet received), and the 13 real messages in `util-series/mail-analyzer-local/testdata/eval/`

## Carried into Phase 1

- Every place the existing code silently dropped something (06, 10, 11) gets a named `Warnings` code
- Fixture 07 is a premise of mail-dissect's trust boundary (choosing the organization's own
  Authentication-Results by authserv-id and position) — a reader that sees only the first one is fooled
  by a forged pass placed on top
