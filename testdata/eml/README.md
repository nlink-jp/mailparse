# .eml fixtures

Fictional messages for mailparse's tests: RFC 2606 domains (`example.com`, `example.net`, `example.org`,
`*.example`) and RFC 5737 addresses only. Japanese text is encoded byte-exact (ISO-2022-JP, Shift_JIS),
so these files hold raw escape sequences and non-UTF-8 bytes on purpose.

| File | Shape | What the existing util-series parsers did (Phase 0) |
|---|---|---|
| `01-iso2022jp.eml` | ISO-2022-JP subject, From and body | read correctly |
| `02-broken-b64-word.eml` | RFC 2047 Base64 payload broken by a space and a tab | read correctly (mail-analyzer's repair) |
| `03-rfc2231-filenames.eml` | RFC 2231 percent-encoded and continued filenames | read correctly |
| `04-forwarded-rfc822.eml` | Original forwarded as message/rfc822, itself with an attachment | inner message not opened |
| `05-forwarded-octet-stream.eml` | Original forwarded as `application/octet-stream` | inner message not opened |
| `06-unclosed-boundary.eml` | Multipart whose closing boundary never comes | second part silently dropped |
| `07-duplicate-headers.eml` | Two From (one multi-mailbox), Sender, two Authentication-Results, interleaved Received | only the first From and the first Authentication-Results read |
| `08-rfc2047-address-spoof.eml` | Display name that decodes to an address form | a fake address surfaced from the display name |
| `09-meta-charset.eml` | HTML part without a charset parameter; Shift_JIS declared only by `<meta>` | garbled |
| `10-malformed-header-line.eml` | A header line with no colon | the whole message failed to parse |
| `11-bad-base64-attachment.eml` | Base64 attachment with invalid characters | hashed as empty data, no warning |
