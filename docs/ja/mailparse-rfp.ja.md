# RFP: mailparse

> Generated: 2026-11-07
> Status: Draft（利用者と全 7 項目合意済み・設計の独立検証を反映済み）
>
> 注記（2026-11-08）: この RFP が「最初の利用者」とする mail-dissect は、公開前に撤回された（設計の破綻、組織 ADR-029 の発端）。
> 本文は当時の設計記録として書き換えていない。現在の利用者は util-series のメール系 4 ツール。

## 1. Problem Statement

.eml・.msg・winmail.dat（TNEF）を、どのツールからも同じように読める共通の形 — ヘッダ、差出人と宛先、
MIME の木構造、UTF-8 に直した本文、添付のバイト列、入れ子のメール、解析中に起きたことの警告 — に変える
Go のライブラリ。組織にはメールのパーサーがすでに 3 実装あり（mail-analyzer ＝ mail-analyzer-local、
eml-to-jsonl、msg-to-jsonl）、直した箇所がばらばらに散り、.msg の読み取りはコミュニティ製の依存
（`github.com/richardlehane/mscfb`、間接に `msoleps`）に頼っている。そのうえ、どの実装も .msg の圧縮 RTF
（プロパティ 0x1009）も winmail.dat も読まず、HTML の本文を圧縮 RTF の中にだけ持つ Outlook のメールでは
リンクを、winmail.dat に包まれた添付は丸ごとを見落とす。これを 1 つにまとめ、攻撃者が作ったメールを
読んでも壊れない土台にする。

最初の利用者は mail-dissect（cybersecurity-series、別の RFP）。既存の 4 ツールが乗り換えるかは、各ツールの
判断として別に扱う。

## 2. Functional Specification

### Commands / API Surface

```go
kind := mailparse.Detect(b)                         // eml / msg / tnef / unknown（中身で積極的に判別）
m, err := mailparse.Parse(r, mailparse.Options{})   // 判別して読む。unknown は ErrNotMessage
m, err := mailparse.ParseEML(r, opts)
m, err := mailparse.ParseMSG(r, opts)
m, err := mailparse.ParseTNEF(r, opts)

// 公開する下位パッケージ（写しを作らせないため）
f, err := cfb.Open(r, cfb.Limits{})                 // MS-CFB の読み取り（OLE の Office 文書の中を見る利用者向け）
```

**判別（`Detect`）**: .msg は CFB のシグネチャに加えて MSG のルートのプロパティストリームがあること、
TNEF はシグネチャ（0x223E9F78）、.eml は先頭がヘッダとして成り立つこと（フィールド名と区切りの形）で
決める。どれでもなければ `unknown` — 設定ファイルや鍵のファイルを、寛容な読み取りで「メール」にしない。

| `Message` の項目 | 中身 |
|---|---|
| `Format` | `eml` / `msg` / `tnef` |
| `Header` | 全フィールドを**出てきた順・重複込み**で、生の値（折り返しを含む）と復号した値の両方 |
| アドレス | From・Sender・Reply-To・Return-Path・To・Cc・Bcc を、**ヘッダの出現ごと・メールボックスごと**に（1 つの From に複数のアドレス、From ヘッダの重複、どちらも全部）。**アドレスを解析してから表示名を RFC 2047 で復号する**（復号してから解析すると、符号化した表示名に偽の `<addr>` を仕込める）。読めない欄は生の値と警告。Exchange の `/O=` 形式は消さずに生のまま残す |
| `Subject`・`MessageID`・`Date` | 復号済み。日付が読めなければ生の値と警告 |
| 本文 | テキストと HTML を UTF-8 に直したもの、決まった文字コードとその根拠（MIME の charset、HTML の `<meta charset>`、.msg のコードページ、RTF の `\ansicpg`）、大きさ、出どころ（MIME のパート、.msg のプロパティ、圧縮 RTF から取り出した HTML、TNEF） |
| `Attachments` | 名前（RFC 2231 / 2047 を復号）、種類、disposition、Content-ID、インラインか、大きさ、**バイト列**。添付されたメール（message/rfc822、.msg の埋め込みメッセージ、winmail.dat、**中身で判別したメール** — `application/octet-stream` で付いたものを含む）は、同じ解析の中で解析済みの `Message` として入れ子にする |
| `Parts` | MIME の木構造（種類・境界・子）— 構造そのものを見たい利用者のため |
| `Warnings` | 解析中に起きたこと（文字コードの壊れ、切れた MIME、閉じない境界、上限で打ち切った箇所、ヘッダの無い .msg、RFC 2047 の壊れた Base64 を補修したこと、圧縮 RTF の CRC 不一致）をコードと説明で |

**上限**（`Options`、既定値）:

| 上限 | 既定 | 意味 |
|---|---|---|
| `MaxSize` | 30 MiB | 入力全体。超えれば `ErrTooLarge` |
| `MaxMessageDepth` | 3 | メールの入れ子の深さ（添付されたメールの層）。mail-dissect の「3 層」と同じ |
| `MaxMIMEDepth` | 32 | 1 通の中の MIME の木の深さ |
| `MaxParts` | 1,000 | 全層を通したパーツ数 |
| `MaxDecoded` | 120 MiB | 全層を通したデコード後の合計（Base64・QP・圧縮 RTF・TNEF の中身を含む） |
| `MaxHeaders` / `MaxHeaderBytes` | 2,000 / 1 MiB | 1 層あたりのフィールド数と合計の大きさ |
| CFB | 入力の大きさから導く | セクタ数、ディレクトリのエントリ数（4,096）、ストリームの申告の大きさ |

- 深さとデコード後の大きさは、**入れ子を開く処理を含む 1 回の解析で 1 つの予算を共有**する
- 上限に達したらそこで打ち切り、`Warnings` に書く（エラーにはしない。入力自体が `MaxSize` を超えるとき、
  判別できないときだけエラー）

**.msg のヘッダ**: `PR_TRANSPORT_MESSAGE_HEADERS`（0x007D、元のインターネットヘッダ）から読む。無い場合
（下書き・送信済みの保存など）は、MAPI のプロパティから差出人・宛先・件名・日付を埋め、「インターネット
ヘッダが無い（Received も無い）」と警告する。String8 のプロパティは `PR_INTERNET_CPID`・メッセージの
コードページで復号する（ISO-2022-JP（50220〜50222）、EUC-JP（51932）を含む — 既存実装の対応表には無い）。

### Input / Output

入力は `io.Reader`（全体を `MaxSize` の範囲でメモリに読む）か `[]byte`。出力は上の `Message`。ハッシュの計算や
添付の種類の判別は利用者が行う。

### Configuration

なし（ライブラリ。上限は `Options` で渡す）。

### External Dependencies

標準ライブラリと Go チーム製の 2 つ（2026-11-07 利用者の承認。lib-series では mermaid-render に前例）:

- `golang.org/x/text` — ISO-2022-JP・Shift_JIS・EUC-JP などの文字コード
- `golang.org/x/net/html` — HTML の `<meta charset>` の判別（`html/charset`）。リンクの読み取りは
  利用者（mail-dissect）が同じパッケージで行う

コミュニティ製の依存は入れない。

## 3. Design Decisions

- **受け持つのは「入れ物」の読み取りまで** — ヘッダ、アドレス、MIME、RFC 2047 / 2231、文字コード（HTML の
  `<meta charset>`、RTF の `\ansicpg` と `\'hh` を含む）と転送エンコーディング、.eml・.msg・TNEF、入れ子
  （中身で判別したメールを含む）、添付のバイト列、上限。Received や Authentication-Results の中身の意味、
  URL の取り出し、添付の種類の判別は使う側が行う（解釈は利用者ごとに違う）
- **元にするコード — 3 実装の和集合**（段階 0 で突き合わせる）
  - mail-analyzer: RFC 2047 の壊れた Base64 の補修（補修したことを警告に残す）、`.msg` の読み取りの骨組み
  - eml-to-jsonl: `mail.ParseAddressList` によるアドレスの解析（mail-analyzer はカンマで分けるだけに
    後退している）
  - msg-to-jsonl: MAPI のプロパティの扱い
  - 取り込まないもの・直すもの: RFC 2047 の復号をアドレスの解析より先に行う順序（偽装の穴）、`/O=` の
    アドレスを空にする扱い、コードページの対応表の欠け
- **CFB は MS-CFB から自前で読み、公開する** — コミュニティ製の mscfb の代わり。FAT・mini-FAT・DIFAT の
  **鎖の循環**、**ディレクトリの木の循環**、範囲外のセクタ、巨大なストリームの申告を検出して打ち切る。
  OLE の Office 文書の中（マクロの有無）を見る利用者が写しを作らずに済むよう、`cfb` パッケージとして公開する
- **圧縮 RTF を読む** — MS-OXRTFCP（LZFu の展開）と MS-OXRTFEX（RTF に包まれた HTML の取り出し）を
  Microsoft の公開仕様から自前で作る。展開後の大きさはヘッダの RAWSIZE と `MaxDecoded` の両方で抑え、
  RAWSIZE が上限を超えれば展開しない。**CRC が合わなければ警告し、展開した結果は使う**（証拠として残す）。
  既存の 3 実装には無い
- **TNEF（winmail.dat）を読む** — MS-OXTNEF から自前で。中の添付・本文（圧縮 RTF を含む）・プロパティを、
  通常の添付・本文として返す
- **標準ライブラリの部品を使い、寛容に読む** — `net/mail`・`mime`・`mime/multipart`・`mime/quotedprintable`
  などを使うが、それらが厳しすぎて読めない形（わざと崩したヘッダ、閉じない境界、不正な文字コード名）には
  自前の寛容な読み方を用意する。読めるところまで読んで警告を返す
- **panic せず、スタックも溢れさせない** — Go のスタックの溢れは回復できない致命的な停止なので、
  **再帰はすべて深さの上限つきか、明示的なスタックによる反復**にする（MIME の木、入れ子のメール、CFB の
  ディレクトリの木、RTF のグループ）。処理量は上限の範囲で入力の大きさにほぼ比例し、時間の上限は
  設けない。Go のファジングで、壊れた入力で panic もハングもしないことを確かめる
- **添付はバイト列で返す**（利用者の判断）— ハッシュや判別は使う側。ライブラリの責務を読むことだけに保つ。
  大きさは上限で守る
- **版は v0.x から** — 最初の利用者（mail-dissect）と一緒に形を固める

**範囲外**

- Received・Authentication-Results・DKIM などヘッダの意味の解釈、URL の取り出し、判定、ハッシュの計算
- メールボックスの一括処理（mbox・PST）、メールの書き出し・組み立て・送信
- RTF の一般的な描画（HTML の取り出しと、包まれていない RTF からのテキストの取り出しだけ）
- 既存 4 ツールの乗せ替え（各ツールの判断）、既存ツールの mscfb 依存の解消（各ツールの issue）

## 4. Development Plan

### Phase 0: 突き合わせと見本（コードは書かない）

- 3 実装のテストと修正を突き合わせ、和集合の一覧を作る（どの実装のどの修正をどう取り込むか、直すもの）
- 架空の値（RFC 2606 / 5737）で .eml の見本を作る（ISO-2022-JP、壊れた Base64、RFC 2231 の名前、入れ子、
  `application/octet-stream` で付いたメール、閉じない境界、重複ヘッダ、複数アドレスの From、RFC 2047 で
  アドレスを偽装した表示名、`<meta charset>` だけで文字コードを示す HTML）
- msg-to-jsonl などに既存の試験用 .msg があれば、出どころと扱い（ライセンス・中身）を確かめる
- **手元での確認材料**（リポジトリに入れない）:
  - 利用者が用意する outlook.jp のウェルカムメールの .msg（Microsoft の文面と利用者のアドレスを含む）。
    **HTML の本文を `PR_HTML` に持つ可能性が高く、圧縮 RTF だけの経路を試せないかもしれない** — 圧縮 RTF と
    TNEF は、仕様どおりに組み立てた架空の見本で確かめる
  - `util-series/mail-analyzer-local/testdata/eval/{safe,unsafe}/` の本物のメール 13 通（gitignore 済み）

### Phase 1: EML

`Detect`、ヘッダ（順序・重複・生と復号）、アドレス（出現ごと・解析してから復号）、MIME の木、文字コード
（`<meta charset>` を含む）、RFC 2047 / 2231、転送エンコーディング、壊れた Base64 の補修、入れ子（中身で
判別したメールを含む）、上限と共有の予算、警告。テストとファジング。

### Phase 2: MSG・TNEF

CFB（MS-CFB、`cfb` パッケージとして公開）、MAPI のプロパティ（MS-OXMSG）— インターネットヘッダ、本文
（テキスト・HTML）、添付、埋め込みメッセージ、コードページ。圧縮 RTF の展開（MS-OXRTFCP）と HTML の
取り出し（MS-OXRTFEX、`\ansicpg`・`\'hh`）。TNEF（MS-OXTNEF）。手元の確認。テストとファジング。

### Phase 3: Release

README の日英・AGENTS・CHANGELOG、リリース前の独立検証、v0.1.0 のリリース、lib-series への登録。

独立検証は 2 回 — この RFP の確定時（2026-11-07 実施・反映済み）と、リリース前。

## 5. Required API Scopes / Permissions

なし（ライブラリ。ネットワーク通信なし）。

## 6. Series Placement

Series: lib-series
Reason: シリーズを横断する共通の土台（toml・pathguard と同じ並び）。最初の利用者は cybersecurity-series の
mail-dissect、将来は util-series のメール系ツール。

## 7. External Platform Constraints

外部サービスなし。従う仕様（いずれも公開）:

- メール: RFC 5322、MIME（RFC 2045〜2049）、RFC 2047、RFC 2231
- HTML の文字コードの判別: HTML 標準（`golang.org/x/net/html/charset` が従う）
- .msg: MS-CFB、MS-OXMSG（MAPI のプロパティ）、MS-OXRTFCP、MS-OXRTFEX
- winmail.dat: MS-OXTNEF

実物の Outlook が仕様どおりに書かない箇所は、手元の .msg で確かめる。

---

## Discussion Log

- **発端（2026-11-07）**: mail-dissect の設計で、組織のメールのパーサーが 3 実装に分かれていると分かった。
  利用者は「共通ライブラリ＋新 MCP」を選んだ（「判定ルールも分岐している」と伝えたが、独立検証の指摘で
  確かめ直すと import の行以外は同一の重複だった。訂正する）
- **依存**: 既存の .msg の読み取りがコミュニティ製の mscfb に依存していると分かり、MS-CFB から自前で
  読むことにした。`golang.org/x/text` は利用者が承認した
- **圧縮 RTF**: 既存の 3 実装がどれもプロパティ 0x1009 を読まないと分かり、MS-OXRTFCP / MS-OXRTFEX の
  自前実装を範囲に入れた — 利用者が承認
- **問題定義・範囲**: 名前は `mailparse`、受け持つのは入れ物の読み取りまで（ヘッダの意味は使う側）、
  元のコードは 3 実装の和集合 — 利用者が承認
- **機能仕様**: 添付はバイト列で返す — 利用者が承認
- **Outlook の見本**: 利用者は Outlook をほとんど使わないため、outlook.jp のウェルカムメールの .msg を
  用意する。リポジトリには入れず手元の確認に使う
- **設計の独立検証（2026-11-07）**: 指摘を全部採用した — 中身による積極的な判別（`Detect`）、上限の既定値と
  1 つの予算の共有、LZFu の展開の上限と CRC 不一致の扱い、FAT・mini-FAT・DIFAT とディレクトリの木の循環の
  検出、再帰の上限（スタックの溢れは回復できない）、TNEF、アドレスはヘッダの出現ごと・解析してから復号、
  `/O=` を残す、コードページの欠け（50220〜50222・51932）、`<meta charset>` と RTF のコードページの担当、
  中身で判別した入れ子のメールの担当、`cfb` の公開、和集合の中身の正確な書き直し、手元の確認材料
  （ウェルカムメールは圧縮 RTF の経路を試せない可能性、mail-analyzer-local の 13 通）。**利用者の判断**:
  `golang.org/x/net/html` を採用（例外）、winmail.dat（TNEF）を範囲に入れる
