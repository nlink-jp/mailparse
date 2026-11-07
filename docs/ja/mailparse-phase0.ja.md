# mailparse 段階 0 の記録

> 実施: 2026-11-07。対象は util-series の 3 実装（mail-analyzer の `internal/parser` — mail-analyzer-local と
> バイト単位で同一、eml-to-jsonl、msg-to-jsonl）。見本は `testdata/eml/` の架空の 11 通（RFC 2606 の
> ドメイン・RFC 5737 のアドレス）。既存の実装の挙動は、インストール済みの mail-analyzer（`--offline` —
> ルールだけでネットワークを使わない）と eml-to-jsonl に見本を通して**実測**した。

## 3 実装の関係

mail-analyzer の CLAUDE.md は、パーサーを「eml-to-jsonl＋msg-to-jsonl から」作ったと書いている。実際に
mail-analyzer は 2 つを 1 つにまとめた版で、そこに RFC 2047 の補修が足され、アドレスの解析は後退している。

| 項目 | mail-analyzer | eml-to-jsonl | msg-to-jsonl |
|---|---|---|---|
| 対応形式 | .eml・.msg | .eml | .msg |
| ヘッダの読み取り | `net/mail` → `textproto`（名前ごとの map） | 同じ | `PR_TRANSPORT_MESSAGE_HEADERS` を自前で分割 |
| アドレス | **RFC 2047 を復号してからカンマで分割** | RFC 2047 を復号してから `mail.ParseAddressList` | `;` で分割 |
| RFC 2047 の壊れた Base64 の補修 | あり（`fixBrokenEncodedWords`） | なし | — |
| 文字コード | `x/text/encoding/htmlindex`。失敗は黙って生のバイト | 同じ | コードページ表（50220〜50222・51932 なし） |
| MIME の深さの上限 | 10 | 10 | — |
| パートの大きさの上限 | 25 MiB（`LimitReader` — 切れても黙って続ける） | 同様 | ストリームの上限あり |
| 添付 | ハッシュだけ（バイト列を返さない） | 同様 | 同様 |
| 入れ子のメール | 開かない（1 つの添付としてハッシュ） | 開かない | **埋め込みの .msg を捨てる**（「名前も中身も無い」として） |
| CFB | `github.com/richardlehane/mscfb`（コミュニティ製） | — | 同じ |
| 圧縮 RTF（0x1009） | 読まない | — | 読まない |
| 固定長プロパティ（`__properties_version1.0`） | **読まない** | — | **読まない** |

## 実測で確かめた欠陥（見本の番号）

| 見本 | 既存の実装の挙動 | mailparse で直すこと |
|---|---|---|
| 01 ISO-2022-JP、02 壊れた Base64 の単語、03 RFC 2231 の名前 | **正しく読めた** | そのまま取り込む（02 は補修したことを警告に残す） |
| 04 message/rfc822 で転送、05 `application/octet-stream` で転送 | 中のメールを開かず、1 つの添付としてハッシュ | 入れ子として開く（05 は中身で判別） |
| 06 閉じない境界 | 2 つ目のパートを**黙って捨てた** | 読めたところまで返し、警告する |
| 07 重複ヘッダ | From は 1 つ目だけ。2 つ目の From（攻撃者のアドレス入り）と Sender を失う。**Authentication-Results も 1 つ目（pass）だけを読み、後の `spf=fail` を無視した** | 全フィールドを出てきた順・重複込みで返す |
| 08 RFC 2047 でアドレスを偽装した表示名 | From が `Bank Security <security@bank.example> <attacker@phish.example>` になった（偽のアドレスが表示名から現れる） | アドレスを解析してから表示名を復号する |
| 09 `<meta charset>` だけで Shift_JIS を示す HTML | **文字化けした** | `<meta charset>` で文字コードを決める（`x/net/html/charset`） |
| 10 コロンの無いヘッダ行 | **メール全体の解析に失敗**（`malformed header line`） | 自前の寛容なヘッダの読み取り。その行を警告に残して続ける |
| 11 不正な文字を含む Base64 の添付 | ハッシュが `e3b0c442…`（**空のデータの SHA-256**）、警告なし | 読めた分を返し、デコードの失敗を警告する |

## コードから読めた欠陥（実物での確認待ち — PLAUSIBLE）

- **固定長プロパティを読まない**: 両方の .msg の読み取りは `__substg1.0_` のストリームしか見ない。MS-OXMSG
  では日時（`PR_CLIENT_SUBMIT_TIME` など）・添付の方式（`PR_ATTACH_METHOD`）・大きさなどの固定長の値は
  `__properties_version1.0` のストリームに入るので、`getTime` / `getInt` は実物の .msg では成功しない
  見込み（日付はインターネットヘッダからしか得られない）。利用者の .msg で確かめる
- **埋め込みメッセージの中が外側に混ざる**: ストレージの所属をパスの最後の要素だけで決めている。埋め込みの
  .msg（`__substg1.0_3701000D`）の中の添付は外側と同じ名前（`__attach_version1.0_#00000000`）を持つので、
  外側の添付の値に上書きされうる。埋め込みの .msg を含む見本で確かめる
- **アドレスの解析が `;` やカンマの単純な分割** — 引用された表示名にカンマがあると壊れる

## 実物の .msg での確認（2026-11-07、利用者の outlook.jp のウェルカムメール）

中身は表示せず、CFB のストリーム名と大きさ、既存の実装の出力の「空か・あるか」だけを見た。

- **固定長プロパティを読まない — 確認した**: 最上位に `__properties_version1.0`（1,920 バイト）、21 個の添付
  すべてに同名のストリーム（各 280 バイト）がある。mail-analyzer（`--offline`）の出力は**日付が空**だった
- **インターネットヘッダが無い**: `PR_TRANSPORT_MESSAGE_HEADERS`（0x007D）もテキストの本文（0x1000）も無い。
  Received は 1 つも得られない。RFP の「MAPI のプロパティで埋めて警告する」は、実物で要る
- **HTML の本文は `PR_HTML`（0x1013、12,742 バイト）にあり、圧縮 RTF（0x1009）は無い** — 予想どおり、この
  ファイルでは圧縮 RTF だけの経路を試せない。段階 2 で仕様どおりに組み立てた見本で確かめる
- 添付は 21 個（インライン画像と思われる、Content-ID つき）、宛先 1、埋め込みメッセージは無い（埋め込みの
  混ざりの疑いはこのファイルでは確かめられない）

## 和集合の方針

- **取り込む**: mail-analyzer の RFC 2047 の補修、`htmlindex` による文字コード名の解決、Base64 の空白の除去、
  RFC 2231 の名前の扱い（`mime.ParseMediaType`）、msg-to-jsonl の MAPI プロパティの型の扱い・UTF-16LE の
  BOM の処理
- **置き換える**: `net/mail` / `textproto` のヘッダの読み取り（順序と重複を失い、1 行の崩れで全体が失敗）を
  自前の寛容な読み取りに。アドレスは `net/mail` のアドレス解析を使い、**解析の後に**表示名を復号。CFB は
  自前（MS-CFB）
- **足す**: 入れ子のメール（rfc822・中身で判別・埋め込みの .msg・TNEF）、固定長プロパティ、圧縮 RTF、
  `<meta charset>`、コードページ表の欠け、すべての「黙って捨てる・黙って切る」箇所を警告に

## 見本と確認材料

- `testdata/eml/` の 11 通（上の表）。生成は架空の値だけで、日本語の文字コードのバイト列を正確に作るため
  スクリプトで書いた
- 既存のリポジトリに試験用の .msg は無い（msg-to-jsonl のテストはプロパティをコードで組み立てている）
- **.msg の見本は段階 2 で作る**: 仕様（MS-CFB・MS-OXMSG・MS-OXRTFCP・MS-OXTNEF）どおりに組み立てた架空の
  .msg（埋め込みメッセージ、固定長プロパティ、圧縮 RTF だけの本文）と winmail.dat
- **手元の確認材料**（リポジトリに入れない）: 利用者が用意する outlook.jp のウェルカムメールの .msg（未着）、
  `util-series/mail-analyzer-local/testdata/eval/` の本物のメール 13 通

## 段階 1 への持ち越し

- 06・10・11 のように既存の実装が黙って欠かしていた箇所は、すべて `Warnings` のコードに名前を付ける
- 07 の結果は mail-dissect の信頼の境界の設計（自社が付けた Authentication-Results を authserv-id と位置で
  選ぶ）にとって前提になる — 1 つ目しか読まない実装では、偽の pass を先頭に置かれると見誤る
