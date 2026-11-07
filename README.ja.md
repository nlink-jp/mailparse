# mailparse

メールを、どのツールからも同じように読める 1 つの形に変える Go のライブラリです。ヘッダは出てきた順・重複込み、
差出人と宛先は欄ごとにすべて、MIME の木構造、UTF-8 に直した本文、添付のバイト列、入れ子のメール、そして途中で
起きたことの警告を返します。

攻撃者が作ったメールを読む前提で作っています。

- **順序と重複を保つ。** 先頭に置かれた偽の `Authentication-Results: ... pass` が、後ろの本物の `fail` を隠さない
  ようにします。2 つ目の `From:` も事実として返します。
- **アドレスを解析してから表示名を復号する。** 符号化した表示名にアドレスを仕込まれないようにします。
- **黙って捨てない。** 崩れたヘッダ行、閉じない境界、壊れた Base64、未知の文字コード、上限での打ち切りは、
  安定したコードを持つ `Warning` になります。空の結果にも、解析の失敗にもしません。
- **上限**（大きさ・入れ子・パーツ数・デコード後の大きさ）は、入れ子のメールも含めた 1 回の解析で共有します。
  入力で panic しないことは、ファジングで確かめています。

> 状態: 開発中（v0.x、未リリース）。`.eml`、Outlook の `.msg`（圧縮 RTF を含む）、winmail.dat（TNEF）に対応。
> `.msg` は実物の Outlook のメールで確かめています。TNEF は仕様どおりに組み立てた見本でだけ確かめています。

[English README](README.md)

## 使い方

```go
m, err := mailparse.Parse(r, mailparse.Options{}) // Options のゼロ値は既定値
switch {
case errors.Is(err, mailparse.ErrNotMessage): // メールとして判別できない — 何もメールとして読んでいない
case errors.Is(err, mailparse.ErrTooLarge):
case err != nil:
}
for _, f := range m.Header.All("Received") { /* 経由の各段を順に */ }
for _, from := range m.From { /* From の欄ごとに 1 つ */ }
for _, a := range m.Attachments {
	if a.Message != nil { /* 転送されたメールを開いたもの */ }
}
for _, w := range m.Warnings { /* 解析中に起きたこと */ }
```

`Detect(b)` は中身でメールを積極的に判別します（`eml` / `msg` / `tnef` / `unknown`）。設定ファイルや鍵のファイルは
`unknown` で、メールとして「読まれる」ことはありません。`.eml` と判別するには、メールにしか現れない欄（Received、
Message-ID、Return-Path、DKIM-Signature など）か、メールらしい欄名（`_` を含まず、すべて小文字ではない）の中に
アドレスを含む From が要ります。スクリプトが送る From/To/Subject だけのメールはメールで、`from:` と `to:` のキーを
持つ YAML や、HTTP のヘッダの写しはメールではありません。

## 読むもの・使う側に任せるもの

読む: ヘッダ（生の値と復号した値）、アドレス（Return-Path を含み、空の `<>` も）、MIME の木、RFC 2047 / 2231、
転送エンコーディング、文字コード（宣言、HTML の `<meta charset>`、宣言の無い日本語の推定）、入れ子のメール
（message/rfc822、.msg の埋め込みメッセージ、中身で判別したもの）、添付のバイト列。Content-Type と
Content-Disposition の引数は寛容に読みます。崩れた引数が 1 つあってもほかを捨てず（添付の名前は見えたまま）、
重複は最初のものを使い、RFC 2231 の名前はどの文字コードでも復号します — それぞれ警告を付けます。分割できない
multipart はバイト列を 1 つの添付として残し、閉じの区切りの後ろに置かれたパートも読んで警告します。

`.msg` からは: Outlook が残したインターネットヘッダ（`PR_TRANSPORT_MESSAGE_HEADERS`）。無ければ差出人・宛先・
件名・日付を MAPI のプロパティから取り、`no_transport_headers` の警告を付けます（そのメールには Received が
ありません）。持っている本文はすべて — テキスト、HTML、圧縮 RTF（MS-OXRTFCP）と、その中に Outlook が包んだ
HTML かテキスト（MS-OXRTFEX）、または包まれていない RTF の見える文字 — を返します。攻撃者は食い違わせられるから
です（CRC が合わなければ警告し、取り出した文字は証拠として残します）。添付とそのバイト列、
埋め込みメッセージ。8 ビットの文字列はメールのコードページで、本文はインターネットのコードページで復号し、
ISO-2022-JP（50220〜50222）と EUC-JP（51932）も含みます。Exchange の `/O=...` 形式のアドレスは `Raw` に残します。
Outlook が表示する MAPI の差出人や件名がヘッダと食い違うとき、表示するアドレスと別の SMTP アドレスを持つ
メールボックスがあるときは、警告で伝えます。包まれていない RTF の HYPERLINK は、Outlook がプレーンテキストで
表すのと同じく「文字 ` <リンク先>`」の形で書くので、リンク先は失われません。隠し文字も残します（見落とすより
多めに返すほうが安全なため）。

winmail.dat（TNEF。たいてい `application/ms-tnef` の添付で、形式 `tnef` の入れ子のメールとして開きます）からは:
本文（Outlook が入れる圧縮 RTF、HTML、テキスト）、名前とバイト列つきの添付、埋め込みメッセージ、宛先の表からの
宛先、包まれた MAPI のプロパティからの差出人・件名・日付。8 ビットの文字列は OEM のコードページで復号します。
チェックサムが合わなければ警告し、値は残します。旧形式の属性 attFrom と attDateSent は読みません。attMessageID
（検索キーで、インターネットの Message-ID ではない）は Message-ID として返しません。

`ParseEML`・`ParseMSG`・`ParseTNEF` は、判別をせずにその形式として読みます。

使う側に任せる: Received や Authentication-Results の意味、URL の取り出し、添付の種類の判別、ハッシュの計算。

## cfb パッケージ

`github.com/nlink-jp/mailparse/cfb` は Compound File Binary（MS-CFB）— `.msg` と旧形式の Office 文書の入れ物 —
を読みます。Office 文書の中（マクロの格納場所など）を見たい利用者が、コミュニティ製の依存なしで使えるよう公開
しています。セクタの鎖やディレクトリの木の循環、範囲外のセクタ、ストリーム同士で共有された鎖、実際より大きい
ストリームの申告は打ち切って報告します（`Issues`、`ErrTruncated`）。開く処理は入力の大きさにほぼ比例します。
どの木からもつながっていない確保済みのエントリ — 木をたどる道具からストリームを隠す手口 — は `File.Unlinked`
に並べます。セクタを共有するストリームがあると、全部を読む費用はファイルの大きさを超えるので、信頼できない
ファイルから読むときは読む量に予算を設けてください（mailparse はそうしています）。`File` は並行して使えません。

```go
f, err := cfb.Open(r, cfb.Limits{}) // 既定は MaxSize 64 MiB、MaxEntries 4,096
for _, e := range f.Root.Children { /* ストレージとストリームをディレクトリの順に */ }
data, err := f.ReadStream(f.Root.Child("WordDocument"))
```

## 上限（Options の既定値）

| 項目 | 既定 |
|---|---|
| `MaxSize` | 30 MiB |
| `MaxMessageDepth` | 入れ子 3 層 |
| `MaxMIMEDepth` | 32 |
| `MaxParts` | 全層で 1,000 |
| `MaxDecoded` | 全層で 120 MiB（Base64・QP、.msg のストリーム、展開した RTF、TNEF の値を含む） |
| `MaxHeaders` / `MaxHeaderBytes` | ヘッダのまとまりごとに 2,000 / 1 MiB |

`MaxDecoded` は、残したデコード済みの写しをすべて数えます。添付されたメールのバイト列と、それを開いたパートの
両方が数えられます。1 通の中で同じコードの警告が 100 件を超えたら、残りは 1 件の `warning_limit` 警告にまとめます。

## 依存

標準ライブラリと Go チーム製の 2 つです。`golang.org/x/text`（日本語などの文字コード）と、`golang.org/x/net/html`
（HTML の `<meta charset>`）。コミュニティ製の依存はありません。

## 文書

[RFP](docs/ja/mailparse-rfp.ja.md) · [段階 0 の記録](docs/ja/mailparse-phase0.ja.md) · [AGENTS.md](AGENTS.md)

## ライセンス

MIT — [LICENSE](LICENSE) を参照。
