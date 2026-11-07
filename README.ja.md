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

> 状態: 開発中（v0.x、未リリース）。`.eml` と Outlook の `.msg`（圧縮 RTF を含む）に対応。winmail.dat（TNEF）は
> 作業中です。

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
`unknown` で、メールとして「読まれる」ことはありません。

## 読むもの・使う側に任せるもの

読む: ヘッダ（生の値と復号した値）、アドレス、MIME の木、RFC 2047 / 2231、転送エンコーディング、文字コード（宣言、
HTML の `<meta charset>`、宣言の無い日本語の推定）、入れ子のメール（message/rfc822、.msg の埋め込みメッセージ、
中身で判別したもの）、添付のバイト列。

`.msg` からは: Outlook が残したインターネットヘッダ（`PR_TRANSPORT_MESSAGE_HEADERS`）。無ければ差出人・宛先・
件名・日付を MAPI のプロパティから取り、`no_transport_headers` の警告を付けます（そのメールには Received が
ありません）。持っている本文はすべて — テキスト、HTML、圧縮 RTF（MS-OXRTFCP）と、その中に Outlook が包んだ
HTML かテキスト（MS-OXRTFEX）、または包まれていない RTF の見える文字 — を返します。攻撃者は食い違わせられるから
です（CRC が合わなければ警告し、取り出した文字は証拠として残します）。添付とそのバイト列、
埋め込みメッセージ。8 ビットの文字列はメールのコードページで復号し、ISO-2022-JP（50220〜50222）と EUC-JP
（51932）も含みます。Exchange の `/O=...` 形式のアドレスは `Raw` に残します。

## cfb パッケージ

`github.com/nlink-jp/mailparse/cfb` は Compound File Binary（MS-CFB）— `.msg` と旧形式の Office 文書の入れ物 —
を読みます。Office 文書の中（マクロの格納場所など）を見たい利用者が、コミュニティ製の依存なしで使えるよう公開
しています。セクタの鎖やディレクトリの木の循環、範囲外のセクタ、実際より大きいストリームの申告は打ち切って
報告します（`Issues`、`ErrTruncated`）。処理量は入力の大きさにほぼ比例します。

```go
f, err := cfb.Open(r, cfb.Limits{}) // 既定は MaxSize 64 MiB、MaxEntries 4,096
for _, e := range f.Root.Children { /* ストレージとストリームをディレクトリの順に */ }
data, err := f.ReadStream(f.Root.Child("WordDocument"))
```

使う側に任せる: Received や Authentication-Results の意味、URL の取り出し、添付の種類の判別、ハッシュの計算。

## 上限（Options の既定値）

| 項目 | 既定 |
|---|---|
| `MaxSize` | 30 MiB |
| `MaxMessageDepth` | 入れ子 3 層 |
| `MaxMIMEDepth` | 32 |
| `MaxParts` | 全層で 1,000 |
| `MaxDecoded` | 全層で 120 MiB |
| `MaxHeaders` / `MaxHeaderBytes` | ヘッダのまとまりごとに 2,000 / 1 MiB |

## 依存

標準ライブラリと Go チーム製の 2 つです。`golang.org/x/text`（日本語などの文字コード）と、`golang.org/x/net/html`
（HTML の `<meta charset>`）。コミュニティ製の依存はありません。

## 文書

[RFP](docs/ja/mailparse-rfp.ja.md) · [段階 0 の記録](docs/ja/mailparse-phase0.ja.md) · [AGENTS.md](AGENTS.md)

## ライセンス

MIT — [LICENSE](LICENSE) を参照。
