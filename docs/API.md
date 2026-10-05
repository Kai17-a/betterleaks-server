# betterleaks-server API 仕様

テキストに含まれるシークレット（API トークン、秘密鍵、パスワード入りの接続 URI など）を検出し、マスクした本文を返す HTTP API。LLM など外部にテキストを渡す前の前段フィルターとして使う。

この文書だけで API を呼び出せるよう、仕様をすべて記載している。

## 概要

| 項目 | 値 |
| --- | --- |
| ベース URL | `http://127.0.0.1:8080`（既定値。運用環境に合わせて読み替える） |
| プロトコル | HTTP/1.1、JSON（UTF-8） |
| 認証 | なし |
| エンドポイント | `POST /v1/scan`、`GET /v1/rules`、`GET /healthz` |

### すべてのリクエストに共通の条件

- `Host` ヘッダーのホスト名は `localhost`、ループバック IP（`127.0.0.1`、`::1` など）、またはサーバー側で許可された名前でなければならない。それ以外は 403。ポート番号は判定に使わない。
- `Origin` ヘッダーを付ける場合、そのホスト名にも同じ条件が適用される。`Origin: null` は 403。`Origin` を付けなければ判定しない。
- CORS ヘッダーは返さない。ブラウザから別オリジンとして呼び出す用途には対応していない。

## 典型的な使い方（LLM の前段フィルター）

1. 送信したいテキストを `POST /v1/scan` の `content` に入れて送る。
2. ステータスが 200 なら、**元のテキストの代わりに `redacted_content` を LLM に渡す**。
3. ステータスが 200 以外なら、**元のテキストを LLM に渡さない**（マスクできていないため）。503 は時間をおいて再試行できる。
4. 検出の有無で処理を分けたい場合は `detected` を見る。

複数のテキスト（会話履歴の各メッセージなど）を扱う場合は、テキストごとに 1 リクエストを送る。一括送信の API はない。

```sh
curl -s -X POST http://127.0.0.1:8080/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"content":"デプロイ用のトークンは <GitHubトークン> です。\n確認をお願いします。"}'
```

```json
{
  "detected": true,
  "redacted_content": "デプロイ用のトークンは [REDACTED:github-pat] です。\n確認をお願いします。",
  "findings": [
    {
      "rule_id": "github-pat",
      "description": "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.",
      "start_line": 1,
      "end_line": 1,
      "start_column": 35,
      "end_column": 74,
      "match": "REDACTED",
      "secret": "REDACTED",
      "file": "",
      "entropy": 5.171928,
      "confidence": "high",
      "tags": [],
      "fingerprint": ":github-pat:1"
    }
  ],
  "count": 1
}
```

## `POST /v1/scan`

テキストをスキャンし、検出結果とマスク済みの本文を返す。

### リクエスト

ヘッダー `Content-Type: application/json` が必須（`; charset=utf-8` などのパラメーターは付けてよい）。

ボディは JSON オブジェクト 1 つ。下記以外のフィールドがあると 400 になる。

| フィールド | 型 | 必須 | 既定値 | 説明 |
| --- | --- | --- | --- | --- |
| `content` | string | 必須 | — | スキャン対象のテキスト。空文字は不可 |
| `redact` | boolean | 任意 | `true` | `findings` 内の `secret` と `match` をマスクするか。`redacted_content` には影響しない |
| `path` | string | 任意 | `""` | 仮想ファイル名。指定しないことを推奨（下記参照） |

制約:

- ボディ全体は既定で 1 MiB（1,048,576 バイト）まで。超えると 413。
- 行の長さに制限はない。改行のない長い文章もそのまま送れる。
- `path` に `.`、`./`、`a/..` など `.` に正規化される値は指定できない（400）。

`path` について: ファイルの内容をスキャンする場合に、ファイル名で判定するルールや除外設定を働かせるための項目。値によっては特定のルールの検出が**抑制される**。プロンプトや会話文など、ファイルに由来しないテキストでは指定しない。第三者が決めた値をそのまま渡さない。

### レスポンス（200）

| フィールド | 型 | 説明 |
| --- | --- | --- |
| `detected` | boolean | シークレットが 1 件以上見つかったか。`count > 0` と同じ |
| `redacted_content` | string | 検出箇所を置き換えた本文。検出がなければ `content` と同一 |
| `findings` | array | 検出の一覧。位置の昇順。検出がなければ `[]` |
| `count` | integer | `findings` の件数 |

`findings` の各要素:

| フィールド | 型 | 説明 |
| --- | --- | --- |
| `rule_id` | string | 検出したルールの ID（例: `github-pat`）。`GET /v1/rules` の `id` に対応 |
| `description` | string | ルールの説明（英語） |
| `start_line` | integer | マッチ開始行。1 始まり。行は `\n` で区切る（`\r` は行内の 1 バイトとして数える） |
| `end_line` | integer | マッチ終了行。1 始まり |
| `start_column` | integer | 開始行内でのマッチ開始位置。1 始まりの**バイト**位置（UTF-8） |
| `end_column` | integer | 終了行内でのマッチ最終バイトの位置。1 始まりの**バイト**位置で、その位置を含む |
| `match` | string | ルールがマッチした文字列。`redact` が `true` なら常に `"REDACTED"` |
| `secret` | string | マッチのうちシークレットにあたる部分。`redact` が `true` なら `"REDACTED"` |
| `file` | string | リクエストの `path`。未指定なら `""` |
| `entropy` | number | シークレットのシャノンエントロピー |
| `confidence` | string | ルールの確度。`"high"`、`"medium"`、`"low"` のいずれか。未設定のルールは `""` |
| `tags` | array of string | 補足情報。エンコードされた値から検出した場合は `"decoded:base64"`、`"decode-depth:1"` などが入る。なければ `[]` |
| `fingerprint` | string | `<path>:<rule_id>:<start_line>` 形式の識別子 |

位置についての注意:

- 行・列は `content` 全体に対する位置。
- 列は文字数ではなくバイト数。日本語は 1 文字 3 バイト、絵文字は 4 バイトで数える。文字単位で扱う言語（JavaScript、Python の `str` など）でそのまま添字に使うとずれる。本文の書き換えは自前で行わず、`redacted_content` を使う。
- 位置はシークレットではなく**マッチ全体**を指す。マッチはシークレットより広いことがある（例: 接続 URI 全体）。
- エンコードされた値から検出した場合、位置は `content` 内のエンコード済みの部分を指し、`match` と `secret` はデコード後の値になる。
- `path` だけで判定するルールによる検出は、位置がすべて 0 になる。

### `redacted_content` の仕様

`redact` の値に関係なく、常にマスクされる。

- 置き換え後の文字列は `[REDACTED:<rule_id>]`（例: `[REDACTED:github-pat]`）。シークレットがルール ID の一部と偶然一致する場合のみ `[REDACTED]` になる。
- ルールが**マッチした範囲全体**を 1 つの目印に置き換える。パスワード入りの接続 URI は、ホスト名なども含めて URI ごと置き換わる。
- マッチの前後にある空白や改行は残す。
- 重なり合う検出は 1 つの目印にまとめ、最も手前で最も広い検出のルール ID を使う。
- base64、16 進、パーセントエンコード、Unicode エスケープで包まれたシークレットは、エンコード済みの部分を置き換える。
- 複数の部品で成立するルール（API キーとアプリケーション ID の組など）は、部品もそれぞれ置き換える。
- 検出したシークレットと同じ文字列（8 バイト以上）が本文の別の場所にあれば、そこも置き換える。
- 置き換え箇所以外は 1 バイトも変更しない。

例:

| `content` | `redacted_content` |
| --- | --- |
| `トークン<GitHubトークン>を使う` | `トークン[REDACTED:github-pat]を使う` |
| `接続先は postgres://user:<パスワード>@db.example.internal:5432/app です。` | `接続先は [REDACTED:generic-credential-uri] です。` |
| `DATABASE_URL=https://user:<パスワード>@git.example.internal/repo?token=abc` | `DATABASE_URL=[REDACTED:generic-credential-uri]` |
| 複数行の `-----BEGIN RSA PRIVATE KEY-----` 〜 `-----END RSA PRIVATE KEY-----` | `[REDACTED:private-key]` |

`redacted_content` を受け取る LLM には、`[REDACTED:...]` が「機密情報を取り除いた跡」であり、元の値は取得できないことを伝えておくとよい。

### `redact` による違い

| | `redact: true`（既定） | `redact: false` |
| --- | --- | --- |
| `redacted_content` | マスク済み | マスク済み（同じ） |
| `findings[].secret` | `"REDACTED"` | 生のシークレット |
| `findings[].match` | `"REDACTED"` | 生のマッチ文字列 |
| `findings[].file`、`fingerprint` | 検出したシークレットと一致する部分を `REDACTED` に置換 | `path` をそのまま含む |

`redact: false` のレスポンスには生のシークレットが含まれる。ログに残したり LLM に渡したりしない。

### 検出がない場合

```json
{"detected":false,"redacted_content":"普通の文章です。","findings":[],"count":0}
```

## `GET /v1/rules`

読み込まれている検出ルールの一覧を返す。ID の昇順。

```json
{
  "rules": [
    {
      "id": "1password-secret-key",
      "description": "Uncovered a possible 1Password secret key, potentially compromising access to secrets in vaults.",
      "tags": []
    }
  ],
  "count": 463
}
```

| フィールド | 型 | 説明 |
| --- | --- | --- |
| `rules[].id` | string | ルール ID。`findings[].rule_id` と目印の `<rule_id>` に対応 |
| `rules[].description` | string | ルールの説明（英語） |
| `rules[].tags` | array of string | ルールのタグ。なければ `[]` |
| `count` | integer | ルールの件数 |

## `GET /healthz`

サーバーが応答できる状態かを返す。

```json
{"status":"ok"}
```

## エラー

下表のエラーは `Content-Type: application/json; charset=utf-8` で、次の形式のボディを返す。

```json
{"error":"content is required"}
```

| ステータス | `error` の値 | 原因 | 再試行 |
| --- | --- | --- | --- |
| 400 | `invalid JSON request body` | JSON として不正、未知のフィールドがある、型が違う、ボディが空 | 不可（リクエストを直す） |
| 400 | `request body must contain a single JSON object` | JSON オブジェクトの後ろに余分なデータがある | 不可 |
| 400 | `content is required` | `content` がない、または空文字 | 不可 |
| 400 | `path must name a file` | `path` が `.` に正規化される | 不可 |
| 403 | `host not allowed` | `Host` が許可されていない | 不可 |
| 403 | `origin not allowed` | `Origin` が許可されていない | 不可 |
| 413 | `request body too large` | ボディが上限を超えた | 不可（分割して送る） |
| 415 | `Content-Type must be application/json` | `Content-Type` がない、または JSON でない | 不可 |
| 500 | `scan failed` | サーバー内部のエラー | 可 |
| 503 | `too many concurrent scans` | 待機中のリクエストが上限に達した。`Retry-After: 1` ヘッダー付き | 可 |
| 503 | `scan timed out` | 待機とスキャンの合計が制限時間（既定 30 秒）を超えた | 可 |
| 503 | `scan canceled` | クライアントが接続を切った | 可 |

次の 2 つは JSON ではなくプレーンテキストで返る。

| ステータス | 原因 |
| --- | --- |
| 404 | 存在しないパス |
| 405 | メソッドが違う（`Allow` ヘッダーに使えるメソッドが入る） |

200 以外のレスポンスに `redacted_content` は含まれない。途中までマスクした本文を返すことはない。

テキストを分割して送る場合の注意: 分割位置をまたぐシークレットは検出できない。行や段落の区切りで分け、1 つの値が途中で切れないようにする。

## 処理時間と同時実行

- 数 KB のテキストは約 1 ミリ秒、通常の文章やコード 1 MB は数十ミリ秒で返る。
- 検出件数が極端に多い入力（1 MB 全体がトークンで埋まっているなど）は、1 件で 5 秒程度かかることがある。
- 同時に実行するスキャンは既定で 2 件。それを超えたリクエストは待機し（既定で 32 件まで）、待機枠も埋まると 503 を返す。
- クライアント側のタイムアウトは、サーバーの制限時間（既定 30 秒）より少し長くする。

## 検出できるもの・できないもの

検出できるもの（例）:

- 形式の決まった API トークンやアクセスキー（GitHub、AWS、Slack、Stripe など。ルールは 463 個）
- PEM 形式の秘密鍵
- ユーザー名とパスワードを含む接続 URI
- 上記が base64 などでエンコードされたもの

検出できないもの:

- 文章で書かれたパスワード（「パスワードは ... です」「password is ...」）
- 氏名、メールアドレス、電話番号、住所、クレジットカード番号などの個人情報
- 形式に特徴のない社内の機密情報

`detected` が `false` でも、テキストに機密情報が含まれていないことの保証にはならない。

その他の制約:

- 本文は 64 KiB ごとに分け、32 KiB ずつ重ねてスキャンする。32 KiB を超える単一のシークレットや、離れた場所の値を組み合わせて判定するルールは、検出できないことがある。
- 本文中の `betterleaks:allow` / `gitleaks:allow` コメントは無視する（検出は抑制されない）。
- 検出したシークレットが実際に有効かどうかの確認（外部サービスへの問い合わせ）は行わない。
- リクエストの内容やシークレットはサーバーのログに記録しない。
