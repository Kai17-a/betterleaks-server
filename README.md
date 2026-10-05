# betterleaks-server

[betterleaks](https://github.com/betterleaks/betterleaks) v1.9.0 を Go パッケージとして組み込んだ、ローカル用のシークレット検出 API サーバー。LLM に送る前のテキストからシークレットを取り除く前段フィルターとして使える。

## 起動

```sh
go run .                       # 127.0.0.1:8080 で待ち受け
go run . -addr 127.0.0.1:9000  # アドレス変更
```

| 設定 | 既定値 | 説明 |
| --- | --- | --- |
| `-addr` / `BETTERLEAKS_SERVER_ADDR` | `127.0.0.1:8080` | 待ち受けアドレス（フラグが優先） |
| `-max-body-bytes` | `1048576`（1 MiB） | `POST /v1/scan` のボディ上限 |
| `-max-concurrent-scans` | `2` | 同時に実行するスキャン数。超過分は待機する |
| `-max-queued-scans` | `32` | 待機できるリクエスト数。超過分は 503（負の値で待機なし） |
| `-scan-timeout` | `30s` | 1 回のスキャンの制限時間（待機時間を含む） |
| `-allowed-hosts` | なし | `Host` / `Origin` で追加で受け付けるホスト名や IP（カンマ区切り） |

認証はないため、ループバック以外にバインドすると警告ログを出す。

### Docker

GitHub Actions の `docker` ワークフローを手動で実行すると、テストのあと `linux/amd64` と `linux/arm64` のイメージをビルドし、`ghcr.io/kai17-a/betterleaks-server` に公開する。push やプルリクエストでは実行されない。

```sh
gh workflow run docker.yml --ref main
```

付くタグは、実行時に選んだブランチやタグで決まる。

| 実行対象 | タグ |
| --- | --- |
| ブランチ（例: `main`） | `main`、`sha-<コミット>` |
| 安定版のタグ（例: `v1.2.3`） | `1.2.3`、`1.2`、`latest`、`sha-<コミット>` |
| プレリリースのタグ（例: `v1.2.3-rc.1`） | `1.2.3-rc.1`、`sha-<コミット>` |

イメージは既定で非公開のため、取得には `read:packages` 権限を持つトークンでの `docker login ghcr.io` が必要（またはパッケージを公開設定にする）。

```sh
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/kai17-a/betterleaks-server:main
```

- コンテナ内では `0.0.0.0:8080` で待ち受ける（`BETTERLEAKS_SERVER_ADDR` で変更可）。ホスト側の公開は上のように `127.0.0.1` に限定する。
- `Host` の検証はコンテナでも有効。ホストから `localhost:8080` で呼ぶ分には追加設定は不要だが、別のコンテナからサービス名で呼ぶ場合は `-allowed-hosts scanner` のように名前を許可する。
- Kubernetes の HTTP プローブは Pod の IP 宛てになるため、`httpHeaders` で `Host: localhost` を付ける。
- `Host` の検証は認証ではない。ネットワーク越しに使う場合は、到達範囲の制限や認証付きのプロキシを別途用意する。
- 最悪入力でのメモリ消費（下記）に合わせて、コンテナのメモリ上限を設定する。
- 実行ユーザーは非 root（UID 65532）。

### スキャンの仕組みと上限値

本文は 64 KiB の区画に分け、32 KiB ずつ重ねてスキャンする。ライブラリの処理コストは 1 回に渡すテキスト内の検出件数の二乗と「検出数 × 行の長さ」で増えるため、区画に分けることで行の長さに関係なく上限が決まる。改行のない長い段落やミニファイ済みのファイルもそのまま受け付ける。

- 区画の境界をまたぐシークレットは、重なり部分で検出する。重なりは、マッチとルールが参照する前後の文脈（最大で前後 8 KiB ずつ）が 1 つの区画に収まる大きさにしている。
- 本文全体を 1 回でスキャンした場合と結果が完全に一致する保証はない。32 KiB を超える単一のシークレット（巨大な鍵ブロックなど）や、離れた場所の部品を組み合わせるルールは、境界で分断されると検出できないことがある。
- 既定値での実測: 4 KB のプロンプトで約 1 ミリ秒、通常の文章やコード 1 MB で数十ミリ秒。上限いっぱいの悪意ある入力（1 MB 全体がトークン）は 1 件で約 5 秒、最大メモリ約 300 MB。同じ入力を 4 件同時に送ると、2 件ずつ処理して全体で約 11 秒、最大メモリ約 830 MB。

### Host / Origin の検証

DNS リバインディングなどブラウザ経由のアクセスを防ぐため、`Host` と `Origin`（付いている場合）が `localhost`、ループバック IP、`-allowed-hosts` のいずれでもないリクエストは 403 で拒否する。`-addr` に特定のホストを指定した場合はそのホストも許可される。`0.0.0.0` のようなワイルドカードにバインドする場合は `-allowed-hosts` の指定が必要。

## API

呼び出し側（AI エージェントなど）に渡すための詳細な仕様は [docs/API.md](docs/API.md) にある。

### `GET /healthz`

```json
{"status":"ok"}
```

### `GET /v1/rules`

読み込まれている検出ルール（ID 昇順）。

```json
{"rules":[{"id":"github-pat","description":"...","tags":[]}],"count":463}
```

### `POST /v1/scan`

`Content-Type: application/json` が必須。

| フィールド | 型 | 説明 |
| --- | --- | --- |
| `content` | string | 必須。スキャン対象の文字列 |
| `path` | string | 任意。パス依存のルール・許可リストに使う仮想ファイル名。`.` に正規化される値（`.`、`a/..` など）は不可 |
| `redact` | bool | 任意。既定は `true` で、`findings` の `secret` と `match` を `REDACTED` に置換する。`false` で生の値を返す |

```sh
curl -s -X POST http://127.0.0.1:8080/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"content":"token = \"...\"","path":"conf/app.env","redact":true}'
```

```json
{
  "detected": true,
  "redacted_content": "token = \"[REDACTED:github-pat]\"",
  "findings": [
    {
      "rule_id": "github-pat",
      "description": "...",
      "start_line": 1,
      "end_line": 1,
      "start_column": 10,
      "end_column": 49,
      "match": "REDACTED",
      "secret": "REDACTED",
      "file": "conf/app.env",
      "entropy": 5.17,
      "confidence": "high",
      "tags": [],
      "fingerprint": "conf/app.env:github-pat:1"
    }
  ],
  "count": 1
}
```

| フィールド | 説明 |
| --- | --- |
| `detected` | シークレットが 1 件以上見つかったか |
| `redacted_content` | 検出箇所を `[REDACTED:<ルールID>]` に置き換えた本文。`redact` の値に関係なく常にマスクされる |
| `findings` | 検出の一覧。行は 1 始まり、列は 1 始まりの**バイト**位置（終端を含む）で、本文全体に対する位置 |
| `confidence` | ルールの確度（`high` / `medium` / `low`。未設定のルールは空文字） |

`redacted_content` のマスクは次のルールで行う。

- ルールがマッチした範囲全体を置き換える。たとえばパスワード入りの接続 URI は URI ごと置き換わる（同じ URI 内の別の認証情報を残さないため）。
- base64 などでエンコードされたシークレットは、エンコード済みの部分を置き換える。
- 複数の部品で成立するルール（API キーとアプリケーション ID の組など）は、部品もそれぞれ置き換える。
- 検出したシークレットと同じ文字列（8 バイト以上）が本文の別の場所にあれば、そこも置き換える。

パスだけで判定するルールに `path` が一致した場合は、`detected` が `true` になるが本文に置き換える箇所はない。スキャンがタイムアウトやキャンセルで終わった場合は 503 を返し、途中までマスクした本文は返さない。

エラーは `{"error":"..."}` 形式。

| ステータス | 条件 |
| --- | --- |
| 400 | 不正な JSON、未知のフィールド、`content` が空、`path` が不正 |
| 403 | `Host` または `Origin` が許可されていない |
| 413 | ボディが上限超過 |
| 415 | `Content-Type` が `application/json` でない |
| 503 | 待機数の上限超過（`Retry-After` 付き）、スキャンのタイムアウト、リクエストのキャンセル |

未定義のパス（404）と不正なメソッド（405）は `net/http` 標準のプレーンテキスト応答になる。

## 仕様メモ

- betterleaks のデフォルト設定（組み込みルール）を使用。シークレットの有効性検証（外部への HTTP 通信）は行わない。
- リクエスト本文やシークレットはログに出力しない。アクセスログはメソッド、パス、ステータス、所要時間のみ。
- 本文は信頼できない入力として扱うため、`betterleaks:allow` / `gitleaks:allow` コメントによる検出の抑制は無効にしている。
- 検出対象はトークンや鍵など機械的な形を持つシークレット。文章で書かれたパスワード（「パスワードは ... です」）や個人情報は検出しない。
- `"redact": false` を指定すると、レスポンスの `findings` に検出したシークレットがそのまま含まれる。
- `path` はパス依存のルールや許可リストの判定に使われるため、検出結果に影響する。信頼できない送信者が指定した `path` をそのまま渡さない。

## 開発

```sh
go test -race ./...
```
