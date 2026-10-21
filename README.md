# Ruleas 1.0.0

[rulea](https://github.com/tanuki276/rulea) の評価エンジンに FastAPI / Uvicorn、PostgreSQL、認証付き管理画面を追加したサーバーです。rulea 本体のコードは変更していません。既存の `ruleas check` / `ruleas test` も利用できます。

## 起動

Python 3.9 以降。PostgreSQL を用意し、次の手順で初期化してください。

```sh
pip install .
export POSTGRES_PASSWORD='replace-with-a-long-random-password'
docker compose up -d db
export RULEAS_DATABASE_URL="postgresql+psycopg://ruleas:${POSTGRES_PASSWORD}@localhost:5432/ruleas"
export RULEAS_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
ruleas init-db
ruleas create-user admin --role admin
# ローカル HTTP 開発時のみ。HTTPS 運用では true（既定値）を使用。
export RULEAS_COOKIE_SECURE=false
ruleas serve --host 127.0.0.1 --port 8000
```

`http://127.0.0.1:8000/` が管理画面、`/docs` が OpenAPI です。ユーザーのパスワードは対話入力（12文字以上）。本番は HTTPS リバースプロキシ配下で起動し、SECRET_KEY は永続的な秘密値として保持してください。`init-db` は新規スキーマ用の冪等な初期化です。将来のスキーマ変更には別途マイグレーションが必要です。

## 保存と権限

1件の「ルール」は `.rulea` 文書単位です。文書内に複数の rule / ruleset を記述できます。namespace はソースから取得し、ソース内の policy version と DB の連番 version は独立しています。タグ・有効無効・更新日時・ソース・履歴を保存します。削除は論理削除で、履歴と監査は保持し、rollback で復元できます。rollback 自体も新しいバージョンになります。import を使用する外部モジュールのアップロードには未対応です。

管理者は編集、削除、復元、ユーザー作成、API キー管理、監査ログ閲覧が可能です。閲覧者はルール・履歴閲覧とテスト実行が可能です。API キーは作成した管理者の権限を継承し、一度だけ表示、DB には SHA-256 ハッシュのみを保存します。パスワードは salt 付き scrypt、管理画面は署名付き HttpOnly セッションと CSRF トークンを使用します。

## API

ログイン: `POST /v1/login` に `username` / `password`。管理画面の変更系リクエストには返された `csrf_token` を `X-CSRF-Token` ヘッダーで指定します。API クライアントは `Authorization: Bearer rs_...` を使用します。

| メソッド | パス | 内容 |
|---|---|---|
| GET | `/health` | DB 接続を含むヘルスチェック |
| POST | `/v1/decide` | Decision をそのまま返す |
| POST | `/v1/check` | allowed / reason / decision |
| GET, POST | `/v1/rules` | 一覧・作成 |
| GET, PUT, DELETE | `/v1/rules/{id}` | 取得・更新・削除 |
| GET | `/v1/rules/{id}/source` | .rulea ダウンロード |
| GET | `/v1/rules/{id}/versions` | 履歴 |
| POST | `/v1/rules/{id}/rollback/{version}` | 復元 |
| POST | `/v1/users` | ユーザー作成（role: admin / viewer） |
| GET, POST | `/v1/api-keys` | キー一覧・発行 |
| DELETE | `/v1/api-keys/{id}` | キー失効 |
| GET | `/v1/audit-logs?limit=100` | 最新監査ログ（最大1000件） |
| GET, POST | `/v1/me`, `/v1/logout` | セッション情報・ログアウト |

ルール作成例:

```json
{"name":"access","source":"namespace access\nrule adult:\n    when: age >= 18\n    reason: \"Adults only\"\n","enabled":true,"tags":["auth"]}
```

更新時には上記に `expected_version`（現在の DB version）を追加します。競合は HTTP 409。実行例:

```sh
curl http://127.0.0.1:8000/v1/decide \
  -H "Authorization: Bearer $RULEAS_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"policy_id":1,"rule":"access.adult","context":{"age":20}}'
```

`ALLOW / DENY / NOT_APPLICABLE / ERROR`、reason、trace、子 Decision、policy hash、engine version を返します。無効文書は NOT_APPLICABLE。未知の rule の挙動も rulea に従います。実行結果は actor・文書 ID・rule 名・日時・結果・hash・engine version とともに DB へ保存され、監査保存に失敗した場合はリクエストも失敗します。context やパスワード、キーの平文は監査に保存しません。

## 検証

```sh
pip install '.[test]'
pytest -q
python -m build
```

サーバーテストは隔離された SQLite を使用します。本番向け PostgreSQL テストは CI の PostgreSQL サービスで実施します。管理画面はルール編集、有効無効、履歴復元、JSON context テスト、Decision / trace 表示、キーとユーザーの作成、監査閲覧を提供します。テスト実行は保存済みソースを対象にします。
