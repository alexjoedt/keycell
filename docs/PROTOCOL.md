# keycell wire protocol

Version 1. This is the contract between `keycelld` and anything that talks to it: the bundled `keycell` CLI and `pkg/keycell`, but also your own scripts and tools. Everything here is implementable with a socket, a JSON library and a line reader; `nc -U` is enough to try it by hand.

## Transport and framing

- Unix domain socket at `$XDG_RUNTIME_DIR/keycell/keycell.sock` (directory `0700`, socket `0600`), overridable in the configuration. There is no `/tmp` fallback; without `XDG_RUNTIME_DIR` the daemon refuses to start.
- The daemon accepts connections only from its own UID (`SO_PEERCRED`).
- NDJSON: one JSON object per line, terminated by `\n`. Values that could contain newlines (`value`, `identity`) are base64, so a line is never split.
- A line is at most 1,463,640 bytes (the base64 form of a 1 MiB value plus 64 KiB for name, kind, attributes and framing). A longer line is a framing error; the daemon answers with `PROTOCOL` and closes the connection.
- A connection may carry any number of requests. Responses come back in request order. `id` exists only for the client's convenience and is echoed untouched; the daemon never interprets it.

## Messages

Request:

```json
{"id": <any JSON value except null>, "method": "<name>", "params": {...}}
```

`params` may be omitted for methods without parameters. Unknown top-level fields are ignored so additive extensions cannot break older daemons; unknown fields *inside* `params` are rejected with `INVALID_ARGUMENT` so a parameter is never silently dropped.

Response, exactly one of `result` and `error`:

```json
{"id": <echoed>, "result": {...}}
{"id": <echoed>, "error": {"code": "<CODE>", "message": "<text>"}}
```

A request whose `id` cannot be parsed, is missing or is `null` is answered with `"id": null`.

## Methods

`value` and `identity` are base64 (standard alphabet, with padding). Timestamps are RFC 3339 in UTC.

### `status`

Params: none. Always allowed, also while locked.

```
→ {"id":1,"method":"status"}
← {"id":1,"result":{"protocol":1,"locked":false,"locks_at":"2026-09-20T20:00:00Z"}}
```

`protocol` is the protocol version this daemon speaks. `locks_at` is present while unlocked with auto-lock active; absent when locked or when auto-lock is off.

### `unlock`

Params: `identity` (base64 of the age X25519 identity, i.e. the `AGE-SECRET-KEY-1...` line), `for` (optional, seconds until auto-lock; `0` disables auto-lock for this session; absent means the daemon's configured default).

The client decrypts `identity.age` itself and hands over the plaintext identity; the daemon never sees a passphrase (ADR 0007). Unlocking an already unlocked daemon replaces the identity and restarts the auto-lock timer.

```
→ {"id":2,"method":"unlock","params":{"identity":"QUdFLVNFQ1JFVC1LRVktMS4uLg==","for":3600}}
← {"id":2,"result":{}}
```

Errors: `INVALID_ARGUMENT` if the identity does not parse or does not open the vault.

### `lock`

Params: none. Waits for in-flight requests, zeroes the identity, then answers. Locking a locked daemon succeeds.

```
→ {"id":3,"method":"lock"}
← {"id":3,"result":{}}
```

### `store`

Params: `name`, `kind`, `attributes` (optional object of string to string), `value` (base64). Upsert: an existing secret of that name is replaced entirely, `created` is kept, `updated` is set to now.

```
→ {"id":4,"method":"store","params":{"name":"git/github.com","kind":"git-credential","attributes":{"host":"github.com","username":"alex"},"value":"Z2hwX3NlY3JldA=="}}
← {"id":4,"result":{}}
```

Errors: `LOCKED`, `INVALID_ARGUMENT` (name, kind, attributes or value violate the rules below).

### `get`

Params: `name`.

```
→ {"id":5,"method":"get","params":{"name":"git/github.com"}}
← {"id":5,"result":{"name":"git/github.com","kind":"git-credential","attributes":{"host":"github.com","username":"alex"},"created":"2026-09-20T12:00:00Z","updated":"2026-09-20T12:00:00Z","value":"Z2hwX3NlY3JldA=="}}
```

Errors: `LOCKED`, `NOT_FOUND`, `INVALID_ARGUMENT`.

### `list`

Params, all optional: `kind` (exact match), `prefix` (name starts with), `attributes` (every given key must exist with exactly that value). Filters combine with AND. Result: an array of secrets without `value`, sorted by name. An empty match is `[]`, not an error.

```
→ {"id":6,"method":"list","params":{"kind":"git-credential","attributes":{"host":"github.com"}}}
← {"id":6,"result":[{"name":"git/github.com","kind":"git-credential","attributes":{"host":"github.com","username":"alex"},"created":"2026-09-20T12:00:00Z","updated":"2026-09-20T12:00:00Z"}]}
```

Errors: `LOCKED`, `INVALID_ARGUMENT`.

### `delete`

Params: `name`.

```
→ {"id":7,"method":"delete","params":{"name":"git/github.com"}}
← {"id":7,"result":{}}
```

Errors: `LOCKED`, `NOT_FOUND`, `INVALID_ARGUMENT`.

There is nothing else. `exists` is `list` with a filter; `rename`, `export` and `import` are CLI commands composed from `list`, `get`, `store` and `delete`.

## Error codes

| Code | Meaning | Typical client reaction |
|---|---|---|
| `PROTOCOL` | Invalid JSON, missing or null `id`, unknown method, line too long | Bug in the client; the connection may be closed |
| `INVALID_ARGUMENT` | Name, kind, attribute or value violates the rules; identity does not open the vault; unknown or mistyped param field | Fix the input |
| `NOT_FOUND` | No secret of that name | Treat as absent |
| `LOCKED` | Daemon holds no identity | Tell the user to run `keycell unlock`; never prompt from an integration |
| `INTERNAL` | Daemon-side failure (vault I/O, decryption) | Report; check `keycelld` logs |

`message` is for humans and may change; `code` is stable.

## Names, kinds, attributes, values

- **Name**: non-empty, at most 256 bytes, valid UTF-8, no control characters, no leading or trailing whitespace. `/` has no meaning to the daemon; `git/github.com` is a convention, not a hierarchy. The namespace is flat.
- **Kind**: `[a-z0-9-]`, 1 to 64 characters. The daemon does not know kinds; they are labels integrations agree on (see `docs/KINDS.md`).
- **Attribute keys**: like kind. **Attribute values**: like name.
- **Value**: at most 1 MiB (1,048,576 bytes) before base64. Arbitrary bytes.

Violations are `INVALID_ARGUMENT`.

## Versioning

There is no version field in requests and no handshake. Changes to version 1 are additive only: new methods, new optional fields. A client learns the daemon's version from `status.protocol`. A breaking change becomes `protocol: 2` on a different socket path, so old and new never meet on one socket (ADR 0008).

## Trying it by hand

```sh
printf '%s\n' '{"id":1,"method":"status"}' | nc -U "$XDG_RUNTIME_DIR/keycell/keycell.sock"
```

`scripts/protocol-smoke.sh` walks all seven methods this way, with `nc`, `jq` and the `age` CLI only; read it as a worked example when writing a client in another language.

The bundled client is documented in [CLI.md](CLI.md); it maps the error codes above to fixed messages and exit codes.
