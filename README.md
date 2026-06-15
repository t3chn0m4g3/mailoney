# Mailoney

Mailoney is a low-interaction SMTP honeypot. It accepts SMTP conversations,
captures authentication attempts, records submitted messages, and writes
Logstash-friendly JSON Lines events. It runs without a database.

## What It Does

- Simulates SMTP on port `25`, Submission on `587`, and SMTPS on `465`.
- Supports `EHLO`, `HELO`, `MAIL FROM`, `RCPT TO`, `DATA`, `AUTH PLAIN`,
  `AUTH LOGIN`, `STARTTLS`, `RSET`, `NOOP`, `VRFY`, and `QUIT`.
- Logs sessions, credentials, mails, and rate-limit blocks to `log/log.json`.
- Stores full `.eml` files and MIME attachments when enabled.
- Generates a self-signed TLS certificate under `log/tls` and reuses it.
- Limits message floods by source IP and envelope sender.

The honeypot is meant for detection and analysis. Keep it isolated from real
mail infrastructure and treat captured mail bodies and attachments as hostile.

## Quick Start

Local development:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[test]"
python main.py
```

Docker Compose:

```bash
mkdir -p log
docker compose up -d
docker compose logs -f mailoney
```

Compose publishes `25`, `465`, and `587`, runs the container read-only, and bind
mounts `./log` to `/app/log`. Logs, stored mail, attachments, rate-limit state,
and generated TLS certificates are written there. If you change
`mailoney.toml`, either rebuild the image or uncomment the config bind mount in
`docker-compose.yml`.

## Testing A Running Honeypot

`smoke_test.py` is a manual SMTP smoke test. It uses Python's standard library
and checks plain SMTP, STARTTLS, and implicit TLS on the default ports.

```bash
python smoke_test.py
```

By default it connects to `127.0.0.1` on ports `25`, `587`, and `465`. Override
the target when you run Mailoney on high local test ports:

```bash
MAILONEY_TEST_SMTP_PORT=2525 \
MAILONEY_TEST_SUBMISSION_PORT=2587 \
MAILONEY_TEST_SMTPS_PORT=2465 \
python smoke_test.py
```

Automated tests are separate:

```bash
.venv/bin/python -m pytest
```

## Configuration

Mailoney loads settings in this order:

```text
defaults < mailoney.toml < MAILONEY_* environment variables < CLI flags
```

Use `--config /path/to/mailoney.toml` for a non-default config file.

The shipped `mailoney.toml` is the recommended starting point:

```toml
[server]
server_name = "mail01.localdomain"
conn_timeout = 30
max_connections = 100
max_mail_body_bytes = 10485760

[[server.listeners]]
name = "smtp"
bind_ip = "0.0.0.0"
port = 25
starttls = true
implicit_tls = false

[[server.listeners]]
name = "submission"
bind_ip = "0.0.0.0"
port = 587
starttls = true
implicit_tls = false

[[server.listeners]]
name = "smtps"
bind_ip = "0.0.0.0"
port = 465
starttls = false
implicit_tls = true

[logging]
log_file = "log/log.json"
log_level = "INFO"

[storage]
mail_dir = "log/mails"
save_mail_bodies = true
save_attachments = true

[tls]
enabled = true
auto_generate = true
cert_file = "log/tls/server.crt"
key_file = "log/tls/server.key"

[rate_limit]
enabled = true
window_seconds = 3600
block_seconds = 3600
max_messages_per_ip = 100
max_messages_per_sender = 25
log_block_once = true
state_file = "log/rate_limit_state.json"
```

### Server Settings

| Setting | Meaning |
| --- | --- |
| `server_name` | SMTP banner name and TLS certificate CN/SAN. The default `mail01.localdomain` looks like a small internal Linux mail host; avoid product names and container hostnames. |
| `conn_timeout` | Per-connection inactivity timeout in seconds. `0` disables it. |
| `max_connections` | Maximum concurrent client handlers per listener. |
| `max_mail_body_bytes` | Maximum bytes accepted in SMTP `DATA`. Also advertised as SMTP `SIZE`. |

### Listener Settings

Listeners are configured in TOML with `[[server.listeners]]`. Environment
variables are intended for scalar settings; use TOML for multiple listeners.

| Setting | Meaning |
| --- | --- |
| `name` | Short name written to `listener.name` in JSON logs. |
| `bind_ip` | Address to bind, for example `0.0.0.0`, `127.0.0.1`, or `::`. |
| `port` | TCP port for this listener. Defaults are `25`, `587`, and `465`. |
| `starttls` | Advertise and accept SMTP `STARTTLS` on a plain TCP listener. Typical for `25` and `587`. |
| `implicit_tls` | Wrap the TCP connection in TLS before sending the SMTP banner. Typical for SMTPS on `465`. |

Use `starttls = true` with `implicit_tls = false` for normal SMTP/Submission
STARTTLS. Use `implicit_tls = true` with `starttls = false` for port `465`.

Legacy single-listener settings such as `bind_ip`, `bind_port`,
`MAILONEY_BIND_IP`, `MAILONEY_BIND_PORT`, `--ip`, and `--port` are still
accepted for old deployments, but they are hidden from the recommended config.

### TLS Settings

| Setting | Meaning |
| --- | --- |
| `enabled` | Enables STARTTLS and implicit TLS listeners. If disabled, implicit TLS listeners are skipped. |
| `auto_generate` | Generates a self-signed certificate when `cert_file` or `key_file` is missing. |
| `cert_file` | Certificate path. Defaults to `log/tls/server.crt`. |
| `key_file` | Private key path. Defaults to `log/tls/server.key`; created with restrictive permissions. |

The generated certificate uses `server.server_name` as CN/SAN and is persisted
under `log/tls`. Delete the files if you intentionally want a new certificate.

### Logging Settings

| Setting | Meaning |
| --- | --- |
| `log_file` | JSONL event file. Defaults to `log/log.json`. |
| `log_level` | Process log level, for example `INFO` or `DEBUG`. |

`log/log.json` is newline-delimited JSON: one complete object per line, not a
JSON array. The file is opened on every write so external `logrotate` can rotate
it. Fields with `null`, empty strings, empty lists, or empty objects are omitted;
numeric `0` and boolean `false` are kept.

### Storage Settings

| Setting | Meaning |
| --- | --- |
| `mail_dir` | Base directory for stored `.eml` files and attachments. |
| `save_mail_bodies` | Writes complete DATA content as `.eml` when true. Metadata is still parsed when false. |
| `save_attachments` | Extracts MIME attachments when true. |

Mail files are stored as:

```text
<mail_dir>/<YYYY-MM-DD>/<src_ip>/<session_id>/<message_id>.eml
```

Attachments are stored as:

```text
<mail_dir>/<YYYY-MM-DD>/<src_ip>/<session_id>/attachments/
```

### Rate-Limit Settings

| Setting | Meaning |
| --- | --- |
| `enabled` | Enables IP and sender rate limiting. |
| `window_seconds` | Sliding-window length for counting accepted messages. |
| `block_seconds` | How long an IP or sender stays blocked after exceeding a limit. |
| `max_messages_per_ip` | Accepted messages per source IP within the window. |
| `max_messages_per_sender` | Accepted messages per envelope sender within the window. |
| `log_block_once` | Logs only the first block event per block period when true. |
| `state_file` | Persists block state across restarts. |

Blocked mail is rejected and not stored. The first block event is written as
`event.type = "rate_limit_block"`.

## Environment Variables

Most scalar settings can be overridden with `MAILONEY_*` variables. Common
examples are listed in `.env.example`:

| Variable | Example |
| --- | --- |
| `MAILONEY_SERVER_NAME` | `mail01.localdomain` |
| `MAILONEY_CONN_TIMEOUT` | `30` |
| `MAILONEY_MAX_CONNECTIONS` | `100` |
| `MAILONEY_MAX_MAIL_BODY_BYTES` | `10485760` |
| `MAILONEY_LOG_FILE` | `log/log.json` |
| `MAILONEY_LOG_LEVEL` | `INFO` |
| `MAILONEY_MAIL_DIR` | `log/mails` |
| `MAILONEY_SAVE_MAIL_BODIES` | `true` |
| `MAILONEY_SAVE_ATTACHMENTS` | `true` |
| `MAILONEY_TLS_ENABLED` | `true` |
| `MAILONEY_TLS_AUTO_GENERATE` | `true` |
| `MAILONEY_TLS_CERT_FILE` | `log/tls/server.crt` |
| `MAILONEY_TLS_KEY_FILE` | `log/tls/server.key` |
| `MAILONEY_RATE_LIMIT_ENABLED` | `true` |
| `MAILONEY_RATE_LIMIT_WINDOW_SECONDS` | `3600` |
| `MAILONEY_RATE_LIMIT_BLOCK_SECONDS` | `3600` |
| `MAILONEY_RATE_LIMIT_MAX_MESSAGES_PER_IP` | `100` |
| `MAILONEY_RATE_LIMIT_MAX_MESSAGES_PER_SENDER` | `25` |
| `MAILONEY_RATE_LIMIT_LOG_BLOCK_ONCE` | `true` |
| `MAILONEY_RATE_LIMIT_STATE_FILE` | `log/rate_limit_state.json` |

Run `python main.py --help` for CLI overrides.

## JSON Events

Every event includes session context such as:

- `event.type`: `mail`, `session`, `auth`, or `rate_limit_block`
- `timestamp`, `session_id`, `session_start`, `session_end`,
  `session_duration`
- `src_ip`, `src_port`, `dest_ip`, `dest_port`
- `server_name`
- `listener.name`, `listener.port`, `listener.tls_mode`
- `tls.used` and TLS details when TLS was negotiated
- `smtp_input`, containing SMTP commands line by line without DATA body content

Mail events add flat `mail.*` fields such as envelope sender, recipients,
headers, subject, sending mailserver, stored `.eml` path, and truncation status.
Attachment metadata is written as `attachment.*` fields. Auth events add
`auth.method`, `auth.raw`, `auth.username`, `auth.password`, and decode errors
when present.

## Operating Tasks

- Set `server_name` before deployment so the banner and TLS certificate look
  plausible for your environment.
- Keep `./log` persistent and writable by the container user.
- Rotate `log/log.json` with `logrotate`; Mailoney does not rotate it itself.
- Review and archive or delete stored `.eml` files and attachments according to
  your retention policy.
- Treat attachments as untrusted malware samples.
- Rebuild the Docker image after changing the baked-in `mailoney.toml`, or mount
  the config file read-only in Compose.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[test]"
pytest
docker compose config
docker build -t mailoney:test .
```
