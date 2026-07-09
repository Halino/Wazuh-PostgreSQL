# PostgreSQL log parser for Wazuh (bilingual EN/IT)

**Decoders** and **rules** so Wazuh can ingest and analyze **PostgreSQL** server logs — including servers running under a **non-English locale**.

## Why

When PostgreSQL runs with a localized `lc_messages` (for example `it_IT`), it writes log
severities and messages in that language: `FATALE` instead of `FATAL`, `ERRORE` instead of
`ERROR`, `permesso negato` instead of `permission denied`. The **stock Wazuh PostgreSQL
decoders match English only** and silently miss those lines — so a database with Italian
logs produces *no* PostgreSQL alerts at all.

This ruleset parses the standard log-line-prefix format and the rules match **both English
and Italian**, so authentication failures, destructive DDL and privilege changes are caught
regardless of the server locale.

## What's included

| File | Purpose |
|------|--------|
| `wazuh/decoders/postgresql_decoders.xml` | Parse `<timestamp> [<pid>] <LEVEL>: <message>` |
| `wazuh/rules/postgresql_rules.xml` | Detect auth failures, destructive DDL, privilege changes, FATAL/PANIC |
| `wazuh/ossec-postgresql.conf.snippet` | Example `localfile` + required `postgresql.conf` settings |
| `tests/sample_logs.txt` | English + Italian sample lines for `wazuh-logtest` |

## Rules

| Rule ID | Level | Detects | MITRE |
|---------|-------|---------|-------|
| 110000 | 0 | Grouping (any PostgreSQL log line) | — |
| 110001 | 7 | `FATAL`/`PANIC` (EN) · `FATALE`/`PANICO` (IT) | — |
| 110002 | 6 | Auth failed / permission denied (bilingual) | T1078 |
| 110003 | 4 | `ERROR` / `ERRORE` | — |
| 110004 | 11 | Destructive DDL: `DROP …` / `TRUNCATE` | T1485 |
| 110005 | 7 | Privilege / role change: `GRANT`/`REVOKE`/`CREATE ROLE` | T1098 |
| 110006 | 0 | Declass routine app-SQL noise (constraint/duplicate-key/autovacuum) | — |
| 110007 | 10 | Repeated auth failures = brute force (freq 5 / 120 s) | T1110 |

Rule IDs use a dedicated **110000-110007** block to avoid clashes with other rulesets.

### False-positive handling

- **110004 / 110005** use a negative lookahead so an echoed bind value or a `DETAIL:` /
  `Parameters:` line containing the word `DROP`/`GRANT` does **not** trigger — only the real
  statement does.
- **110006** declasses routine application SQL errors (FK/unique violations, deadlocks,
  autovacuum, syntax) to level 0 so app bugs don't flood the alert stream. Remove/tune it if
  you *do* want those.

## Deployment

### 1. Copy decoder and rules to the Wazuh manager

```bash
sudo cp wazuh/decoders/postgresql_decoders.xml /var/ossec/etc/decoders/
sudo cp wazuh/rules/postgresql_rules.xml       /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

### 2. Collect the PostgreSQL log

On the **database server** (Wazuh agent) — or the manager if PostgreSQL is local — add the
`localfile` block from `wazuh/ossec-postgresql.conf.snippet` to `ossec.conf`, pointing at
your PostgreSQL log path.

### 3. Make sure PostgreSQL logs what you want to detect

In `postgresql.conf`:

```conf
logging_collector = on
log_line_prefix   = '%m [%p] '   # timestamp + pid — matches the decoder
log_statement     = 'ddl'        # required for DROP/TRUNCATE/GRANT detection
# log_connections = on           # optional: source host on auth events
```

> The decoder keys on the `YYYY-MM-DD HH:MM:SS.mmm <tz> [<pid>] ` prefix. If your
> `log_line_prefix` differs substantially, adjust the decoder `prematch`/`regex`.

## Testing

```bash
/var/ossec/bin/wazuh-logtest
```

Paste, for example (Italian locale):

```
2026-07-06 09:14:02.001 CEST [3312] FATALE:  autenticazione con password fallita per l'utente "app"
```

Expected: decoder `postgresql-local`, rule **110002** (authentication_failed, T1078).

See `tests/sample_logs.txt` for the full English + Italian set.

## Compatibility

- Wazuh 4.x (uses `pcre2` decoders/fields).
- PostgreSQL 12+ (stderr logging with a timestamp + `[pid]` prefix). Tested against PG 17.

## License

MIT — see [LICENSE](LICENSE).
