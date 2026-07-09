# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Initial release: bilingual (English + Italian) PostgreSQL decoders and rules for Wazuh.
- **Decoder `postgresql-local`**: parses the `<timestamp> <tz> [<pid>] <LEVEL>: <message>` log-line-prefix format.
- **Rules 110000-110007**:
  - `110001` FATAL / PANIC (EN) · FATALE / PANICO (IT).
  - `110002` authentication failed / permission denied, bilingual (T1078).
  - `110003` ERROR / ERRORE.
  - `110004` destructive DDL `DROP`/`TRUNCATE` (T1485), with a negative lookahead so echoed
    bind values / `DETAIL:` lines don't false-positive.
  - `110005` privilege / role changes `GRANT`/`REVOKE`/`CREATE ROLE` (T1098).
  - `110006` declass routine application-SQL noise (FK/unique violations, deadlocks,
    autovacuum, syntax) to level 0.
  - `110007` brute-force correlation on repeated auth failures (T1110).
- Dedicated rule ID block **110000-110007** to avoid clashes with other rulesets.
- `tests/sample_logs.txt` with English and Italian sample lines.
- `wazuh/ossec-postgresql.conf.snippet` with `localfile` and required `postgresql.conf` settings.
- MIT LICENSE, .gitignore.
