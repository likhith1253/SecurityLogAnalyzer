# Security Log Analyzer (SLA)

A Java console application that scans web-server access logs for suspicious activity. It scores each source IP with a simple heuristic (status codes, sensitive paths, attack-pattern matches, IP geolocation), blacklists IPs above a threshold, and writes a forensic report. Log records are indexed in a hand-written Red-Black Tree, which backs the time-range and IP-trace queries.

It is a coursework / learning project (data structures + security concepts), not a production SIEM.

## Features

- Heuristic threat scoring with a configurable threshold (`threat.score.threshold` in `config.properties`)
- Pattern matching for configured "confidential data" requests (`confidential_data_requests.txt`)
- IP-prefix geolocation lookup from `geo_data.csv`
- Dynamic blacklist persisted to `blacklist.txt` (XOR-obfuscated; see limitations)
- Queries: trace one IP's history, list events in a time range, Red-Black Tree operations demo
- Role-based access: `AUDITOR` sees redacted IPs, `INVESTIGATOR` and `ADMIN` see full data
- Per-user query audit log (`query_log.txt`)
- Self-written Red-Black Tree (`com/sla/dsa/SelfBalancingSearchTree.java`): insert, delete, search, range query, predecessor/successor, validity check

## Requirements

JDK 11 or newer. No third-party dependencies.

## Build and run

```bash
mkdir out
javac -encoding UTF-8 -d out SecurityLogAnalyzer.java com/sla/*/*.java
java -cp out SecurityLogAnalyzer
```

Run it from the repository root: configuration files are read from the working directory. On start it generates a random sample `logs.txt` (regenerated on every run and potentially very large, so it is git-ignored).

Demo accounts shipped in `users.csv` (local demo only):

| user | password | role |
|---|---|---|
| `admin` | `adminpass` | ADMIN |
| `investigator` | `investigatorpass` | INVESTIGATOR |
| `auditor` | `auditorpass` | AUDITOR |

Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes. To add a user, generate a hash and append a line to `users.csv` (`username,hash,ROLE,userId`):

```bash
java -cp out com.sla.util.PasswordHasher 'a-new-password'
```

Entries with plaintext passwords are rejected at load time.

## Tests

```bash
mkdir out
javac -encoding UTF-8 -d out $(find . -name '*.java')
java -cp out com.sla.SlaTests
```

11 tests with a small dependency-free runner (`test/com/sla/SlaTests.java`): password hashing and login, query-log forging prevention, XOR cipher and blacklist persistence, Red-Black Tree invariants under random insert/delete, range queries, log parsing, and IP redaction by role. CI runs the same commands (`.github/workflows/ci.yml`).

## Documentation

[Architecture](docs/architecture.md) | [Features](docs/features.md) | [Setup](docs/setup.md) | [Log processing flow](docs/log_processing_flow.md) | [Usage examples](docs/usage_examples.md) | [Evaluation](docs/evaluation.md) | [Deployment notes](docs/deployment.md)

## Known limitations

- The blacklist file is protected only by a repeating-key XOR (obfuscation, not encryption). The default key is in the source; set the `SLA_CIPHER_KEY` environment variable to use another one.
- Log records are ordered in the tree by timestamp only, so a lookup by timestamp returns one of possibly several records sharing that timestamp.
- The login prompt is a local console prompt; there is no network service, session handling or lockout beyond 3 attempts per start.

## License

[MIT](LICENSE) (c) Likhith Ponnada
