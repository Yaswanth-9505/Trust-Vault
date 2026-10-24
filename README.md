# TrustVault

Secure document sharing with a real audit trail. A document can be reached only by someone it was granted to, by name. Taking access away works on the next request. Every access is recorded, including the refused ones, in a hash-chained log that cannot be quietly altered.

**Live demo:** `https://Yaswanth9505.pythonanywhere.com`

**Stack:** Python 3.11+ · Flask · SQLite · `cryptography` (AES-256-GCM). Three dependencies. No front-end framework.

## Demo accounts

| Role | Email | Password | What to try |
|---|---|---|---|
| Administrator | `admin@trustvault.test` | `Admin-Demo-2026!` | Alerts, audit trail, users. You **cannot** open anyone's documents. |
| Owner | `olivia@trustvault.test` | `Olivia-Demo-2026!` | Owns the salary letters, financials and partner contract. Share, revoke, view the custody record. |
| Owner | `oscar@trustvault.test` | `Oscar-Demo-2026!` | Owns the engineering and audit papers, plus private notes nobody else can read. |
| Viewer | `vera@trustvault.test` | `Vera-Demo-2026!` | Can read her own salary letter, edit the Q3 financials, and read the audit papers. |
| Viewer | `victor@trustvault.test` | `Victor-Demo-2026!` | Can read his own salary letter and edit the bridge drawings. Nothing else. |
| Viewer (external) | `ext@partner.test` | `Partner-Demo-2026!` | An outside partner. Can read the partner contract and nothing else. |

Demo accounts cannot change their own password while `TV_DEMO_MODE=1`, so one person cannot lock the others out. To restore the demo data, run `python -m scripts.seed --reset`.

## Roles

| | Administrator | Owner | Viewer |
|---|---|---|---|
| Upload new documents | – | ✓ | – |
| Open or download a document | only if granted | own, or if granted | only if granted |
| Edit a document / upload a new version | only with an edit grant | own, or with an edit grant | only with an edit grant |
| Share, revoke, delete, restore, see a document's record | – | own documents only | – |
| Search the people directory | ✓ | ✓ | – |
| Manage accounts, see all audit records and alerts | ✓ | – | – |
| See document **metadata** for everything | ✓ | – | – |
| Transfer ownership (for leavers) | ✓, never to themselves | – | – |

The full permission model is explained in [WRITEUP.md](WRITEUP.md), the threats and controls in [THREATS.md](THREATS.md), and every endpoint with who may call it in [API.md](API.md).

## Run it locally (from a clean clone)

```bash
git clone https://github.com/Yaswanth-9505/Trust-Vault.git
cd trustvault
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m scripts.seed               # creates instance/trustvault.db with demo data
python wsgi.py                       # http://127.0.0.1:5000
```

In development the app generates its keys into `instance/dev_keys.json`. In production (`TV_ENV=production`) it refuses to start unless `TV_MASTER_KEY` and `TV_AUDIT_KEY` are set.

## Tests

```bash
python -m unittest discover -s tests -t . -v    # 85 tests, about 10 seconds
python -m scripts.mutation_check                # removes 28 security checks one at a time
```

The mutation check copies the repo, disables one check, such as the `authorize()` line in the download handler, and confirms that the suite fails. Expect `28/28 mutants killed`. Test names map to the IDs in THREATS.md.

## Database

The schema is in [`app/schema.sql`](app/schema.sql). It is applied automatically the first time the app starts against an empty database. The seed script is `scripts/seed.py`.

**Backup:**

```bash
sqlite3 "$TV_DATABASE_PATH" ".backup backup-$(date +%F).db"
```

Store the backup and `TV_MASTER_KEY` separately. Neither one is useful without the other.

## Deploy

Full click-by-click instructions for PythonAnywhere (free, HTTPS) are in **[DEPLOY.md](DEPLOY.md)**, including a troubleshooting table. After deploying, prove the live site holds:

```bash
python -m scripts.check_live https://Yaswanth9505.pythonanywhere.com
```

A `Dockerfile` is included for container hosts.

## Verify the audit trail

- In the app: **Administration → Alerts** shows the integrity status of the whole chain.
- From a console: `python -m scripts.verify_audit`
- Against an earlier export: `python -m scripts.verify_audit --against export.jsonl`

## Hand-in map

| Required | Where |
|---|---|
| Threat model | [THREATS.md](THREATS.md) |
| AI usage log | [PROMPTS.md](PROMPTS.md) |
| Tests | [`tests/`](tests) and [`scripts/mutation_check.py`](scripts/mutation_check.py) |
| Schema and setup | [`app/schema.sql`](app/schema.sql), [`scripts/seed.py`](scripts/seed.py), this README |
| API documentation | [API.md](API.md) |
| Write-up | [WRITEUP.md](WRITEUP.md) |
| Demo video | `LINK-TO-VIDEO` |
