"""Verify the audit hash chain from the command line.

    python -m scripts.verify_audit                      # check the live database
    python -m scripts.verify_audit --against export.jsonl
        # also check that every record in an earlier export is still present
        # and unchanged - catches a full rewrite by someone who had the key.

Exit code 0 = intact, 1 = broken.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from app.audit import verify_chain  # noqa: E402
from app.db import get_db  # noqa: E402


def main():
    app = create_app()
    with app.app_context():
        db = get_db()
        result = verify_chain(db, app.config["TV"].AUDIT_KEY)
        print(json.dumps(result, indent=2))
        ok = result["valid"]
        if "--against" in sys.argv:
            path = sys.argv[sys.argv.index("--against") + 1]
            mismatches = 0
            with open(path, encoding="utf-8") as f:
                for line in f:
                    old = json.loads(line)
                    row = db.execute("SELECT hash FROM audit_log WHERE seq = ?", (old["seq"],)).fetchone()
                    if row is None or row["hash"] != old["hash"]:
                        mismatches += 1
                        print(f"record {old['seq']} differs from the export")
            print(f"export comparison: {mismatches} mismatch(es)")
            ok = ok and mismatches == 0
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
