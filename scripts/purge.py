"""Destroy content of documents that have been in the trash past retention.
Run daily (PythonAnywhere "Tasks" tab, or cron):  python -m scripts.purge
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from app.db import get_db  # noqa: E402
from app.retention import purge_expired  # noqa: E402

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        ids = purge_expired(get_db(), app.config["TV"].TRASH_RETENTION_DAYS)
        print(f"Purged {len(ids)} document(s).")
