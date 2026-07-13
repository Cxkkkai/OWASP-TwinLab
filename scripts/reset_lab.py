"""Reset the default local TwinLab database from a direct Python command."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import create_app
from app.db import reset_database


if __name__ == "__main__":
    application = create_app()
    with application.app_context():
        reset_database()
    print("TwinLab reset complete: synthetic seed restored and sessions cleared.")
