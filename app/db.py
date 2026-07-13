"""SQLite lifecycle and deterministic synthetic seed data for OWASP TwinLab."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import click
from flask import current_app, g
from werkzeug.security import check_password_hash, generate_password_hash


SCHEMA = """
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS coupon_uses;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    item TEXT NOT NULL,
    shipping_address TEXT NOT NULL,
    total_cents INTEGER NOT NULL
);

CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    is_public INTEGER NOT NULL CHECK (is_public IN (0, 1)),
    price_cents INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    variant TEXT NOT NULL CHECK (variant IN ('vulnerable', 'candidate', 'secure')),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE coupon_uses (
    user_id INTEGER NOT NULL REFERENCES users(id),
    coupon_code TEXT NOT NULL,
    variant TEXT NOT NULL,
    used_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX one_secure_coupon_use_per_user
ON coupon_uses (user_id, coupon_code)
WHERE variant = 'secure';

CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    details TEXT NOT NULL,
    request_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    variant TEXT NOT NULL DEFAULT 'system',
    comparison_run_id TEXT NOT NULL DEFAULT 'default'
);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    variant TEXT NOT NULL DEFAULT 'system',
    comparison_run_id TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX audit_events_comparison_scope
ON audit_events (variant, comparison_run_id, actor, event_type, created_at);

CREATE INDEX alerts_comparison_scope
ON alerts (variant, comparison_run_id, actor, alert_type, created_at);
"""


def demo_password_hash(password: str) -> str:
    """Create a salted, deliberately slow hash for the shared lab login store."""

    try:
        return generate_password_hash(password, method="scrypt")
    except AttributeError:
        # The bundled macOS Python 3.9 lacks hashlib.scrypt. Werkzeug's salted
        # PBKDF2 path still avoids the former single-round SHA-256 contradiction.
        return generate_password_hash(password, method="pbkdf2:sha256:600000")


def verify_demo_password(stored_hash: str, password: str) -> bool:
    return check_password_hash(stored_hash, password)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        database = Path(current_app.config["DATABASE"])
        database.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(database)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_error: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def ensure_schema_compatibility() -> None:
    """Add comparison-scope columns to lab databases created before this release.

    Resetting the lab remains the preferred way to obtain deterministic seed data,
    but a local existing database must also be safe to open after an upgrade.
    Non-A09 records retain the explicit ``system/default`` scope.
    """

    connection = get_db()
    tables = {
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    required_tables = {
        "users",
        "orders",
        "products",
        "sessions",
        "coupon_uses",
        "audit_events",
        "alerts",
    }
    if not required_tables.issubset(tables):
        reset_database()
        return
    session_schema = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sessions'"
    ).fetchone()
    if session_schema is None or "'candidate'" not in (session_schema["sql"] or ""):
        # Sessions are disposable synthetic runtime state.  Recreate this one
        # table on upgrade so the Auditor can isolate its candidate lifecycle
        # without asking users to delete their whole local database.
        connection.execute("DROP TABLE sessions")
        connection.execute(
            """CREATE TABLE sessions (
                   token_hash TEXT PRIMARY KEY,
                   user_id INTEGER NOT NULL REFERENCES users(id),
                   variant TEXT NOT NULL CHECK (
                       variant IN ('vulnerable', 'candidate', 'secure')
                   ),
                   active INTEGER NOT NULL CHECK (active IN (0, 1)),
                   expires_at INTEGER NOT NULL,
                   created_at INTEGER NOT NULL
               )"""
        )
    for table in ("audit_events", "alerts"):
        columns = {
            row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if "variant" not in columns:
            connection.execute(
                f"ALTER TABLE {table} ADD COLUMN variant TEXT NOT NULL DEFAULT 'system'"
            )
        if "comparison_run_id" not in columns:
            connection.execute(
                f"ALTER TABLE {table} ADD COLUMN comparison_run_id TEXT NOT NULL DEFAULT 'default'"
            )
    connection.execute(
        """CREATE INDEX IF NOT EXISTS audit_events_comparison_scope
           ON audit_events (variant, comparison_run_id, actor, event_type, created_at)"""
    )
    connection.execute(
        """CREATE INDEX IF NOT EXISTS alerts_comparison_scope
           ON alerts (variant, comparison_run_id, actor, alert_type, created_at)"""
    )
    legacy_hashes = connection.execute(
        "SELECT username, password_hash FROM users WHERE instr(password_hash, '$') = 0"
    ).fetchall()
    known_demo_passwords = {
        "alice": "alice-demo",
        "bob": "bob-demo",
        "admin": "demo-admin",
    }
    for row in legacy_hashes:
        password = known_demo_passwords.get(row["username"])
        if password is not None:
            connection.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (demo_password_hash(password), row["username"]),
            )
    connection.commit()


def reset_database() -> None:
    """Reset all mutable state to stable, fictional IDs and values."""

    if not current_app.testing:
        configured = Path(current_app.config["DATABASE"]).resolve()
        dedicated_lab_database = (Path(current_app.instance_path) / "twinlab.sqlite3").resolve()
        if configured != dedicated_lab_database:
            raise RuntimeError(
                "Refusing to reset a database outside the dedicated TwinLab instance path."
            )

    db = get_db()
    db.executescript(SCHEMA)
    db.executemany(
        "INSERT INTO users (id, username, role, password_hash) VALUES (?, ?, ?, ?)",
        [
            (1, "alice", "customer", demo_password_hash("alice-demo")),
            (2, "bob", "customer", demo_password_hash("bob-demo")),
            (3, "admin", "admin", demo_password_hash("demo-admin")),
        ],
    )
    db.executemany(
        "INSERT INTO orders (id, owner_id, item, shipping_address, total_cents) VALUES (?, ?, ?, ?, ?)",
        [
            (101, 1, "Security Engineering Handbook", "1 Example Street", 4900),
            (202, 2, "Privacy Screen", "2 Fiction Avenue", 7900),
        ],
    )
    db.executemany(
        "INSERT INTO products (id, name, is_public, price_cents) VALUES (?, ?, ?, ?)",
        [
            (1, "Security Engineering Handbook", 1, 4900),
            (2, "Privacy Screen", 1, 7900),
            (3, "USB Data Blocker", 1, 1900),
            (99, "HIDDEN-PRODUCT-INTERNAL-ONLY", 0, 999900),
        ],
    )
    db.commit()


@click.command("reset-lab")
def reset_lab_command() -> None:
    reset_database()
    click.echo("TwinLab reset complete: synthetic seed restored and sessions cleared.")


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    app.cli.add_command(reset_lab_command)

    database = Path(app.config["DATABASE"])
    with app.app_context():
        if not database.exists():
            reset_database()
        else:
            ensure_schema_compatibility()
