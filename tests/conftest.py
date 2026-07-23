from __future__ import annotations

import pytest

from app import create_app
from app.db import reset_database


@pytest.fixture()
def app(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "twinlab-test.sqlite3"),
            "SECRET_KEY": "test-only-secret",
        }
    )
    with app.app_context():
        reset_database()
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def json_get(client):
    def call(path: str, **kwargs):
        separator = "&" if "?" in path else "?"
        return client.get(f"{path}{separator}format=json", **kwargs)

    return call


@pytest.fixture()
def json_post(client):
    def call(path: str, **kwargs):
        separator = "&" if "?" in path else "?"
        return client.post(f"{path}{separator}format=json", **kwargs)

    return call
