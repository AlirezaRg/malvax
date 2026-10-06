import getpass
from pathlib import Path

import pytest

from malvax import manage


@pytest.fixture
def db_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("MALVAX_DATABASE_URL", f"sqlite:///{(tmp_path / 'm.db').as_posix()}")
    return tmp_path


def test_create_user_prompts_for_password_and_stores_hash(db_env, monkeypatch, capsys) -> None:
    answers = iter(["strongpass1", "strongpass1"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))
    assert manage.main(["create-user", "--username", "root", "--role", "admin"]) == 0
    assert "created user 'root' with role admin" in capsys.readouterr().out


def test_password_mismatch_is_refused(db_env, monkeypatch, capsys) -> None:
    answers = iter(["strongpass1", "different123"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))
    assert manage.main(["create-user", "--username", "root", "--role", "admin"]) == 1
    assert "do not match" in capsys.readouterr().err


def test_duplicate_username_returns_error(db_env, monkeypatch, capsys) -> None:
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "strongpass1")
    assert manage.main(["create-user", "--username", "root", "--role", "admin"]) == 0
    assert manage.main(["create-user", "--username", "root", "--role", "viewer"]) == 1
    assert "already taken" in capsys.readouterr().err
