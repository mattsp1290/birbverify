import sqlite3

import pytest

from birbverify.deployment_bootstrap import provision
from birbverify.deployment_http import strict_json
from birbverify.deployment_journal import Journal


def test_service_restart_requires_original_epoch_and_ledger(tmp_path):
    db = tmp_path / "journal"
    args = ("a" * 64, "proof.test", "app")
    install = (*args, "cluster", "b" * 64, "request", "c" * 64)
    with pytest.raises(FileNotFoundError):
        Journal(db, *args, expected_epoch="missing")
    assert not db.exists()
    epoch = provision(db, *install)
    original = Journal(db, *args, expected_epoch=epoch)
    original.seal(epoch)
    with pytest.raises(FileExistsError):
        provision(db, *install)
    db.rename(tmp_path / "original")
    db.touch()
    with pytest.raises(sqlite3.Error):
        Journal(db, *args, expected_epoch=epoch)
    assert db.stat().st_size == 0
    db.unlink()
    other = provision(db, *install)
    assert other != epoch
    with pytest.raises(ValueError, match="epoch mismatch"):
        original.snapshot(epoch)
    with pytest.raises(ValueError, match="epoch mismatch"):
        Journal(db, *args, expected_epoch=epoch)


def test_ambiguous_application_identity_is_rejected():
    with pytest.raises(ValueError, match="duplicate JSON key"):
        strict_json(b'{"username":"first","username":"second"}')
