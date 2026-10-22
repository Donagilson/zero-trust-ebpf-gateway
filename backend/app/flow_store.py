"""Persistent ownership metadata for authorized eBPF flows."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class FlowStoreError(RuntimeError):
    """Flow ownership metadata could not be read or updated."""


class FlowRegistry:
    """Persist the authenticated owner associated with each deterministic flow ID."""

    def __init__(self, database_path: str | None = None) -> None:
        configured_path = database_path or os.getenv("FLOW_DATABASE_PATH")
        self.database_path = Path(
            configured_path
            if configured_path
            else Path(tempfile.gettempdir()) / "zero-trust-gateway-flows.sqlite3"
        ).expanduser()
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            with self._connection() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS flow_owners (
                        flow_id TEXT PRIMARY KEY,
                        subject_sub TEXT NOT NULL
                    )
                    """
                )
            if os.name != "nt":
                self.database_path.chmod(0o600)
        except sqlite3.Error as exc:
            raise FlowStoreError("Unable to initialize flow ownership storage") from exc
        except OSError as exc:
            raise FlowStoreError("Unable to create flow ownership storage") from exc

    def get_owner(self, flow_id: str) -> str | None:
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT subject_sub FROM flow_owners WHERE flow_id = ?",
                    (flow_id,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise FlowStoreError("Unable to read flow ownership") from exc
        return row[0] if row is not None else None

    def list_owners(self) -> dict[str, str]:
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    "SELECT flow_id, subject_sub FROM flow_owners"
                ).fetchall()
        except sqlite3.Error as exc:
            raise FlowStoreError("Unable to read flow ownership") from exc
        return {flow_id: subject_sub for flow_id, subject_sub in rows}

    def set_owner(self, flow_id: str, subject_sub: str) -> None:
        try:
            with self._connection() as connection:
                connection.execute(
                    "INSERT INTO flow_owners (flow_id, subject_sub) VALUES (?, ?)",
                    (flow_id, subject_sub),
                )
        except sqlite3.IntegrityError as exc:
            raise FlowStoreError("Flow ownership already exists") from exc
        except sqlite3.Error as exc:
            raise FlowStoreError("Unable to save flow ownership") from exc

    def remove_owner(self, flow_id: str) -> None:
        try:
            with self._connection() as connection:
                connection.execute(
                    "DELETE FROM flow_owners WHERE flow_id = ?",
                    (flow_id,),
                )
        except sqlite3.Error as exc:
            raise FlowStoreError("Unable to remove flow ownership") from exc

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=5)
        try:
            connection.execute("PRAGMA busy_timeout = 5000")
            with connection:
                yield connection
        finally:
            connection.close()
