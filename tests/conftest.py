"""Shared pytest fixtures.

Every demo backend is constructed with ``speed=0`` so WebSocket tests finish
instantly.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from skillsentry.server.app import create_app
from skillsentry.server.demo_backend import DemoBackend

# The mock model is only reachable from tests and development (see cli._refuse_mock_backend).
os.environ.setdefault("SKILLSENTRY_DEV", "1")
# Tests never touch the user's cache and scan history: the database is a temporary file.
os.environ.setdefault(
    "SKILLSENTRY_DB", os.path.join(tempfile.mkdtemp(prefix="sks-test-"), "test.db")
)


@pytest.fixture()
def demo_backend() -> DemoBackend:
    return DemoBackend(speed=0)


@pytest.fixture()
def demo_app():
    return create_app(DemoBackend(speed=0))


@pytest.fixture()
def client(demo_app) -> Iterator[TestClient]:
    with TestClient(demo_app) as test_client:
        yield test_client


@pytest.fixture()
def store():
    from skillsentry.server.demo_data import build_demo_store

    return build_demo_store()
