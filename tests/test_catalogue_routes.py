"""Adding to the shipped catalogues through the UI.

The catalogue these routes write is `service-catalogue.yaml` at the repository root — a
tracked file. So the fixture points them at a copy in a temp directory: a test that
added a service for real would edit the source tree, and would pass while doing it.

The behaviour under test is a refusal. Both catalogues are held by name, so adding a
second entry under an existing name replaced the first without a word. That is worst in
exactly the case host templates are used for — several kinds of workstation differing
only by operating system — where the second one looks added and the first is gone.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from btht.app import data as data_module
from btht.app.main import app

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    catalogue = tmp_path / "service-catalogue.yaml"
    shutil.copy(REPO / "service-catalogue.yaml", catalogue)
    estates = tmp_path / "estates"
    monkeypatch.setattr(data_module, "ESTATES", estates)
    monkeypatch.setattr("btht.app.web.routes.ESTATES", estates)
    monkeypatch.setattr("btht.app.web.routes.SERVICE_CATALOGUE", catalogue)
    with TestClient(app) as test_client:
        yield test_client


def test_a_duplicate_host_template_name_is_refused(client: TestClient) -> None:
    response = client.post(
        "/services/types/new",
        data={"name": "windows_workstation", "default_os": "Windows 11 23H2"},
        follow_redirects=True,
    )
    assert "already exists" in response.text
    assert "name of its own" in response.text, "and it says what to do instead"


def test_a_duplicate_service_name_is_refused(client: TestClient) -> None:
    """A replaced service silently changes what every template pointing at it opens."""
    response = client.post(
        "/services/new", data={"name": "RDP", "tcp": "3389"}, follow_redirects=True
    )
    assert "already exists" in response.text


def test_a_distinctly_named_template_is_accepted(client: TestClient, tmp_path: Path) -> None:
    """The refusal must not block the thing it is there to make possible."""
    from btht.app.model.services import load_catalogue

    response = client.post(
        "/services/types/new",
        data={
            "name": "windows_workstation_win11",
            "default_os": "Windows 11 23H2",
            "services": ["RDP"],
        },
        follow_redirects=True,
    )
    assert "added" in response.text
    catalogue = load_catalogue(tmp_path / "service-catalogue.yaml")
    assert "windows_workstation_win11" in catalogue.host_types
    assert "windows_workstation" in catalogue.host_types, "the original is untouched"


def test_the_shipped_catalogue_is_not_written_by_these_tests() -> None:
    """The control on the fixture above, proved rather than assumed."""
    import subprocess

    changed = subprocess.run(
        ["git", "status", "--porcelain", "service-catalogue.yaml"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert changed.stdout.strip() == "", "the tracked catalogue must be untouched"
