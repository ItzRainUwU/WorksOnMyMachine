"""Security and API contract tests for ZIP target uploads."""

from io import BytesIO
from pathlib import Path
import zipfile

from fastapi.testclient import TestClient

from worksonmymachine.app import app
import worksonmymachine.app as app_module


def _zip_bytes(*members: tuple[str, bytes]) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in members:
            archive.writestr(name, content)
    return output.getvalue()


def _client(monkeypatch, tmp_path: Path) -> TestClient:
    monkeypatch.setattr(app_module, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(app_module, "UPLOADS_DIR", tmp_path / ".worksonmymachine" / "uploads")
    return TestClient(app)


def test_zip_upload_extracts_target_and_returns_ui_metadata(monkeypatch, tmp_path: Path) -> None:
    client = _client(monkeypatch, tmp_path)
    payload = _zip_bytes(
        ("sample-project/README.md", b"# sample\n"),
        ("sample-project/src/main.py", b"print('ok')\n"),
    )

    response = client.post(
        "/api/v1/upload",
        files={"file": ("sample-project.zip", payload, "application/zip")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["target"] == body["path"]
    assert body["target"].startswith(".worksonmymachine/uploads/upload-")
    assert body["file_count"] == 2
    assert body["directory_count"] == 0
    target = tmp_path / Path(body["target"])
    assert (target / "README.md").read_bytes() == b"# sample\n"
    assert (target / "src" / "main.py").read_bytes() == b"print('ok')\n"
    assert body["target"] in client.get("/api/v1/targets?scope=workspace").json()["targets"]


def test_zip_upload_rejects_traversal_before_extraction(monkeypatch, tmp_path: Path) -> None:
    client = _client(monkeypatch, tmp_path)
    payload = _zip_bytes(("../escaped.txt", b"must not be written"))

    response = client.post(
        "/api/v1/upload",
        files={"file": ("unsafe.zip", payload, "application/zip")},
    )

    assert response.status_code == 400
    assert "traversal" in response.json()["detail"]
    assert not (tmp_path / "escaped.txt").exists()
    uploads = tmp_path / ".worksonmymachine" / "uploads"
    assert not uploads.exists() or not list(uploads.iterdir())


def test_zip_upload_rejects_non_zip_content(monkeypatch, tmp_path: Path) -> None:
    client = _client(monkeypatch, tmp_path)

    response = client.post(
        "/api/v1/upload",
        files={"file": ("not-a-zip.txt", b"plain text", "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "uploaded file must be a valid ZIP archive"


def test_zip_upload_rejects_duplicate_paths(monkeypatch, tmp_path: Path) -> None:
    client = _client(monkeypatch, tmp_path)
    output = BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("same.txt", b"first")
        archive.writestr("same.txt", b"second")

    response = client.post(
        "/api/v1/upload",
        files={"file": ("duplicate.zip", output.getvalue(), "application/zip")},
    )

    assert response.status_code == 400
    assert "duplicate" in response.json()["detail"]


def test_delete_uploaded_target_and_clear_all(monkeypatch, tmp_path: Path) -> None:
    client = _client(monkeypatch, tmp_path)
    payload = _zip_bytes(("sample/README.md", b"# sample\n"))

    upload_res = client.post(
        "/api/v1/upload",
        files={"file": ("sample.zip", payload, "application/zip")},
    )
    assert upload_res.status_code == 200
    target = upload_res.json()["target"]
    assert target in client.get("/api/v1/targets?scope=workspace").json()["targets"]

    delete_res = client.delete(f"/api/v1/targets?target={target}")
    assert delete_res.status_code == 200
    assert delete_res.json()["deleted"] is True
    assert target not in client.get("/api/v1/targets?scope=workspace").json()["targets"]

    # Re-upload and test clear all
    upload_res2 = client.post(
        "/api/v1/upload",
        files={"file": ("sample2.zip", payload, "application/zip")},
    )
    assert upload_res2.status_code == 200
    target2 = upload_res2.json()["target"]
    assert target2 in client.get("/api/v1/targets?scope=workspace").json()["targets"]

    clear_res = client.delete("/api/v1/uploads")
    assert clear_res.status_code == 200
    assert clear_res.json()["deleted_count"] >= 1
    assert target2 not in client.get("/api/v1/targets?scope=workspace").json()["targets"]
