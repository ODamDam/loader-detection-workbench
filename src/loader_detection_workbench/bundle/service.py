"""Case Bundle v1 application service."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from loader_detection_workbench.artifact.seal import ContentReader
from loader_detection_workbench.artifact.store import ArtifactStore
from loader_detection_workbench.bundle.domain import (
    ARTIFACT_SENSITIVITY,
    BundleReport,
    Sensitivity,
)
from loader_detection_workbench.bundle.manifest import validate_manifest
from loader_detection_workbench.bundle.zip_store import check_members
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.validation import (
    FindingSeverity,
    ValidationFinding,
    ValidationScope,
)
from loader_detection_workbench.project.database import connect_database
from loader_detection_workbench.project.service import ProjectService


def _finding(code: str, message: str, subject: str | None = None) -> ValidationFinding:
    return ValidationFinding(
        code, FindingSeverity.ERROR, ValidationScope.ARTIFACT, subject, message
    )


class BundleService:
    def __init__(self, root: Path) -> None:
        self.root = root

    @staticmethod
    def _manifest_bytes(manifest: dict[str, Any]) -> bytes:
        return (
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode()

    @staticmethod
    def _content_digest(stream: Any) -> tuple[str, int]:
        # Sealed members (ADR-030) are identified by their unsealed content.
        reader = ContentReader(stream)
        digest = hashlib.sha256()
        size = 0
        while chunk := reader.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
        return digest.hexdigest(), size

    def _load_archive(
        self, bundle: Path
    ) -> tuple[zipfile.ZipFile, dict[str, Any], list[zipfile.ZipInfo]]:
        try:
            zf = zipfile.ZipFile(bundle, "r")
        except (OSError, zipfile.BadZipFile) as exc:
            raise DomainError(
                DomainErrorCode.INVALID_BUNDLE_ARCHIVE,
                "Bundle archive could not be opened",
            ) from exc
        try:
            infos = check_members(zf)
            try:
                raw = zf.read("manifest.json")
                data = json.loads(raw)
            except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise DomainError(
                    DomainErrorCode.INVALID_BUNDLE_MANIFEST,
                    "Bundle manifest is invalid",
                ) from exc
            manifest = validate_manifest(data)
            names = {item.filename for item in infos}
            expected = {item["relative_path"] for item in manifest["contents"]} | {
                "manifest.json"
            }
            if names != expected:
                raise DomainError(
                    DomainErrorCode.MISSING_BUNDLE_CONTENT,
                    "Bundle members do not match manifest contents",
                )
            for content in manifest["contents"]:
                try:
                    info = zf.getinfo(content["relative_path"])
                    with zf.open(info, "r") as stream:
                        digest, size = self._content_digest(stream)
                except (KeyError, OSError, zipfile.BadZipFile) as exc:
                    raise DomainError(
                        DomainErrorCode.MISSING_BUNDLE_CONTENT,
                        "Bundle content is unreadable",
                    ) from exc
                if size != content["size_bytes"]:
                    raise DomainError(
                        DomainErrorCode.BUNDLE_SIZE_MISMATCH,
                        "Bundle content size does not match manifest",
                    )
                if digest != content["sha256"]:
                    raise DomainError(
                        DomainErrorCode.BUNDLE_SHA256_MISMATCH,
                        "Bundle content hash does not match manifest",
                    )
            return zf, manifest, infos
        except BaseException:
            zf.close()
            raise

    @staticmethod
    def _cleanup_published(
        connection: sqlite3.Connection | None,
        store: ArtifactStore | None,
        published: list[Any],
    ) -> None:
        if connection is None or store is None:
            return
        for content in published:
            if content.owned_identity is None:
                continue
            referenced = connection.execute(
                "SELECT 1 FROM artifacts WHERE relative_path = ? OR sha256 = ? LIMIT 1",
                (content.relative_path.as_posix(), content.sha256),
            ).fetchone()
            if referenced is None:
                try:
                    store.cleanup(content)
                except OSError as exc:
                    raise DomainError(
                        DomainErrorCode.BUNDLE_CLEANUP_FAILED,
                        "Bundle content cleanup failed",
                    ) from exc

    def validate(self, bundle: Path) -> BundleReport:
        try:
            zf, _, _ = self._load_archive(bundle)
            zf.close()
            return BundleReport(())
        except DomainError as exc:
            return BundleReport((_finding(exc.code.value, str(exc)),))
        except (OSError, ValueError, TypeError, sqlite3.Error):
            return BundleReport(
                (
                    _finding(
                        DomainErrorCode.INVALID_BUNDLE_ARCHIVE.value,
                        "Bundle validation failed",
                    ),
                )
            )

    def export(self, case_display_id: str, output: Path) -> Path:
        workspace = ProjectService().open(self.root)
        from loader_detection_workbench.artifact.sqlite_repository import (
            SQLiteArtifactRepository,
        )
        from loader_detection_workbench.case.sqlite_repository import (
            SQLiteCaseRepository,
        )

        case_repo = SQLiteCaseRepository(workspace)
        artifact_repo = SQLiteArtifactRepository(workspace)
        try:
            case = case_repo.get(case_display_id)
            artifacts = artifact_repo.list_artifacts(case.case_id.ulid)
        finally:
            case_repo.close()
            artifact_repo.close()
        store = ArtifactStore(workspace.root)
        entries: dict[str, tuple[Path, int]] = {}
        for artifact in artifacts:
            path = store.resolve(artifact.relative_path)
            store.verify(path, (artifact.sha256, artifact.size_bytes))
            entries[artifact.sha256] = (path, artifact.size_bytes)
        sensitivities = [
            Sensitivity.INTERNAL,
            *(ARTIFACT_SENSITIVITY[a.kind.value] for a in artifacts),
        ]
        classification = max(sensitivities, key=lambda item: item.rank).value
        manifest = {
            "schema_version": "1",
            "bundle_kind": "case",
            "classification": classification,
            "source_project": {
                "internal_id": workspace.manifest.project_id.ulid,
                "display_id": workspace.manifest.project_id.display_id,
                "name": workspace.manifest.name,
                "created_at": workspace.manifest.created_at.strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            },
            "case": {
                "internal_id": case.case_id.ulid,
                "display_id": case.case_id.display_id,
                "project_id": case.project_id,
                "kind": case.kind.value,
                "status": case.status.value,
                "name": case.name,
                "description": case.description,
                "created_at": case.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "updated_at": case.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "closed_at": None
                if case.closed_at is None
                else case.closed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "artifacts": [
                {
                    "internal_id": a.artifact_id.ulid,
                    "display_id": a.artifact_id.display_id,
                    "project_id": a.project_id,
                    "case_id": a.case_id,
                    "kind": a.kind.value,
                    "relative_path": a.relative_path.as_posix(),
                    "sha256": a.sha256,
                    "size_bytes": a.size_bytes,
                    "created_at": a.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "sensitivity": ARTIFACT_SENSITIVITY[a.kind.value].value,
                }
                for a in artifacts
            ],
            "contents": [
                {
                    "relative_path": f"artifacts/sha256/{sha[:2]}/{sha}",
                    "sha256": sha,
                    "size_bytes": size,
                }
                for sha, (_, size) in sorted(entries.items())
            ],
        }
        validate_manifest(manifest)
        output = output.absolute()
        output.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=".bundle-", suffix=".tmp", dir=output.parent
        )
        os.close(fd)
        temp = Path(temp_name)
        try:
            with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("manifest.json", self._manifest_bytes(manifest))
                for sha, (path, _) in sorted(entries.items()):
                    zf.write(path, f"artifacts/sha256/{sha[:2]}/{sha}")
            self._load_archive(temp)[0].close()
            os.replace(temp, output)
            return output
        except BaseException:
            temp.unlink(missing_ok=True)
            raise

    def import_bundle(self, bundle: Path) -> dict[str, str]:
        zf, manifest, infos = self._load_archive(bundle)
        staging = Path(
            tempfile.mkdtemp(prefix=".bundle-import-", dir=self.root.absolute())
        )
        published: list[Any] = []
        connection: sqlite3.Connection | None = None
        store: ArtifactStore | None = None
        try:
            target = ProjectService().open(self.root)
            case_data = manifest["case"]
            connection = connect_database(target.database_path)
            # Check both identity classes before publishing bytes.
            if connection.execute(
                "SELECT 1 FROM cases WHERE internal_id = ? OR display_id = ?",
                (case_data["internal_id"], case_data["display_id"]),
            ).fetchone():
                raise DomainError(
                    DomainErrorCode.CASE_ID_COLLISION,
                    "Case identity collides with the target Project",
                )
            artifact_ids = [
                (a["internal_id"], a["display_id"]) for a in manifest["artifacts"]
            ]
            for internal_id, display_id in artifact_ids:
                if connection.execute(
                    "SELECT 1 FROM artifacts WHERE internal_id = ? OR display_id = ?",
                    (internal_id, display_id),
                ).fetchone():
                    raise DomainError(
                        DomainErrorCode.ARTIFACT_ID_COLLISION,
                        "Artifact identity collides with the target Project",
                    )
            for content in manifest["contents"]:
                target_path = staging / content["relative_path"]
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with (
                    zf.open(content["relative_path"], "r") as source,
                    target_path.open("xb") as destination,
                ):
                    while chunk := source.read(1024 * 1024):
                        destination.write(chunk)
            connection.execute("BEGIN IMMEDIATE")
            case_number = int(case_data["display_id"].split("-")[1])
            connection.execute(
                "UPDATE counters SET next_value = max(next_value, ?) "
                "WHERE name = 'case'",
                (case_number + 1,),
            )
            for artifact in manifest["artifacts"]:
                number = int(artifact["display_id"].split("-")[1])
                connection.execute(
                    "UPDATE counters SET next_value = max(next_value, ?) "
                    "WHERE name = 'artifact'",
                    (number + 1,),
                )
            store = ArtifactStore(target.root)
            for content in manifest["contents"]:
                source = staging / content["relative_path"]
                try:
                    published.append(store.publish(source))
                except BaseException:
                    if store.published is not None:
                        published.append(store.published)
                    raise
            connection.execute(
                "INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    case_data["internal_id"],
                    target.manifest.project_id.ulid,
                    case_data["display_id"],
                    case_data["kind"],
                    case_data["status"],
                    case_data["name"],
                    case_data["description"],
                    case_data["created_at"],
                    case_data["updated_at"],
                    case_data["closed_at"],
                ),
            )
            for artifact in manifest["artifacts"]:
                connection.execute(
                    "INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        artifact["internal_id"],
                        target.manifest.project_id.ulid,
                        artifact["display_id"],
                        case_data["internal_id"],
                        artifact["kind"],
                        artifact["relative_path"],
                        artifact["sha256"],
                        artifact["size_bytes"],
                        artifact["created_at"],
                    ),
                )
            connection.commit()
            return {
                "case_display_id": case_data["display_id"],
                "case_internal_id": case_data["internal_id"],
            }
        except sqlite3.Error as exc:
            if connection is not None:
                connection.rollback()
            self._cleanup_published(connection, store, published)
            raise DomainError(
                DomainErrorCode.BUNDLE_IMPORT_FAILED,
                "Bundle import database operation failed",
            ) from exc
        except BaseException:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            self._cleanup_published(connection, store, published)
            raise
        finally:
            zf.close()
            if connection is not None:
                connection.close()
            try:
                shutil.rmtree(staging)
            except OSError as exc:
                raise DomainError(
                    DomainErrorCode.BUNDLE_CLEANUP_FAILED,
                    "Bundle staging cleanup failed",
                ) from exc
