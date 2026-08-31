from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path

from securescan.domain.enums import ArtifactKind
from securescan.domain.models import ArtifactRecord

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class ContentAddressedArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def put(
        self,
        data: bytes,
        *,
        kind: ArtifactKind,
        media_type: str,
        sanitized: bool,
    ) -> ArtifactRecord:
        digest = hashlib.sha256(data).hexdigest()
        relative_path = Path("sha256") / digest[:2] / digest
        destination = self.root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)

        if not destination.exists():
            self._atomic_write(destination, data)

        return ArtifactRecord(
            kind=kind,
            sha256=digest,
            size_bytes=len(data),
            media_type=media_type,
            storage_path=str(relative_path),
            sanitized=sanitized,
        )

    def read(self, record: ArtifactRecord) -> bytes:
        path = self.root / record.storage_path
        data = path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != record.sha256:
            raise ValueError("Artifact digest mismatch")
        return data

    def read_by_sha256(
        self,
        sha256: str,
        *,
        expected_size_bytes: int,
    ) -> bytes:
        """Read a content-addressed object without accepting a storage path."""
        if (
            not isinstance(sha256, str)
            or _SHA256_PATTERN.fullmatch(sha256) is None
            or type(expected_size_bytes) is not int
            or expected_size_bytes < 0
        ):
            raise ValueError("Artifact reference is invalid")
        path = self.root / "sha256" / sha256[:2] / sha256
        data = path.read_bytes()
        if (
            len(data) != expected_size_bytes
            or hashlib.sha256(data).hexdigest() != sha256
        ):
            raise ValueError("Artifact digest mismatch")
        return data

    @staticmethod
    def _atomic_write(destination: Path, data: bytes) -> None:
        fd, temporary_name = tempfile.mkstemp(prefix=".artifact-", dir=destination.parent)
        try:
            with os.fdopen(fd, "wb") as file:
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary_name, destination)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
