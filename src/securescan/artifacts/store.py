from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

from securescan.domain.enums import ArtifactKind
from securescan.domain.models import ArtifactRecord


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
