from __future__ import annotations

import sysconfig
from pathlib import Path


def runtime_asset_path(name: str) -> Path:
    """Resolve a release asset from a source checkout or an installed wheel."""

    if not name or Path(name).name != name:
        raise ValueError("runtime asset name is invalid")
    source_path = Path(__file__).resolve().parents[2] / name
    if source_path.is_file():
        return source_path
    return Path(sysconfig.get_path("data")) / "share" / "securescan" / name
