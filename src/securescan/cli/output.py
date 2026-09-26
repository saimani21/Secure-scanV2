from __future__ import annotations

import errno
import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path

from .source import SourceCliError


def write_private_atomic(path: Path, payload: bytes, *, overwrite: bool) -> Path:
    """Atomically install complete private bytes without following symlinks."""

    if not isinstance(payload, bytes):
        raise SourceCliError("EXPORT_FAILED", "Export payload is invalid", 5)
    absolute = Path(os.path.abspath(os.fspath(path)))
    if absolute.name in {"", ".", ".."}:
        raise _unsafe()
    parent_fd = _open_parent(absolute.parent)
    temporary: str | None = None
    try:
        existing = _target_kind(parent_fd, absolute.name)
        if existing is not None:
            if existing != "regular":
                raise _unsafe()
            if not overwrite:
                raise SourceCliError(
                    "OUTPUT_EXISTS",
                    "Output already exists; use --overwrite for a regular file",
                    2,
                )
        temporary, descriptor = _create_temporary(parent_fd, absolute.name)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            _unlink_quietly(parent_fd, temporary)
            temporary = None
            raise

        if overwrite:
            current = _target_kind(parent_fd, absolute.name)
            if current not in {None, "regular"}:
                raise _unsafe()
            os.replace(
                temporary,
                absolute.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        else:
            try:
                os.link(
                    temporary,
                    absolute.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                raise SourceCliError(
                    "OUTPUT_EXISTS",
                    "Output already exists; use --overwrite for a regular file",
                    2,
                ) from None
            os.unlink(temporary, dir_fd=parent_fd)
        temporary = None
        os.fsync(parent_fd)
        return absolute
    except SourceCliError:
        raise
    except OSError:
        raise SourceCliError("EXPORT_FAILED", "SARIF output could not be written", 5) from None
    finally:
        if temporary is not None:
            _unlink_quietly(parent_fd, temporary)
        os.close(parent_fd)


def _open_parent(parent: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in parent.parts[1:]:
            if component in {"", ".", ".."}:
                raise _unsafe()
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except FileNotFoundError:
        os.close(descriptor)
        raise SourceCliError(
            "OUTPUT_PARENT_MISSING",
            "Output parent directory does not exist",
            2,
        ) from None
    except SourceCliError:
        os.close(descriptor)
        raise
    except OSError:
        os.close(descriptor)
        raise _unsafe() from None


def _target_kind(parent_fd: int, name: str) -> str | None:
    try:
        details = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if stat.S_ISREG(details.st_mode):
        return "regular"
    return "unsafe"


def _create_temporary(parent_fd: int, target_name: str) -> tuple[str, int]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    for _attempt in range(32):
        name = f".{target_name}.securescan-{secrets.token_hex(16)}.tmp"
        try:
            return name, os.open(name, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
    raise SourceCliError("EXPORT_FAILED", "SARIF output could not be written", 5)


def _unlink_quietly(parent_fd: int, name: str) -> None:
    with suppress(FileNotFoundError):
        os.unlink(name, dir_fd=parent_fd)


def _unsafe() -> SourceCliError:
    return SourceCliError("UNSAFE_OUTPUT", "SARIF output path is unsafe", 2)
