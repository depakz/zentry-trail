from __future__ import annotations

import shutil
from pathlib import Path
from typing import Iterable, Optional


ROOT_DIR = Path(__file__).resolve().parents[3]
ROOT_BIN_DIR = ROOT_DIR / "bin"


def resolve_binary(name: str, extra_paths: Optional[Iterable[str]] = None) -> Optional[str]:
    """Resolve a tool binary from ./bin first, then PATH, then optional hints."""
    if not name:
        return None

    candidates = [ROOT_BIN_DIR / name]
    if extra_paths:
        for path in extra_paths:
            if path:
                candidates.append(Path(path))

    for candidate in candidates:
        try:
            if candidate.exists() and candidate.is_file():
                return str(candidate)
        except Exception:
            continue

    discovered = shutil.which(name)
    if discovered:
        return discovered

    return None