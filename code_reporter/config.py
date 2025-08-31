"""Lightweight configuration for report generation.

Allows users to control which languages appear in charts,
via blacklist/whitelist with simple JSON override.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Set


def _normalize_lang(name: str) -> str:
    """Normalize language names for matching (case/spacing variations)."""
    if not name:
        return ""
    lowered = name.strip().lower()
    # Remove common separators to match variants like "Docker ignore" vs "dockerignore"
    for ch in [" ", "-", "."]:
        lowered = lowered.replace(ch, "")
    return lowered


DEFAULT_BLACKLIST = {
    # Markup / data formats
    "css",
    "scss",
    "sass",
    "less",
    "html",
    "xml",
    "json",
    "yaml",
    "yml",
    "toml",
    "ini",
    "properties",
    "markdown",
    "md",
    "svg",
    # Infrastructure / config / ignores
    "dockerfile",
    "dockerignore",
    "dockerignorefile",
    "gitignore",
    "editorconfig",
    "env",
    "dotenv",
    # Build/lock files often show up in SCC as separate types
    "lock",
    "license",
    "plaintext",
}

# A sensible default whitelist in case users opt into whitelist mode.
DEFAULT_WHITELIST = {
    "python",
    "go",
    "php",
    "rust",
    "javascript",
    "typescript",
    "java",
    "kotlin",
    "c",
    "cpp",
    "csharp",
    "ruby",
    "swift",
}


@dataclass
class ReportConfig:
    language_filter_mode: str = "blacklist"  # "blacklist" or "whitelist"
    languages_blacklist: Set[str] = field(default_factory=lambda: set(DEFAULT_BLACKLIST))
    languages_whitelist: Set[str] = field(default_factory=lambda: set(DEFAULT_WHITELIST))
    min_language_lines: int = 500
    # Map canonical label -> list of aliases to merge under that label
    language_aliases: dict = field(default_factory=lambda: {
        "Shell": [
            "Shell", "Bash", "BASH", "Zsh", "zsh", "Ksh", "Tcsh", "csh", "sh", "fish",
            "PowerShell", "Powershell", "pwsh", "ps1", "psm1"
        ],
    })

    def is_language_reportable(self, name: Optional[str]) -> bool:
        if not name:
            return False
        key = _normalize_lang(name)
        if self.language_filter_mode == "whitelist":
            return key in { _normalize_lang(x) for x in self.languages_whitelist }
        # blacklist (default)
        return key not in { _normalize_lang(x) for x in self.languages_blacklist }

    def canonical_language(self, name: Optional[str]) -> Optional[str]:
        if not name:
            return None
        norm = _normalize_lang(name)
        # Build alias map once
        alias_map = {}
        for canonical, aliases in self.language_aliases.items():
            for a in aliases:
                alias_map[_normalize_lang(a)] = canonical
        return alias_map.get(norm, name)


def _load_json(path: Path) -> Optional[dict]:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def load_config() -> ReportConfig:
    """Load configuration from JSON if available, otherwise defaults.

    Load order:
    1) CODE_REPORTER_CONFIG env var (JSON file path)
    2) ./code_reporter_config.json in project root (walk up from this file)
    3) Defaults
    """
    # 1) Env var path
    env_path = os.getenv("CODE_REPORTER_CONFIG")
    if env_path:
        data = _load_json(Path(env_path))
        if data:
            return _from_dict(data)

    # 2) Search upwards for code_reporter_config.json
    current = Path(__file__).resolve().parent
    for _ in range(6):  # search up a few levels
        candidate = current / "code_reporter_config.json"
        data = _load_json(candidate)
        if data:
            return _from_dict(data)
        if current.parent == current:
            break
        current = current.parent

    # 3) Defaults
    return ReportConfig()


def _from_dict(data: dict) -> ReportConfig:
    mode = data.get("language_filter_mode", "blacklist").lower()
    bl = set(data.get("languages_blacklist", [])) or set(DEFAULT_BLACKLIST)
    wl = set(data.get("languages_whitelist", [])) or set(DEFAULT_WHITELIST)
    min_lines = int(data.get("min_language_lines", 500))
    aliases = data.get("language_aliases") or {
        "Shell": [
            "Shell", "Bash", "BASH", "Zsh", "zsh", "Ksh", "Tcsh", "csh", "sh", "fish",
            "PowerShell", "Powershell", "pwsh", "ps1", "psm1"
        ],
    }
    # Ensure we don't accidentally blacklist things templates asked to keep
    return ReportConfig(
        language_filter_mode=mode,
        languages_blacklist=bl,
        languages_whitelist=wl,
        min_language_lines=min_lines,
        language_aliases=aliases,
    )
