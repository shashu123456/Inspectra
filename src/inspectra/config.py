"""Configuration file support for ``inspectra scan --config``.

The file is JSON (parsed with the standard library, so no new dependency).
Keys are the long option names of ``inspectra scan`` without the leading
dashes; hyphens and underscores are interchangeable. Values given on the
command line always win over values from the file.

Example::

    {
      "format": "json",
      "fail-on": "medium",
      "skip-ports": true,
      "rules-dir": ["./my-checks"]
    }
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

# Options that cannot be defaults: the target is positional, ``config`` and
# ``list-checks`` are meta options, and the consent prompt must stay explicit.
_EXCLUDED = {"target", "config", "list_checks", "yes", "help"}


class ConfigError(Exception):
    """The configuration file is missing, unreadable or invalid."""


def load_config(path: Path, scan_parser: argparse.ArgumentParser) -> dict[str, Any]:
    """Read ``path`` and return validated defaults keyed by argparse ``dest``."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise ConfigError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a JSON object")

    actions: dict[str, argparse.Action] = {}
    for action in scan_parser._actions:  # noqa: SLF001 - argparse has no public listing
        if action.dest in _EXCLUDED:
            continue
        for option in action.option_strings:
            if option.startswith("--"):
                actions[option[2:].replace("-", "_")] = action
    defaults: dict[str, Any] = {}
    for key, value in raw.items():
        found = actions.get(key.replace("-", "_"))
        if found is None:
            raise ConfigError(f"unknown option {key!r} in {path}")
        defaults[found.dest] = _validate(key, value, found)
    return defaults


def _validate(key: str, value: Any, action: argparse.Action) -> Any:
    if isinstance(action, argparse._StoreTrueAction):  # noqa: SLF001
        if not isinstance(value, bool):
            raise ConfigError(f"option {key!r} must be true or false")
        return value
    if isinstance(action, argparse._AppendAction):  # noqa: SLF001
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ConfigError(f"option {key!r} must be a list of strings")
        return value
    if action.type is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"option {key!r} must be an integer")
    elif action.type is float:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ConfigError(f"option {key!r} must be a number")
        value = float(value)
    elif not isinstance(value, str):
        raise ConfigError(f"option {key!r} must be a string")
    if action.choices is not None and value not in action.choices:
        raise ConfigError(f"option {key!r} must be one of {sorted(action.choices)}")
    return value
