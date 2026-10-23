"""
engine/config.py - Rules configuration loader and validator for ForensiTrace.

Author: Akash (Correlation Engine & Rules Owner)
Contract: docs/rules.yaml, docs/schema.md
Scope: Task 2 - Rules R1, R2, R3
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger("forensitrace.engine.config")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Default location of technical contract rules file
DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "docs" / "rules.yaml"


@dataclass
class RuleDefinition:
    """Structured representation of a single correlation rule from YAML."""
    rule_id: str
    name: str
    description: str
    enabled: bool = True
    window_seconds: int = 300
    trigger: dict[str, Any] = field(default_factory=dict)
    target: dict[str, Any] = field(default_factory=dict)
    context: Optional[dict[str, Any]] = None


@dataclass
class RulesConfig:
    """Container for parsed rules configuration."""
    version: str
    rules: dict[str, RuleDefinition] = field(default_factory=dict)

    def get_rule(self, rule_id: str) -> Optional[RuleDefinition]:
        return self.rules.get(rule_id)

    def get_window_seconds(self, rule_id: str, default: int = 300) -> int:
        r = self.get_rule(rule_id)
        return r.window_seconds if r else default


def load_rules_config(rules_path: Optional[Path | str] = None) -> RulesConfig:
    """
    Loads and validates rules configuration from YAML file.
    Falls back to docs/rules.yaml if no path is specified.
    """
    target_path = Path(rules_path or DEFAULT_RULES_PATH)
    logger.info("[load_rules_config] [RECEIVED] Loading rules configuration from '%s'", target_path)

    if not target_path.exists():
        raise FileNotFoundError(f"Rules configuration file not found at: {target_path}")

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as exc:
        raise ValueError(f"Failed to parse rules YAML from {target_path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Invalid rules YAML: expected top-level dictionary, got {type(data)}")

    version = str(data.get("version", "1.0"))
    raw_rules = data.get("rules", {})
    if not isinstance(raw_rules, dict):
        raise ValueError(f"Invalid rules section: expected dictionary of rules, got {type(raw_rules)}")

    parsed_rules: dict[str, RuleDefinition] = {}

    for r_id, r_dict in raw_rules.items():
        if not isinstance(r_dict, dict):
            logger.warning("[load_rules_config] Skipping non-dict rule definition '%s'", r_id)
            continue

        rule_id = r_dict.get("rule_id", r_id)
        name = r_dict.get("name", f"Rule {rule_id}")
        description = r_dict.get("description", "")
        enabled = bool(r_dict.get("enabled", True))
        window_sec = int(r_dict.get("window_seconds", 300))
        trigger = r_dict.get("trigger", {})
        target = r_dict.get("target", {})
        context = r_dict.get("context")

        parsed_rules[rule_id] = RuleDefinition(
            rule_id=rule_id,
            name=name,
            description=description,
            enabled=enabled,
            window_seconds=window_sec,
            trigger=trigger,
            target=target,
            context=context,
        )

    logger.info("[load_rules_config] [PRODUCED] Successfully loaded %d rule(s): %s", len(parsed_rules), list(parsed_rules.keys()))
    return RulesConfig(version=version, rules=parsed_rules)
