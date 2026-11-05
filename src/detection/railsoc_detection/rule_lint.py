"""Offline lint for Wazuh custom rule/decoder files (tasks M3-03 / M3-04). Runs in CI, no Wazuh needed.

Checks what can be checked offline: well-formed XML, id range and uniqueness, level range, a
description on every rule, and an ATT&CK mapping on every high-severity rule. Semantics must still
be validated with `wazuh-logtest` against the Wazuh version you deploy.

Reserved id ranges (HC convention, see PLAN.md): 100000-100099 common, 100100-100199 scenario A,
100200-100299 scenario B, 100300-100399 scenario C, 100400-100499 ML alerts.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

CUSTOM_ID_MIN, CUSTOM_ID_MAX = 100000, 120000
HIGH_LEVEL = 7
MATCHERS = ("prematch", "regex", "parent", "program_name", "plugin_decoder")


@dataclass(frozen=True)
class Issue:
    file: str
    message: str

    def __str__(self) -> str:
        return f"{self.file}: {self.message}"


def _parse(text: str) -> ET.Element:
    """Wazuh files have several top-level elements, so wrap them in a root before parsing."""
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
    return ET.fromstring(f"<root>{text}</root>")


def lint_rules_file(path: Path, seen: dict[int, str] | None = None) -> list[Issue]:
    """Lint one rules file. `seen` maps rule id -> file and is shared to catch cross-file duplicates."""
    seen = seen if seen is not None else {}
    name = path.name
    try:
        root = _parse(path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        return [Issue(name, f"not well-formed XML: {exc}")]

    issues: list[Issue] = []
    for rule in root.iter("rule"):
        raw_id = rule.get("id")
        if raw_id is None or not raw_id.isdigit():
            issues.append(Issue(name, "a <rule> has no numeric id"))
            continue
        rule_id = int(raw_id)
        if not CUSTOM_ID_MIN <= rule_id <= CUSTOM_ID_MAX:
            issues.append(Issue(name, f"rule {rule_id}: custom rules must use ids 100000-120000"))
        if rule_id in seen:
            issues.append(Issue(name, f"rule {rule_id}: duplicate id (also in {seen[rule_id]})"))
        seen[rule_id] = name

        level = rule.get("level")
        level_ok = level is not None and level.isdigit() and 0 <= int(level) <= 15
        if not level_ok:
            issues.append(Issue(name, f"rule {rule_id}: level must be an integer 0-15"))
        if not rule.findtext("description", default="").strip():
            issues.append(Issue(name, f"rule {rule_id}: missing <description>"))
        if level_ok and int(level) >= HIGH_LEVEL and rule.find("mitre/id") is None:
            issues.append(Issue(name, f"rule {rule_id}: level >= {HIGH_LEVEL} needs a <mitre><id>"))
    return issues


def lint_decoders_file(path: Path) -> list[Issue]:
    name = path.name
    try:
        root = _parse(path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        return [Issue(name, f"not well-formed XML: {exc}")]

    issues: list[Issue] = []
    for decoder in root.iter("decoder"):
        label = decoder.get("name")
        if not label:
            issues.append(Issue(name, "a <decoder> has no name"))
            continue
        if not any(decoder.find(tag) is not None for tag in MATCHERS):
            issues.append(Issue(name, f"decoder {label}: needs one of {', '.join(MATCHERS)}"))
    return issues


def lint_tree(siem_dir: Path) -> list[Issue]:
    """Lint every rules/*.xml and decoders/*.xml under `siem_dir` (e.g. src/detection/siem)."""
    issues: list[Issue] = []
    seen: dict[int, str] = {}
    for rules_file in sorted((siem_dir / "rules").glob("*.xml")):
        issues += lint_rules_file(rules_file, seen)
    for decoders_file in sorted((siem_dir / "decoders").glob("*.xml")):
        issues += lint_decoders_file(decoders_file)
    return issues
