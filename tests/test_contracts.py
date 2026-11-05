"""Repo-level contract tests: keep the modules consistent and enforce the hard constraints.

HC-17 (plan lists every hard constraint), HC-18 (isolated lab), HC-14 (workflow gates),
HC-20 (no secrets / big files in git). See plan/PLAN.md section 2.
"""

import csv
import ipaddress
from pathlib import Path

import yaml

from railsoc_common.lab import LAB_CIDR, ZONES

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "src" / "simulation" / "docker-compose.yml"
ASSETS = ROOT / "src" / "simulation" / "config" / "assets.csv"
PLAN = ROOT / "plan" / "PLAN.md"

HARD_CONSTRAINT_IDS = [f"HC-{n:02d}" for n in range(1, 23)]
TEAM = ("Talha", "Furqan", "Roshni", "Anum")

# The repo root stays tidy: code in src/, docs in docs/, plan in plan/, lab outputs in lab/.
ALLOWED_ROOT_DIRS = {".github", "docs", "lab", "plan", "scripts", "src", "tests"}
ALLOWED_ROOT_FILES = {
    "README.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "pyproject.toml",
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
    ".dockerignore",
}
LOCAL_ARTIFACTS = {".git", ".venv", "venv", ".pytest_cache", ".ruff_cache", "build", "dist"}
MODULES = {"common", "simulation", "attacks", "detection", "ml"}


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def test_every_lab_network_is_internal_and_matches_its_zone():
    networks = _compose()["networks"]
    assert set(networks) == set(ZONES)
    for name, cfg in networks.items():
        assert cfg.get("internal") is True, f"{name} must be internal (HC-18)"
        subnets = [entry["subnet"] for entry in cfg["ipam"]["config"]]
        assert subnets == [str(ZONES[name])]
        assert ipaddress.ip_network(subnets[0]).subnet_of(LAB_CIDR)


def test_compose_static_ips_are_in_the_asset_inventory_in_the_right_zone():
    with ASSETS.open(encoding="utf-8") as fh:
        by_ip = {row["ip"]: row for row in csv.DictReader(fh)}
    for service_name, service in _compose()["services"].items():
        for network_name, cfg in (service.get("networks") or {}).items():
            ip = cfg["ipv4_address"]
            assert ip in by_ip, f"{service_name}: {ip} is missing from assets.csv"
            assert by_ip[ip]["zone"] == network_name, f"{service_name}: {ip} is in the wrong zone"


def test_services_only_publish_ports_on_localhost():
    for name, service in _compose()["services"].items():
        for port in service.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), f"{name}: publish ports on 127.0.0.1 only"


def test_compose_build_context_reaches_the_shared_packages():
    service = _compose()["services"]["pis"]["build"]
    context = (COMPOSE.parent / service["context"]).resolve()
    assert context == ROOT
    assert (context / service["dockerfile"]).is_file()


def test_gitignore_protects_secrets_and_big_captures():
    lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for pattern in (".env", "*.pcap", "*.pcapng", "lab/data/*", "src/ml/models/*", "/context/"):
        assert pattern in lines, f".gitignore must contain {pattern}"


def test_repo_root_stays_tidy():
    unexpected = []
    for entry in ROOT.iterdir():
        if entry.name in LOCAL_ARTIFACTS or entry.name.endswith(".egg-info"):
            continue
        allowed = ALLOWED_ROOT_DIRS if entry.is_dir() else ALLOWED_ROOT_FILES
        if entry.name not in allowed:
            unexpected.append(entry.name)
    assert not unexpected, f"unexpected top-level entries (keep the root tidy): {unexpected}"
    modules = {p.name for p in (ROOT / "src").iterdir() if p.is_dir() and p.name != "__pycache__"}
    assert modules == MODULES, "src/ holds exactly the five module folders"


def test_plan_lists_every_hard_constraint():
    plan = PLAN.read_text(encoding="utf-8")
    missing = [hc for hc in HARD_CONSTRAINT_IDS if f"| {hc} |" not in plan]
    assert not missing, f"plan/PLAN.md section 2 is missing: {missing}"


def test_plan_names_every_team_member_where_their_part_is_described():
    plan = PLAN.read_text(encoding="utf-8")
    for name in TEAM:
        assert plan.count(name) >= 10, f"plan/PLAN.md must name {name} next to their tasks"


def test_pr_template_requires_the_local_checks():
    template = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    assert "check_all" in template


def test_ci_workflow_exposes_the_required_gate():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "ci-gate" in workflow and "develop" in workflow and "main" in workflow
