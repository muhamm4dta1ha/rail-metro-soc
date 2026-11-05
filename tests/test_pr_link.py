import subprocess

import pr_link
import pytest


def test_parse_remote_url_variants():
    expected = "acme/rail-metro-soc"
    assert pr_link.parse_remote_url("https://github.com/acme/rail-metro-soc.git") == expected
    assert pr_link.parse_remote_url("https://github.com/acme/rail-metro-soc") == expected
    assert pr_link.parse_remote_url("git@github.com:acme/rail-metro-soc.git") == expected
    assert pr_link.parse_remote_url("ssh://git@github.com/acme/rail-metro-soc.git") == expected
    with pytest.raises(ValueError):
        pr_link.parse_remote_url("https://gitlab.com/acme/rail-metro-soc.git")


def test_suggest_title_follows_conventional_commits():
    assert pr_link.suggest_title("feature/sim/M1-04-pis-service") == "feat(sim): M1-04 pis service"
    assert pr_link.suggest_title("feature/detection/M3-04-rules") == "feat(detect): M3-04 rules"
    assert pr_link.suggest_title("docs/docs/update-plan") == "docs(docs): update plan"
    assert pr_link.suggest_title("fix/common/typo") == "fix(common): typo"
    assert pr_link.suggest_title("random-branch") == "random branch"


def test_build_url_keeps_slashes_and_encodes_the_title():
    url = pr_link.build_url("acme/r", "develop", "feature/sim/M1-04-x", "feat(sim): M1-04 x")
    assert url.startswith("https://github.com/acme/r/compare/develop...feature/sim/M1-04-x?expand=1")
    assert "title=feat%28sim%29%3A%20M1-04%20x" in url
    assert "body=" not in url


def test_main_prints_a_link_for_the_given_head(capsys):
    assert pr_link.main(["--repo", "acme/r", "--head", "feature/ml/M4-05-features"]) == 0
    out = capsys.readouterr().out
    assert "compare/develop...feature/ml/M4-05-features" in out
    assert "title=feat%28ml%29%3A%20M4-05%20features" in out


def test_main_release_links_develop_into_main(capsys):
    assert pr_link.main(["--repo", "acme/r", "--release"]) == 0
    assert "compare/main...develop" in capsys.readouterr().out


def test_main_refuses_develop_or_main_as_a_feature_head(capsys):
    assert pr_link.main(["--repo", "acme/r", "--head", "develop"]) == 2
    assert pr_link.main(["--repo", "acme/r", "--head", "main"]) == 2
    assert "cannot be the source" in capsys.readouterr().err


def _git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def test_all_lists_only_branches_that_are_ahead(tmp_path, monkeypatch, capsys):
    _git(tmp_path, "init", "-b", "develop")
    (tmp_path / "a.txt").write_text("a")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "init")
    _git(tmp_path, "switch", "-c", "feature/sim/M1-01-assets")
    (tmp_path / "b.txt").write_text("b")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "work")
    _git(tmp_path, "switch", "develop")
    _git(tmp_path, "branch", "feature/ml/M4-01-idle")  # same commit as develop -> not ahead

    monkeypatch.chdir(tmp_path)
    assert pr_link.main(["--repo", "acme/r", "--all"]) == 0
    out = capsys.readouterr().out
    assert "feature/sim/M1-01-assets" in out
    assert "M4-01-idle" not in out
