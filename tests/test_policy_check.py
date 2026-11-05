import policy_check as pc


def test_feature_branches_may_target_develop():
    for head in (
        "feature/sim/M1-04-pis-service",
        "feature/attacks/M2-04-admin-access",
        "feature/detection/M3-04-rules",
        "feature/ml/M4-07-supervised-models",
        "fix/common/event-schema-typo",
        "docs/docs/update-plan",
        "chore/ci/pin-python",
    ):
        assert pc.check_branch(head, "develop") == [], head


def test_badly_named_branches_are_rejected():
    for head in ("my-branch", "feature/M1-04", "feature/unknown/x", "develop", "main", "hotfix/sim/x"):
        assert pc.check_branch(head, "develop"), head


def test_only_develop_may_be_released_into_main():
    assert pc.check_branch("develop", "main") == []
    assert pc.check_branch("feature/sim/M1-04-x", "main")
    assert pc.check_branch("feature/sim/M1-04-x", "some-other-branch")


def test_ai_attribution_is_detected():
    text = "\n".join(
        [
            "feat(sim): add PIS stub",
            "",
            "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>",
            "Generated with [Claude Code](https://claude.com/claude-code)",
            "Reviewed-by: Assistant <noreply@anthropic.com>",
        ]
    )
    assert len(pc.find_ai_attribution(text)) == 3


def test_human_coauthors_are_fine():
    text = "feat(ml): add features\n\nCo-authored-by: Alice Example <alice@example.com>\n"
    assert pc.find_ai_attribution(text) == []


def test_secret_and_oversized_files_are_rejected(tmp_path):
    (tmp_path / ".env").write_text("X=1")
    (tmp_path / ".env.example").write_text("X=changeme")
    (tmp_path / "big.bin").write_bytes(b"0" * 2048)
    (tmp_path / "ok.txt").write_text("ok")
    errors = pc.check_files([".env", ".env.example", "big.bin", "ok.txt", "key.pem"], tmp_path, 1024)
    flagged = " ".join(errors)
    assert ".env:" in flagged and "big.bin" in flagged and "key.pem" in flagged
    assert ".env.example" not in flagged and "ok.txt" not in flagged


def test_cli_exit_codes(tmp_path, capsys):
    assert pc.main(["branch", "--head", "feature/sim/M1-04-x", "--base", "develop"]) == 0
    assert pc.main(["branch", "--head", "oops", "--base", "develop"]) == 1
    assert "POLICY VIOLATION" in capsys.readouterr().err

    clean = tmp_path / "clean.txt"
    clean.write_text("feat(sim): fine\n", encoding="utf-8")
    dirty = tmp_path / "dirty.txt"
    dirty.write_text("Co-Authored-By: Claude <noreply@anthropic.com>\n", encoding="utf-8")
    assert pc.main(["attribution", "--file", str(clean)]) == 0
    assert pc.main(["attribution", "--file", str(dirty)]) == 1
