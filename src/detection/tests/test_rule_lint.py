from pathlib import Path

from railsoc_detection.rule_lint import lint_decoders_file, lint_rules_file, lint_tree

SIEM = Path(__file__).resolve().parents[1] / "siem"


def test_the_shipped_rules_and_decoders_are_clean():
    assert lint_tree(SIEM) == []


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_malformed_xml_is_reported(tmp_path):
    issues = lint_rules_file(write(tmp_path, "bad.xml", "<group><rule id='100001'></group>"))
    assert issues and "not well-formed" in issues[0].message


def test_id_range_level_description_and_mitre_are_checked(tmp_path):
    rules = """
    <group name="x,">
      <rule id="5000" level="3"><description>too low an id</description></rule>
      <rule id="100001" level="99"><description>bad level</description></rule>
      <rule id="100002" level="3"></rule>
      <rule id="100003" level="9"><description>no mitre</description></rule>
      <rule id="100004" level="9"><description>ok</description><mitre><id>T1110</id></mitre></rule>
    </group>
    """
    messages = " | ".join(i.message for i in lint_rules_file(write(tmp_path, "r.xml", rules)))
    assert "ids 100000-120000" in messages
    assert "rule 100001: level" in messages
    assert "rule 100002: missing <description>" in messages
    assert "rule 100003: level >= 7 needs" in messages
    assert "100004" not in messages


def test_duplicate_ids_are_found_across_files(tmp_path):
    rule = '<group name="x,"><rule id="100001" level="3"><description>d</description></rule></group>'
    seen: dict[int, str] = {}
    assert lint_rules_file(write(tmp_path, "a.xml", rule), seen) == []
    issues = lint_rules_file(write(tmp_path, "b.xml", rule), seen)
    assert issues and "duplicate id" in issues[0].message


def test_decoders_need_a_name_and_a_matcher(tmp_path):
    decoders = """
    <decoder name="ok"><prematch>^X</prematch></decoder>
    <decoder name="empty"></decoder>
    <decoder><prematch>^Y</prematch></decoder>
    """
    messages = " | ".join(i.message for i in lint_decoders_file(write(tmp_path, "d.xml", decoders)))
    assert "decoder empty" in messages and "has no name" in messages
    assert "decoder ok" not in messages
