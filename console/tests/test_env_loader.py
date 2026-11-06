from app.env_loader import load_env_file, parse_env_text


def test_parse_handles_comments_quotes_and_export():
    values = parse_env_text('# note\nA=1\nexport B="two words"\nC=\'x\'\n\nbad line\n1BAD=no\nD =  spaced \n')
    assert values == {"A": "1", "B": "two words", "C": "x", "D": "spaced"}


def test_load_fills_only_missing_values(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("KEEP=file\nNEW=file\nBLANK=\n", encoding="utf-8")
    target = {"KEEP": "real"}
    applied = load_env_file(str(env_file), target)
    assert target == {"KEEP": "real", "NEW": "file"}
    assert applied == ["NEW"]


def test_blank_template_value_does_not_mask_existing_empty_variable(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("KEY=\n", encoding="utf-8")
    target = {}
    assert load_env_file(str(env_file), target) == []
    assert "KEY" not in target


def test_missing_file_is_ignored(tmp_path):
    assert load_env_file(str(tmp_path / "absent.env"), {}) == []
