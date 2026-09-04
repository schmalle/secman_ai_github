"""Unit tests for skill packs: SKILL.md parsing, resolution, and prompt rendering."""

import pytest

from secscan import skills
from secscan.skills import (
    MAX_SKILL_CHARS,
    Skill,
    SkillError,
    bundled_names,
    bundled_skills,
    load_skill_dir,
    load_skills,
    parse_frontmatter,
    render_skills_prompt,
    resolve_skill,
    skill_dirs,
)


def _write_skill(root, name, body="Look for X.", description="desc", frontmatter=None):
    d = root / name
    d.mkdir(parents=True)
    fm = frontmatter if frontmatter is not None else f"---\nname: {name}\ndescription: {description}\n---\n"
    (d / "SKILL.md").write_text(fm + body, encoding="utf-8")
    return d


# --- frontmatter -----------------------------------------------------------------


def test_parse_frontmatter_plain_scalars():
    meta, body = parse_frontmatter("---\nname: foo\ndescription: \"quoted: value\"\n---\nBody\n")
    assert meta == {"name": "foo", "description": "quoted: value"}
    assert body == "Body"


def test_parse_frontmatter_folded_and_literal_blocks():
    text = (
        "---\n"
        "name: foo\n"
        "description: >\n"
        "  first line\n"
        "  second line\n"
        "notes: |\n"
        "  keep\n"
        "  breaks\n"
        "metadata:\n"
        "  adapted-from: somewhere\n"
        "---\n"
        "Body"
    )
    meta, body = parse_frontmatter(text)
    assert meta["description"] == "first line second line"
    assert meta["notes"] == "keep\nbreaks"
    assert "adapted-from" in meta["metadata"]  # nested mapping kept as raw text
    assert body == "Body"


def test_parse_frontmatter_wrapped_plain_scalar():
    meta, _ = parse_frontmatter("---\ndescription: one\n  two\n---\nx")
    assert meta["description"] == "one two"


def test_parse_frontmatter_absent_means_whole_text_is_body():
    meta, body = parse_frontmatter("# Just markdown\n")
    assert meta == {}
    assert body.startswith("# Just markdown")


def test_parse_frontmatter_unterminated_is_an_error():
    with pytest.raises(SkillError, match="not terminated"):
        parse_frontmatter("---\nname: foo\nBody without closing fence")


# --- loading ---------------------------------------------------------------------


def test_load_skill_dir_reads_name_description_body(tmp_path):
    d = _write_skill(tmp_path, "my-skill", body="Check things.")
    s = load_skill_dir(d)
    assert s.name == "my-skill"
    assert s.description == "desc"
    assert s.body == "Check things."
    assert s.path == d.resolve()
    assert s.skill_md == d.resolve() / "SKILL.md"
    assert s.bundled is False


def test_load_skill_dir_accepts_the_file_itself(tmp_path):
    d = _write_skill(tmp_path, "my-skill")
    assert load_skill_dir(d / "SKILL.md").path == d.resolve()


def test_load_skill_dir_falls_back_to_directory_name(tmp_path):
    d = _write_skill(tmp_path, "dir-name", frontmatter="---\ndescription: d\n---\n")
    assert load_skill_dir(d).name == "dir-name"


def test_load_skill_dir_rejects_invalid_names(tmp_path):
    d = _write_skill(tmp_path, "bad", frontmatter="---\nname: Bad Name!\n---\n")
    with pytest.raises(SkillError, match="lowercase"):
        load_skill_dir(d)


def test_load_skill_dir_rejects_empty_body(tmp_path):
    d = _write_skill(tmp_path, "empty", body="\n\n")
    with pytest.raises(SkillError, match="no body"):
        load_skill_dir(d)


def test_load_skill_dir_rejects_oversized_body(tmp_path):
    d = _write_skill(tmp_path, "huge", body="x" * (MAX_SKILL_CHARS + 1))
    with pytest.raises(SkillError, match="limit"):
        load_skill_dir(d)


def test_load_skill_dir_missing(tmp_path):
    with pytest.raises(SkillError, match="no SKILL.md"):
        load_skill_dir(tmp_path / "nope")


# --- resolution ------------------------------------------------------------------


def test_bundled_skills_all_load_and_are_well_formed():
    found = bundled_skills()
    names = [s.name for s in found]
    assert names == sorted(names)
    assert {"owasp-top10", "false-positive-filter", "cicd-and-iac", "llm-app-security"} <= set(names)
    for s in found:
        assert s.bundled is True
        assert s.description, s.name
        assert s.path.name == s.name  # directory name matches the frontmatter name
        assert len(s.body) < MAX_SKILL_CHARS


def test_resolve_bundled_name():
    s = resolve_skill("owasp-top10")
    assert s.bundled is True
    assert "A05 Injection" in s.body


def test_resolve_path(tmp_path):
    d = _write_skill(tmp_path, "custom")
    assert resolve_skill(str(d)).name == "custom"
    assert resolve_skill(str(d / "SKILL.md")).name == "custom"


def test_resolve_unknown_lists_bundled_names():
    with pytest.raises(SkillError) as exc:
        resolve_skill("no-such-skill")
    msg = str(exc.value)
    assert "no-such-skill" in msg
    for name in bundled_names():
        assert name in msg


def test_resolve_empty_ref():
    with pytest.raises(SkillError):
        resolve_skill("   ")


def test_resolve_bundled_name_wins_over_a_same_named_local_dir(tmp_path, monkeypatch):
    # A directory literally called "owasp-top10" in cwd must not shadow the bundled one.
    monkeypatch.chdir(tmp_path)
    _write_skill(tmp_path, "owasp-top10", body="local override")
    assert resolve_skill("owasp-top10").bundled is True
    assert resolve_skill("./owasp-top10").bundled is False


def test_load_skills_keeps_order_and_dedupes_identical(tmp_path):
    a = _write_skill(tmp_path, "a")
    b = _write_skill(tmp_path, "b")
    loaded = load_skills([str(b), str(a), str(b)])
    assert [s.name for s in loaded] == ["b", "a"]


def test_load_skills_rejects_two_different_skills_with_one_name(tmp_path):
    one = _write_skill(tmp_path / "one", "same")
    two = _write_skill(tmp_path / "two", "same")
    with pytest.raises(SkillError, match="both named 'same'"):
        load_skills([str(one), str(two)])


def test_bundled_skills_empty_when_dir_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(skills, "BUNDLED_DIR", tmp_path / "absent")
    assert bundled_skills() == []


# --- rendering -------------------------------------------------------------------


def test_render_skills_prompt_empty_for_no_skills():
    assert render_skills_prompt([]) == ""


def test_render_skills_prompt_includes_each_skill_and_trust_note(tmp_path):
    a = Skill(name="a", description="first", body="Body A", path=tmp_path / "a")
    b = Skill(name="b", description="", body="Body B", path=tmp_path / "b")
    text = render_skills_prompt([a, b])
    assert "Operator-supplied security skills" in text
    assert "TRUSTED" in text and "read-only" in text
    assert text.index("## Skill: a") < text.index("## Skill: b")
    assert "_first_" in text
    assert "Body A" in text and "Body B" in text
    assert str(tmp_path / "a") in text  # directory shown so references can be found


def test_skill_dirs_are_unique_and_ordered(tmp_path):
    a = Skill(name="a", description="", body="x", path=tmp_path / "a")
    a2 = Skill(name="a2", description="", body="x", path=tmp_path / "a")
    b = Skill(name="b", description="", body="x", path=tmp_path / "b")
    assert skill_dirs([a, a2, b]) == [str(tmp_path / "a"), str(tmp_path / "b")]
