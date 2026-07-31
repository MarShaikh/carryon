"""Re-keying behaviour, exercised on synthetic Transcript lines.

Every path here belongs to a fake home ("/Users/someone", "/home/elsewhere").
No real Transcript content appears and no real directory names either - the
fixtures were written for these tests, and the encode_project_dir pairs are
synthetic paths exercising the character classes the live verification saw.
"""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import rekey  # noqa: E402

FAKE_HOME = "/Users/someone"
OTHER_HOME = "/home/elsewhere"


def jsonl(*objs) -> str:
    return "".join(json.dumps(o, separators=(",", ":")) + "\n" for o in objs)


def parsed(text):
    return [json.loads(line) for line in text.splitlines() if line]


# --- canonicalise: home -> '~' inside string values ------------------------

def test_cwd_field_is_canonicalised():
    out, stats = rekey.canonicalise_jsonl(
        jsonl({"cwd": FAKE_HOME + "/proj"}), FAKE_HOME)
    assert parsed(out) == [{"cwd": "~/proj"}]
    assert stats.lines == 1
    assert stats.rewritten_values == 1


def test_mid_string_occurrences_in_prose():
    obj = {"text": f"edited {FAKE_HOME}/proj/a.py then {FAKE_HOME}/proj/b.py"}
    out, stats = rekey.canonicalise_jsonl(jsonl(obj), FAKE_HOME)
    assert parsed(out) == [{"text": "edited ~/proj/a.py then ~/proj/b.py"}]
    assert stats.rewritten_values == 1, "counted per value, not per occurrence"


def test_nested_structures_are_walked():
    obj = {"message": {"content": [
               {"input": {"file_path": FAKE_HOME + "/proj/main.py"}},
               {"content": f"wrote {FAKE_HOME}/proj/main.py"}]},
           "toolUseResult": FAKE_HOME + "/proj",
           "count": 3, "ok": True, "gone": None}
    out, stats = rekey.canonicalise_jsonl(jsonl(obj), FAKE_HOME)
    assert parsed(out) == [{"message": {"content": [
                               {"input": {"file_path": "~/proj/main.py"}},
                               {"content": "wrote ~/proj/main.py"}]},
                           "toolUseResult": "~/proj",
                           "count": 3, "ok": True, "gone": None}]
    assert stats.rewritten_values == 3


def test_value_exactly_home_becomes_the_bare_token():
    out, _ = rekey.canonicalise_jsonl(jsonl({"home": FAKE_HOME}), FAKE_HOME)
    assert parsed(out) == [{"home": "~"}]


def test_keys_are_never_rewritten():
    key = FAKE_HOME + "/proj"
    out, stats = rekey.canonicalise_jsonl(
        jsonl({key: {"cwd": key}}), FAKE_HOME)
    assert parsed(out) == [{key: {"cwd": "~/proj"}}]
    assert stats.rewritten_values == 1


def test_near_miss_is_counted_never_rewritten():
    line = json.dumps({"note": "try /users/someone/proj today"},
                      separators=(",", ":"))
    out, stats = rekey.canonicalise_jsonl(line + "\n", FAKE_HOME)
    assert out == line + "\n", "case-insensitive-only match must survive"
    assert stats.near_misses == 1
    assert stats.rewritten_values == 0


def test_worst_case_home_glued_to_prose_still_parses():
    # ADR-0006's accepted bounded worst case: confining rewrites to string
    # values means a home immediately followed by non-path text rewrites to
    # something semantically odd, never structurally broken. FAKE_HOME +
    # "lse" reads like another user's dir but contains the home, so it
    # becomes "~lse" - and the line must still re-parse as JSON.
    obj = {"text": f"ask {FAKE_HOME}lse about it"}
    out, stats = rekey.canonicalise_jsonl(jsonl(obj), FAKE_HOME)
    assert parsed(out) == [{"text": "ask ~lse about it"}]
    assert stats.rewritten_values == 1
    assert stats.malformed == 0


def test_malformed_line_survives_byte_identical():
    good = json.dumps({"cwd": FAKE_HOME + "/proj"}, separators=(",", ":"))
    bad = '{"cwd": "/Users/someone/tru'  # truncated mid-write
    out, stats = rekey.canonicalise_jsonl(
        good + "\n" + bad + "\n" + good + "\n", FAKE_HOME)
    lines = out.split("\n")
    assert lines[1] == bad
    assert stats.lines == 3
    assert stats.malformed == 1
    assert json.loads(lines[0]) == {"cwd": "~/proj"}


def test_untouched_lines_pass_through_byte_identical():
    # Odd spacing would not survive re-serialisation; a line with nothing to
    # rewrite must not be re-serialised at all, or pull's byte comparison
    # would call every Session divergent.
    line = '{"a":     "no paths here",  "b": 1}'
    out, stats = rekey.canonicalise_jsonl(line + "\n", FAKE_HOME)
    assert out == line + "\n"
    assert stats.rewritten_values == 0
    assert stats.malformed == 0


# --- expand: '~' -> local home, then --map pairs ---------------------------

def test_expand_restores_under_a_different_home():
    canon = jsonl({"cwd": "~/proj", "note": "see ~/proj/a.py"}, {"home": "~"})
    out, stats = rekey.expand_jsonl(canon, OTHER_HOME)
    assert parsed(out) == [
        {"cwd": OTHER_HOME + "/proj", "note": f"see {OTHER_HOME}/proj/a.py"},
        {"home": OTHER_HOME}]
    assert stats.rewritten_values == 3, "cwd, note and the bare-token value"


def test_expand_leaves_a_bare_mid_string_tilde_alone():
    line = json.dumps({"note": "takes ~5 minutes"}, separators=(",", ":"))
    out, stats = rekey.expand_jsonl(line + "\n", OTHER_HOME)
    assert out == line + "\n"
    assert stats.rewritten_values == 0


def test_round_trip_restores_paths_under_a_different_home():
    objs = [
        {"cwd": FAKE_HOME + "/proj",
         "note": f"edited {FAKE_HOME}/proj/a.py and {FAKE_HOME}/proj/b.py"},
        {"home": FAKE_HOME},
        {"nested": [{"file_path": FAKE_HOME + "/dir/f"}]},
    ]
    canon, _ = rekey.canonicalise_jsonl(jsonl(*objs), FAKE_HOME)
    assert FAKE_HOME not in canon, "the Archive form must be machine-neutral"
    out, _ = rekey.expand_jsonl(canon, OTHER_HOME)
    assert parsed(out) == [
        {"cwd": OTHER_HOME + "/proj",
         "note": f"edited {OTHER_HOME}/proj/a.py and {OTHER_HOME}/proj/b.py"},
        {"home": OTHER_HOME},
        {"nested": [{"file_path": OTHER_HOME + "/dir/f"}]},
    ]


def test_maps_apply_longest_old_first():
    # Given shortest-first on purpose; the longer OLD must still win.
    maps = [("/data", "/mnt"), ("/data/projects", "/srv/projects")]
    out, _ = rekey.expand_jsonl(
        jsonl({"path": "/data/projects/x/file"}), OTHER_HOME, maps=maps)
    assert parsed(out) == [{"path": "/srv/projects/x/file"}]


def test_map_case_mismatch_is_a_near_miss():
    out, stats = rekey.expand_jsonl(
        jsonl({"path": "/data/proj/file"}), OTHER_HOME,
        maps=[("/Data/Proj", "/x")])
    assert parsed(out) == [{"path": "/data/proj/file"}]
    assert stats.near_misses == 1
    assert stats.rewritten_values == 0


def test_map_near_miss_is_counted_beside_an_exact_hit():
    # Occurrence-wise, matching canonicalise: an exact hit in the same value
    # must not swallow the case-variant one.
    out, stats = rekey.expand_jsonl(
        jsonl({"note": "in /data/proj and /DATA/PROJ"}), OTHER_HOME,
        maps=[("/data/proj", "/x")])
    assert parsed(out) == [{"note": "in /x and /DATA/PROJ"}]
    assert stats.rewritten_values == 1
    assert stats.near_misses == 1


# --- one home, more than one true name -------------------------------------


def symlinked_home(tmp_path):
    """A home reachable by two paths: <tmp>/link/me and <tmp>/real/me.

    Built rather than borrowed from the runner's temp directory, which is
    where this bug was found but is not the same shape on every machine.
    """
    (tmp_path / "real" / "me").mkdir(parents=True)
    (tmp_path / "link").symlink_to(tmp_path / "real")
    home = tmp_path / "link" / "me"
    assert str(home) != str(home.resolve()), "the fixture built no symlink"
    return home


def test_the_other_spelling_of_a_symlinked_home_is_rewritten_too(tmp_path):
    """A Transcript records whatever the process that wrote it saw.

    A shell prints the resolved path while the CLI hands push an unresolved
    $HOME, so one Session holds both spellings of one directory. Knowing only
    one of them shipped the other to the Archive verbatim - and where the two
    overlap, rewriting the shorter first left '/private~/proj', which is
    neither what was recorded nor machine-neutral and expands on the
    receiving machine into a directory that cannot exist. The Setup half has
    had this fix; the History half went without it.
    """
    home = symlinked_home(tmp_path)
    line = jsonl({"cwd": f"{home}/proj",
                  "text": f"cd {home.resolve()}/proj && pwd"})

    out, stats = rekey.canonicalise_jsonl(line, home)

    assert parsed(out) == [{"cwd": "~/proj", "text": "cd ~/proj && pwd"}]
    assert str(tmp_path) not in out, "a fragment of the real home survived"
    assert stats.rewritten_values == 2

    back, _ = rekey.expand_jsonl(out, OTHER_HOME)
    assert parsed(back) == [{"cwd": OTHER_HOME + "/proj",
                             "text": f"cd {OTHER_HOME}/proj && pwd"}]


def test_the_other_spelling_goes_from_plain_text_as_well(tmp_path):
    """Memory files are prose about the same directories a Transcript
    records, and travel in the same encrypted object."""
    home = symlinked_home(tmp_path)
    md = f"Notes in {home}/notes; the shell called it {home.resolve()}.\n"

    out, stats = rekey.canonicalise_text(md, home)

    assert out == "Notes in ~/notes; the shell called it ~.\n"
    assert str(tmp_path) not in out
    assert stats.replaced == 2
    assert stats.bare_tokens == 1, "the trailing '~' expands back to nothing"


def test_home_forms_are_longest_first_so_no_form_can_eat_another(tmp_path):
    """The ordering is the whole fix where one spelling contains another:
    '/var/.../x' rewritten before '/private/var/.../x' leaves '/private~'."""
    forms = rekey.home_forms(symlinked_home(tmp_path))
    assert forms == sorted(forms, key=len, reverse=True)
    assert len(forms) == len(set(forms)), "a spelling is listed twice"


# --- non-JSONL text and raw bytes ------------------------------------------

def test_plain_text_round_trip():
    md = f"Notes live in {FAKE_HOME}/notes and {FAKE_HOME}/inbox.\n"
    canon, stats = rekey.canonicalise_text(md, FAKE_HOME)
    assert canon == "Notes live in ~/notes and ~/inbox.\n"
    assert stats.replaced == 2
    assert stats.near_misses == 0
    assert stats.bare_tokens == 0
    back, back_stats = rekey.expand_text(canon, OTHER_HOME)
    assert back == md.replace(FAKE_HOME, OTHER_HOME)
    assert back_stats.replaced == 2


def test_expand_text_applies_maps_longest_first():
    out, stats = rekey.expand_text("in /data/projects/x and /data/y\n",
                                   OTHER_HOME,
                                   maps=[("/data", "/mnt"),
                                         ("/data/projects", "/srv/projects")])
    assert out == "in /srv/projects/x and /mnt/y\n"
    assert stats.replaced == 2


def test_canonicalise_text_reports_home_near_misses():
    md = f"see /users/someone/notes not {FAKE_HOME}/notes\n"
    out, stats = rekey.canonicalise_text(md, FAKE_HOME)
    assert out == "see /users/someone/notes not ~/notes\n", \
        "case-insensitive-only match must survive"
    assert stats.replaced == 1
    assert stats.near_misses == 1


def test_expand_text_reports_map_near_misses():
    out, stats = rekey.expand_text("see /Data/Proj here\n", OTHER_HOME,
                                   maps=[("/data/proj", "/x")])
    assert out == "see /Data/Proj here\n", "never rewritten, only reported"
    assert stats.replaced == 0
    assert stats.near_misses == 1


def test_expand_text_map_near_miss_is_counted_beside_an_exact_hit():
    out, stats = rekey.expand_text("in /data/proj and /DATA/PROJ\n",
                                   OTHER_HOME, maps=[("/data/proj", "/x")])
    assert out == "in /x and /DATA/PROJ\n"
    assert stats.replaced == 1
    assert stats.near_misses == 1


def test_bare_token_round_trip_gap_is_surfaced_both_ways():
    # A home at the end of a sentence canonicalises to a bare '~', which
    # expand cannot safely restore (in prose '~' also means "approximately").
    # The gap is allowed but must be countable, so pull can report it instead
    # of the asymmetry hiding in a docstring.
    canon, push_stats = rekey.canonicalise_text(
        f"the root is {FAKE_HOME}.\n", FAKE_HOME)
    assert canon == "the root is ~.\n"
    assert push_stats.replaced == 1
    assert push_stats.bare_tokens == 1
    back, pull_stats = rekey.expand_text(canon, OTHER_HOME)
    assert back == canon, "a bare '~' is left alone"
    assert pull_stats.replaced == 0
    assert pull_stats.bare_tokens == 1


def test_non_utf8_bytes_come_back_unchanged_and_flagged():
    blob = b"\x89PNG\r\n\x1a\n" + bytes(range(256))
    out, stats, is_utf8 = rekey.apply_to_bytes(
        blob, lambda t: rekey.canonicalise_text(t, FAKE_HOME))
    assert out == blob
    assert stats is None
    assert is_utf8 is False


def test_utf8_bytes_are_rewritten():
    data = f"path {FAKE_HOME}/x é".encode("utf-8")
    out, stats, is_utf8 = rekey.apply_to_bytes(
        data, lambda t: rekey.canonicalise_text(t, FAKE_HOME))
    assert is_utf8 is True
    assert out == "path ~/x é".encode("utf-8")
    assert stats.replaced == 1


# --- read_cwd ---------------------------------------------------------------

def test_read_cwd_returns_the_first_cwd_skipping_junk(tmp_path):
    p = tmp_path / "0000-fake-uuid.jsonl"
    p.write_text("not json at all\n"
                 '{"type":"meta"}\n'
                 '{"cwd":"/Users/someone/proj"}\n'
                 '{"cwd":"/Users/someone/other"}\n')
    assert rekey.read_cwd(p) == "/Users/someone/proj"


def test_read_cwd_is_none_when_no_line_has_one(tmp_path):
    p = tmp_path / "0000-fake-uuid.jsonl"
    p.write_text('{"type":"meta"}\n')
    assert rekey.read_cwd(p) is None


# --- encode_project_dir -----------------------------------------------------

# The encoding rule was verified read-only against a live ~/.claude/projects
# on 2026-07-29 (six dir names matched against each dir's first recorded cwd).
# These pairs are synthetic - carryon is public, so no real directory names -
# but they exercise every character class that verification covered:
# '/', '_' and ' ' each become '-'; a literal '-' survives; case survives.
ENCODING_PAIRS = [
    ("/Users/someone/Documents",
     "-Users-someone-Documents"),
    ("/Users/someone/Documents/ABC",
     "-Users-someone-Documents-ABC"),
    ("/Users/someone/code/snake_case_dir/deep/nested/sub",
     "-Users-someone-code-snake-case-dir-deep-nested-sub"),
    ("/Users/someone/code/Mixed_Case/Sub_Dir_Name",
     "-Users-someone-code-Mixed-Case-Sub-Dir-Name"),
    ("/Users/someone/code/dash-name",
     "-Users-someone-code-dash-name"),
    ("/Users/someone/notes/Two words",
     "-Users-someone-notes-Two-words"),
]


def test_encode_project_dir_matches_every_character_class():
    for cwd, expected in ENCODING_PAIRS:
        assert rekey.encode_project_dir(cwd) == expected, cwd


def test_encoding_collapses_and_cannot_be_decoded():
    # Three different cwds, one dir name: the reason ADR-0006 derives the
    # name from the recorded cwd instead of ever decoding it.
    names = {rekey.encode_project_dir(c) for c in
             ["/Users/x/a-b", "/Users/x/a_b", "/Users/x/a b"]}
    assert names == {"-Users-x-a-b"}
