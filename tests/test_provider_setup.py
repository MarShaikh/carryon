"""The Provider table, and the two rclone verbs that act on it (ADR-0011).

A Provider is per-service knowledge the way an Adapter is per-agent
knowledge: which handful of fields that service needs, and nothing else
about it. It lives in one declarative table so the engine keeps no Provider
branches - knowing a Provider is not speaking its protocol; rclone does
that.

The verbs are `rclone config create` and `rclone mkdir`, both on fixed argv
against a fake rclone on a prepended PATH. What `mkdir remote:bucket` does
on a real backend was verified against rclone's own source rather than
guessed: the s3 backend's Mkdir calls CreateBucket (with the configured
ACL and location constraint), the gcs backend's creates the bucket and
refuses without a project number, and b2's posts b2_create_bucket. It
creates buckets, which is why carryon asks first - a bucket is a billable
resource in a region and under a name carryon has no business choosing.
"""

import json
import os
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon.destinations import providers, rclone_setup  # noqa: E402


# --- the table ----------------------------------------------------------------


def test_every_provider_declares_what_the_dialogue_needs():
    assert len(providers.PROVIDERS) >= 4
    keys = [p.key for p in providers.PROVIDERS]
    assert len(keys) == len(set(keys)), "two Providers share a key"
    for p in providers.PROVIDERS:
        assert p.name and p.rclone_type, p.key
        assert p.place and p.place_question, \
            f"{p.key} does not say what the path half of its spec is"
        for field in p.fields:
            assert field.key, p.key
            assert field.question or field.derive, \
                f"{p.key}.{field.key} is neither asked nor derived"


def test_secrets_are_marked_as_secrets():
    """The dialogue echoes ordinary answers and must not echo these."""
    secret_keys = {(p.key, f.key) for p in providers.PROVIDERS
                   for f in p.fields if f.secret}
    assert ("s3", "secret_access_key") in secret_keys
    assert ("r2", "secret_access_key") in secret_keys


def test_no_bucket_holding_provider_lets_a_write_conjure_the_bucket():
    """rclone's UPLOAD creates a missing bucket (s3's prepareUpload and
    gcs's Update both reach makeBucket), which would have had the
    reachability probe create the very bucket the user had just declined -
    a billable resource, silently. So every bucket-holding Provider pins
    no_check_bucket in the Remote's config, and switches it back on for
    exactly one call: the offered creation the user said yes to. B2 is
    absent from the table because its upload has no such switch."""
    for p in providers.PROVIDERS:
        if not p.place_costs:
            continue
        assert ("no_check_bucket", "true") in p.fixed, \
            f"{p.key}: an ordinary write can create a bucket"
        assert any("no-check-bucket=false" in flag
                   for flag in p.mkdir_flags), \
            f"{p.key}: the offered creation is a no-op under its own config"
    assert not any(p.key == "b2" or p.rclone_type == "b2"
                   for p in providers.PROVIDERS)


def test_r2_derives_its_endpoint_from_the_account_id():
    r2 = next(p for p in providers.PROVIDERS if p.key == "r2")
    answers = {"_account_id": "abc123", "access_key_id": "AK",
               "secret_access_key": "SK"}
    pairs = dict(providers.config_pairs(r2, answers))

    assert pairs["endpoint"] == "https://abc123.r2.cloudflarestorage.com"
    assert pairs["provider"] == "Cloudflare"
    assert "_account_id" not in pairs, \
        "an answer that only feeds a derivation reached rclone's config"


def test_aws_location_constraint_follows_the_region():
    """Used when creating buckets only, and us-east-1 is spelled by leaving
    it out - rclone's own config flow says 'Empty for US Region'."""
    s3 = next(p for p in providers.PROVIDERS if p.key == "s3")

    east = dict(providers.config_pairs(
        s3, {"access_key_id": "AK", "secret_access_key": "SK",
             "region": "us-east-1"}))
    assert "location_constraint" not in east

    eu = dict(providers.config_pairs(
        s3, {"access_key_id": "AK", "secret_access_key": "SK",
             "region": "eu-west-1"}))
    assert eu["location_constraint"] == "eu-west-1"


def test_sftp_needs_no_credential_fields_at_all():
    """ssh-agent is the ordinary way in, so the table must not invent a
    password question rclone does not need."""
    sftp = next(p for p in providers.PROVIDERS if p.key == "sftp")
    assert not any(f.secret for f in sftp.fields)
    assert sftp.place == "directory"


# --- the verbs, against a fake rclone -----------------------------------------


FAKE = """#!__PY__
import json, pathlib, sys
LOG = pathlib.Path("__LOG__")
CTL = pathlib.Path("__CTL__")
with LOG.open("a") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\\n")
ctl = json.loads(CTL.read_text() or "{}") if CTL.is_file() else {}
verb = sys.argv[1] if len(sys.argv) > 1 else ""
if verb in ctl.get("fail", {}):
    sys.stderr.write(ctl["fail"][verb] + "\\n")
    raise SystemExit(1)
if verb == "listremotes":
    sys.stdout.write(ctl.get("remotes", ""))
"""


class FakeRclone:
    def __init__(self, log, ctl):
        self.log, self.ctl = log, ctl

    def argv_log(self):
        return [json.loads(line)
                for line in self.log.read_text().splitlines()]

    def set(self, **kw):
        current = json.loads(self.ctl.read_text() or "{}")
        current.update(kw)
        self.ctl.write_text(json.dumps(current))


@pytest.fixture
def fake_rclone(tmp_path, monkeypatch):
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    log = tmp_path / "rclone-argv.log"
    log.write_text("")
    ctl = tmp_path / "rclone-ctl.json"
    ctl.write_text("{}")
    script = bin_dir / "rclone"
    script.write_text(FAKE.replace("__PY__", sys.executable)
                          .replace("__LOG__", str(log))
                          .replace("__CTL__", str(ctl)))
    script.chmod(0o755)
    monkeypatch.setenv("PATH",
                       f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return FakeRclone(log, ctl)


def test_create_remote_runs_config_create_on_fixed_argv(fake_rclone):
    rclone_setup.create_remote(
        "carryon", "s3",
        [("provider", "AWS"), ("access_key_id", "AK"),
         ("secret_access_key", "SK"), ("region", "us-east-1")])

    create = [argv for argv in fake_rclone.argv_log()
              if argv[:2] == ["config", "create"]]
    assert create == [[
        "config", "create", "carryon", "s3",
        "provider=AWS", "access_key_id=AK", "secret_access_key=SK",
        "region=us-east-1", "--non-interactive",
    ]], "the argv is fixed - nothing user-typed becomes a flag"


def test_create_remote_refuses_a_name_rclone_already_has(fake_rclone):
    """`rclone config create` over an existing name UPDATES it. A Remote
    belongs to rclone and the user; carryon may create one and never
    rewrite one it did not just make."""
    fake_rclone.set(remotes="carryon:\nother:\n")

    with pytest.raises(SystemExit) as exc:
        rclone_setup.create_remote("carryon", "s3", [("provider", "AWS")])

    assert "carryon" in str(exc.value)
    assert "already" in str(exc.value)
    assert not [argv for argv in fake_rclone.argv_log()
                if argv[:2] == ["config", "create"]], \
        "the existing remote was rewritten anyway"


def test_create_remote_quotes_rclone_when_it_refuses(fake_rclone):
    fake_rclone.set(fail={"config": "didn't like that type"})

    with pytest.raises(SystemExit) as exc:
        rclone_setup.create_remote("carryon", "nosuch", [])

    assert "didn't like that type" in str(exc.value)


def test_a_leading_dash_cannot_turn_an_answer_into_a_flag(fake_rclone):
    """The fixed-argv promise, probed at its edge: a remote named
    '--config' or a value of '-v' must land after `--` or be refused, not
    reach rclone as an option."""
    with pytest.raises(SystemExit) as exc:
        rclone_setup.create_remote("--config", "s3", [])
    assert "name" in str(exc.value).lower()
    assert not fake_rclone.argv_log(), "the argv was run anyway"


def test_a_nul_anywhere_in_the_argv_is_refused_not_a_traceback(fake_rclone):
    """subprocess answers an embedded NUL with a ValueError whose text is
    not even the same on two interpreters (cli.py's door says the same of a
    path). A secret is the one dialogue answer no other door sees, so this
    is where it is caught."""
    with pytest.raises(SystemExit) as exc:
        rclone_setup.create_remote(
            "carryon", "s3", [("secret_access_key", "SE\x00KRIT")])
    assert "NUL" in str(exc.value)
    assert "SE\\x00KRIT" not in str(exc.value) and "SEKRIT" not in str(
        exc.value), "the refusal echoed the secret"
    assert not fake_rclone.argv_log()

    why = rclone_setup.make_place("carryon:bad\x00name")
    assert why is not None and "NUL" in why


def test_make_place_runs_mkdir_and_reports_failure(fake_rclone):
    assert rclone_setup.make_place("carryon:my-bucket") is None
    assert ["mkdir", "carryon:my-bucket"] in fake_rclone.argv_log()

    fake_rclone.set(fail={"mkdir": "AccessDenied: not yours to make"})
    why = rclone_setup.make_place("carryon:other")
    assert why is not None and "AccessDenied" in why


def test_make_place_carries_the_tables_flags(fake_rclone):
    """The one call allowed to create a bucket un-suppresses the check the
    Remote's own config pins (providers.py says why)."""
    assert rclone_setup.make_place("carryon:my-bucket",
                                   ("--s3-no-check-bucket=false",)) is None
    assert ["mkdir", "carryon:my-bucket",
            "--s3-no-check-bucket=false"] in fake_rclone.argv_log()


def test_missing_rclone_is_one_clear_sentence(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    with pytest.raises(SystemExit) as exc:
        rclone_setup.create_remote("carryon", "s3", [])
    assert "rclone" in str(exc.value)
