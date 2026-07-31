"""Attack tests: what an untrusted Destination gets to see, and to serve back.

Written as the exploit rather than the invariant, because each of these was
once possible:

1. The pairing object's name is published on the Destination. It used to be
   sha256(canonical code)[:16] - an unsalted, single-iteration digest of the
   very secret the 600,000-iteration wrap exists to protect. The name is now
   the code's locator half, drawn independently of the secret half, so the
   name is a function of nothing anyone needs to guard.

2. A Destination may serve any blob it holds under any key it likes, and
   nothing in an Archive object used to say where it belonged. Every object
   now authenticates against its own label before a byte is decrypted.

3. Keys come back from the Destination's own listing, so read_tree treats
   them as input and validates before it makes a directory for one.

Every home here is a temp dir and the OS keychain is forced to the fallback
file, so nothing touches the real keyring or the real ~/.claude.
"""

import argparse
import hashlib
import json
import pathlib
import re
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, config, crypto, keyring, rekey, sync  # noqa: E402
from carryon.destinations.base import Destination  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402

PAIR_CODE = re.compile(r"--join (\S+)")

MASTER = bytes(range(32))
UUID_A = "6b3c1c2e-9a71-4f0e-8f2d-4a5b6c7d8e9f"
UUID_B = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
TAR_A = b"\x1f\x8b Session A tree bytes" * 20
TAR_B = b"\x1f\x8b Session B tree bytes" * 20


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


@pytest.fixture
def dest(tmp_path):
    return DirectoryDestination(tmp_path / "archive")


def ns(**kw) -> argparse.Namespace:
    base = dict(dest=None, join=None, machine=None, apply=False, agent=None,
                category=None, force=False)
    base["map"] = []
    base.update(kw)
    return argparse.Namespace(**base)


def paired_machine(tmp_path):
    """A home that already opens an Archive at a directory Destination."""
    home = tmp_path / "home_a"
    home.mkdir()
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    return home, dest_spec


def mint(home, capsys) -> str:
    sync.pair(ns(), home)
    return PAIR_CODE.search(capsys.readouterr().out).group(1)


def fresh_home(tmp_path, name) -> pathlib.Path:
    home = tmp_path / name
    home.mkdir()
    return home


def make_meta():
    return {"agent": "claude", "cwd": "~/p", "machine": "laptop",
            "tree_hash": "a" * 64, "pushed_at": "2026-07-30T00:00:00Z"}


# --- A: the published object name must not name the secret -------------------


def test_the_pairing_object_name_is_not_derived_from_the_secret(tmp_path,
                                                                capsys):
    """The one that mattered: the Destination stores the name in the clear.

    Entropy arithmetic, which is the whole reason the code has two halves:

      alphabet             32 chars            = 5 bits per character
      locator, 6 chars     2**30 names         public, guards nothing
      secret, 10 chars     2**50 candidates    the only PBKDF2 input

    Attacking the wrap costs 2**50 * 600_000 * 2 ~= 1.3e21 SHA-256
    compressions - about 2000 years on a 20 GH/s GPU. The old scheme
    published sha256(code)[:16] as the filename: 2**40 unsalted,
    single-iteration hashes ~= 55 seconds on the same GPU, and the code it
    recovered opened the wrap directly. A truncation to 64 bits still pins a
    unique preimage, so the truncation bought nothing.
    """
    home, _ = paired_machine(tmp_path)
    code = mint(home, capsys)
    locator, secret = sync.parse_pairing_code(code)

    keys = DirectoryDestination(tmp_path / "archive").list(archive.PAIR_PREFIX)
    assert len(keys) == 1
    name = keys[0][len(archive.PAIR_PREFIX):]
    stem = name[:-len(".enc")]

    canon = "".join(code.split()).replace("-", "").upper()
    for candidate in (secret, code, canon, locator + secret):
        digest = hashlib.sha256(candidate.encode("ascii")).hexdigest()
        assert stem != digest[:len(stem)], \
            f"the object name is a truncated sha256 of {candidate!r}"

    assert stem == locator, "the object is named by the locator, verbatim"
    assert secret not in name and secret.lower() not in name.lower()


def test_the_secret_half_keeps_its_full_entropy_behind_the_wrap(tmp_path,
                                                                capsys):
    """Knowing the name tells an attacker the locator and nothing else: the
    50-bit secret is still 50 bits, and it is all PBKDF2 ever sees."""
    home, _ = paired_machine(tmp_path)
    code = mint(home, capsys)
    locator, secret = sync.parse_pairing_code(code)

    assert len(locator) == sync.LOCATOR_CHARS == 6
    assert len(secret) == sync.SECRET_CHARS == 10
    assert set(locator) <= set(sync.PAIR_ALPHABET)
    assert set(secret) <= set(sync.PAIR_ALPHABET)
    assert len(sync.PAIR_ALPHABET) == 32, "5 bits per character"

    # Independently drawn: 200 mints, no repeated locator and no locator that
    # is a slice of its own secret.
    seen = set()
    for _ in range(200):
        loc, sec = sync.parse_pairing_code(sync.new_pairing_code())
        assert loc not in seen
        seen.add(loc)
        assert loc not in sec


def test_a_wrong_secret_leaves_the_pairing_object_in_place(tmp_path, capsys):
    """A typo must not cost the user the code that works: the locator half
    still finds the object, the wrong secret fails to unwrap it, and the
    blob is still there for the right code afterwards."""
    home_a, dest_spec = paired_machine(tmp_path)
    code = mint(home_a, capsys)
    locator, secret = sync.parse_pairing_code(code)

    wrong_char = "Z" if secret[-1] != "Z" else "Y"
    typo = locator + secret[:-1] + wrong_char

    home_b = fresh_home(tmp_path, "home_b")
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=dest_spec, join=typo, machine="machine-b"), home_b)
    assert "wrong or expired code" in str(exc.value)
    assert keyring.fetch_master(home=home_b) is None

    dest = DirectoryDestination(tmp_path / "archive")
    assert dest.read(archive.pairing_key(locator)) is not None, \
        "a failed unwrap must leave the blob for the right code to claim"

    home_c = fresh_home(tmp_path, "home_c")
    assert sync.init(ns(dest=dest_spec, join=code, machine="machine-c"),
                     home_c) == 0
    assert keyring.fetch_master(home=home_c) == \
        keyring.fetch_master(home=home_a)


# --- B: a blob is bound to the object it is stored as ------------------------


def test_a_blob_sealed_under_one_label_is_refused_under_another():
    data = b"Session A bytes"
    blob = crypto.seal(data, MASTER, "session:" + UUID_A)
    assert crypto.unseal(blob, MASTER, "session:" + UUID_A) == data
    with pytest.raises(crypto.CryptoError) as exc:
        crypto.unseal(blob, MASTER, "session:" + UUID_B)
    assert "authenticate" in str(exc.value)


def test_a_session_served_at_another_sessions_key_is_refused(dest):
    """The honest-but-curious Destination's cheapest attack: keep both
    objects, hand back the wrong one. Nothing in the ciphertext used to say
    where it belonged, so it decrypted cleanly and pull laid Session B's
    tree down as Session A."""
    key_a = archive.put_session(dest, MASTER, UUID_A, TAR_A, make_meta())
    key_b = archive.put_session(dest, MASTER, UUID_B, TAR_B, make_meta())

    dest.write(key_a, dest.read(key_b))  # the swap

    # SystemExit, not CryptoError: this reaches the user partway through a
    # pull, and the sentence explaining it is the point of writing it.
    with pytest.raises(SystemExit) as exc:
        archive.get_session(dest, MASTER, UUID_A, key_a)
    assert "authenticate" in str(exc.value)


def test_a_project_residue_served_as_a_session_is_refused(dest):
    """Cross-type replay too, not just Session for Session."""
    session_key = archive.put_session(dest, MASTER, UUID_A, TAR_A, make_meta())
    project_key = archive.put_project(dest, MASTER, "~/other", TAR_B,
                                      make_meta())

    dest.write(session_key, dest.read(project_key))
    with pytest.raises(SystemExit):
        archive.get_session(dest, MASTER, UUID_A, session_key)


def test_the_index_served_as_a_session_is_refused(dest):
    key = archive.put_session(dest, MASTER, UUID_A, TAR_A, make_meta())
    archive.save_index(dest, MASTER, archive.fresh_index())

    dest.write(key, dest.read(archive.INDEX_KEY))
    with pytest.raises(SystemExit):
        archive.get_session(dest, MASTER, UUID_A, key)


def test_a_session_served_as_the_index_is_refused(dest):
    key = archive.put_session(dest, MASTER, UUID_A, TAR_A, make_meta())
    dest.write(archive.INDEX_KEY, dest.read(key))
    with pytest.raises(SystemExit) as exc:
        archive.load_index(dest, MASTER)
    assert "Index" in str(exc.value)


# --- C: tampering is named as tampering --------------------------------------


def test_a_flipped_ciphertext_byte_is_refused(dest):
    key = archive.put_session(dest, MASTER, UUID_A, TAR_A, make_meta())
    blob = bytearray(dest.read(key))
    blob[-1] ^= 0x01
    dest.write(key, bytes(blob))

    with pytest.raises(SystemExit) as exc:
        archive.get_session(dest, MASTER, UUID_A, key)
    message = str(exc.value)
    assert "authenticate" in message
    assert "passphrase" not in message, \
        "tampering is not a wrong-key message: it says the Archive was edited"


def test_a_flipped_tag_byte_is_refused():
    blob = bytearray(crypto.seal(b"payload" * 40, MASTER, "index"))
    blob[0] ^= 0x80
    with pytest.raises(crypto.CryptoError):
        crypto.unseal(bytes(blob), MASTER, "index")


def test_a_truncated_blob_is_refused():
    blob = crypto.seal(b"payload" * 40, MASTER, "index")
    for cut in (0, 1, crypto.MAC_BYTES - 1):
        with pytest.raises(crypto.CryptoError):
            crypto.unseal(blob[:cut], MASTER, "index")


def test_the_mac_key_is_not_the_master_key():
    """Derived, so the same 32 bytes never both encrypt and authenticate."""
    blob = crypto.seal(b"x", MASTER, "index")
    tag = blob[:crypto.MAC_BYTES]
    ciphertext = blob[crypto.MAC_BYTES:]
    import hmac as hmac_mod
    naive = hmac_mod.new(MASTER, b"index" + b"\0" + ciphertext,
                         hashlib.sha256).digest()
    assert tag != naive


# --- read_tree: a key from a listing is input --------------------------------


class HostileDestination(Destination):
    """Answers list() with a key that walks out of the Archive's root.

    read() validates the way every real Destination does, which is exactly
    why the escape had to be caught earlier: by the time read() refuses, the
    default read_tree has already made the directory outside dst_dir.
    """

    def __init__(self, keys):
        self.keys = keys

    def list(self, prefix: str = "") -> list:
        return [k for k in self.keys if k.startswith(prefix)]

    def read(self, key: str):
        from carryon.destinations.base import require_key
        require_key(key)
        return b"planted"

    def describe(self) -> str:
        return "hostile"


def test_read_tree_refuses_a_key_that_escapes_its_root(tmp_path):
    dst = tmp_path / "dst"
    dest = HostileDestination(["carryon/setups/mac/../sibling/evil.txt"])

    with pytest.raises(ValueError):
        dest.read_tree("carryon/setups/mac", dst)

    assert not (tmp_path / "sibling").exists(), \
        "the escaping directory was created before the key was ever checked"
    assert not (tmp_path / "sibling" / "evil.txt").exists()


def test_read_tree_refuses_a_malformed_key(tmp_path):
    dest = HostileDestination(["carryon/setups/mac/ok.txt",
                               "carryon/setups/mac//empty-component.txt"])
    with pytest.raises(ValueError):
        dest.read_tree("carryon/setups/mac", tmp_path / "dst")


def test_read_tree_still_materialises_ordinary_keys(tmp_path):
    dst = tmp_path / "dst"
    dest = HostileDestination(["carryon/setups/mac/claude/settings.json"])
    dest.read_tree("carryon/setups/mac", dst)
    assert (dst / "claude" / "settings.json").read_bytes() == b"planted"


# --- an Archive that goes backwards ------------------------------------------


def test_pull_warns_when_the_archive_serves_an_older_index(tmp_path, capsys):
    """A replayed Index is authentic - it was written by a key holder - so
    the MAC cannot catch it. The Index revision only ever goes up, so a
    machine that has seen a higher one says so and carries on."""
    home, dest_spec = paired_machine(tmp_path)
    master = keyring.fetch_master(home=home)
    dest = DirectoryDestination(tmp_path / "archive")

    index = archive.load_index(dest, master)
    archive.save_index(dest, master, index)      # revision 1
    old_blob = dest.read(archive.INDEX_KEY)
    archive.save_index(dest, master, index)      # revision 2
    archive.save_index(dest, master, index)      # revision 3

    sync.pull(ns(apply=True), home)              # marks revision 3 as seen
    capsys.readouterr()

    dest.write(archive.INDEX_KEY, old_blob)      # the rollback
    assert sync.pull(ns(apply=True), home) == 0, \
        "a rollback warns, it does not fail"
    out = capsys.readouterr().out
    assert "rolled back" in out or "rollback" in out
    assert "3" in out and "1" in out, "the two revisions are both named"


def test_a_first_pull_against_a_fresh_archive_warns_about_nothing(tmp_path,
                                                                  capsys):
    home, _ = paired_machine(tmp_path)
    capsys.readouterr()
    sync.pull(ns(apply=True), home)
    assert "rolled back" not in capsys.readouterr().out


def test_a_dry_run_pull_writes_no_high_water_mark(tmp_path, capsys):
    """A dry run is a plan: it reads the mark to warn and leaves it alone."""
    home, _ = paired_machine(tmp_path)
    state = home / ".carryon" / "state.json"
    dest = DirectoryDestination(tmp_path / "archive")
    archive.save_index(dest, keyring.fetch_master(home=home),
                       archive.fresh_index())

    sync.pull(ns(), home)
    assert not state.exists()

    sync.pull(ns(apply=True), home)
    marks = json.loads(state.read_text())["destinations"]
    assert marks[str(tmp_path / "archive")]["index_revision"] == 1


# --- the pairing payload itself ----------------------------------------------


def test_the_pairing_blob_never_shows_the_master_key(tmp_path, capsys):
    home, _ = paired_machine(tmp_path)
    master = keyring.fetch_master(home=home)
    code = mint(home, capsys)
    locator, _ = sync.parse_pairing_code(code)

    blob = DirectoryDestination(tmp_path / "archive").read(
        archive.pairing_key(locator))
    assert master not in blob
    assert master.hex().encode() not in blob
    assert json.dumps({"master": master.hex()}).encode() not in blob
    assert code.encode() not in blob and locator.encode() not in blob


def test_an_expired_code_is_still_refused_and_burnt(tmp_path, capsys,
                                                    monkeypatch):
    """The TTL sits inside the wrapped payload, so only a successful unwrap
    can enforce it - it is not, and never was, a defence against brute force
    of the code itself. That is the wrap's job."""
    home_a, dest_spec = paired_machine(tmp_path)
    code = mint(home_a, capsys)

    real_now = time.time()
    monkeypatch.setattr(sync.time, "time",
                        lambda: real_now + sync.PAIRING_TTL_SECONDS + 60)
    home_b = fresh_home(tmp_path, "home_b")
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=dest_spec, join=code, machine="machine-b"), home_b)

    assert "expired" in str(exc.value)
    assert keyring.fetch_master(home=home_b) is None
    assert DirectoryDestination(tmp_path / "archive").list(
        archive.PAIR_PREFIX) == []


class UnfilteredDestination(Destination):
    """Answers list() with everything it holds, prefix or no prefix.

    The base class's read_tree slices `key[len(head):]` on the assumption
    that every listed key really is under `head`. A Destination is untrusted
    storage; that assumption is the Destination's to break.
    """

    def __init__(self, keys):
        self.keys = keys

    def list(self, prefix: str = "") -> list:
        return list(self.keys)

    def read(self, key: str):
        return b"planted"

    def describe(self) -> str:
        return "unfiltered"


def test_read_tree_refuses_a_key_that_is_not_under_the_prefix(tmp_path):
    """`relative_to` is lexical and does not reject '..': dst/'../evil'
    relative_to dst returns '../evil' rather than raising. So the slice, not
    the whole key, is what has to be contained - and a key that is not under
    the prefix slices into one that walks out."""
    dst = tmp_path / "staging"
    head = "carryon/setups/mac"          # 18 chars; head becomes 19 with '/'
    escaping = "a" * 19 + "../evil"
    dest = UnfilteredDestination([escaping])

    with pytest.raises(ValueError):
        dest.read_tree(head, dst)
    assert not (tmp_path / "evil").exists(), "read_tree wrote outside dst_dir"


def test_a_tampered_pairing_blob_is_refused_and_not_burnt(tmp_path, capsys):
    """The pairing blob is unauthenticated AES-CBC by necessity, so a byte
    flipped outside the last block leaves the PKCS#7 padding intact and
    openssl exits 0. Exit 0 is not proof the code opened the blob; a
    well-formed payload is, and it must be checked before the one-time
    delete burns a code that still works."""
    home_a, dest_spec = paired_machine(tmp_path)
    code = mint(home_a, capsys)
    locator, _ = sync.parse_pairing_code(code)

    dest = DirectoryDestination(tmp_path / "archive")
    key = archive.pairing_key(locator)
    blob = bytearray(dest.read(key))
    blob[20] ^= 0x01
    dest.write(key, bytes(blob))

    home_b = fresh_home(tmp_path, "home_b")
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=dest_spec, join=code, machine="machine-b"), home_b)

    message = str(exc.value)
    assert "tamper" in message or "not a carryon pairing" in message, message
    assert keyring.fetch_master(home=home_b) is None
    assert dest.read(key) is not None, \
        "a tampered blob burnt the pairing code that would have worked"


# --- one bad object costs that object, not the rest of the pull --------------
#
# The Destination decides what comes back from every key, so a tampered or
# truncated object is a thing it can serve at any moment. A pull meets these
# halfway through, with earlier Sessions and often the whole Setup already on
# disk, so the failure mode has to be a named skip in the report - never an
# abort, which leaves the user with a partial $HOME and a traceback.

UUID_ONE = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
UUID_TWO = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"


def build_home_with_two_sessions(tmp_path, name="home_t") -> pathlib.Path:
    """Two Sessions in one project, plus a memory file - the project residue.

    Two of them because the point is what survives one bad object: a single
    Session cannot tell 'skipped it' from 'skipped everything'."""
    home = tmp_path / name
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')
    cwd = str(home / "code" / "app")
    project = claude / "projects" / rekey.encode_project_dir(cwd)
    project.mkdir(parents=True)
    for uuid in (UUID_ONE, UUID_TWO):
        (project / (uuid + ".jsonl")).write_text(
            json.dumps({"cwd": cwd, "type": "user", "text": uuid}) + "\n")
    (project / "memory.md").write_text("project notes\n")
    return home


def link_home(home, dest_spec, machine, master_from) -> None:
    """A second machine on the same Archive, without the pairing theatre."""
    keyring.store_master(keyring.fetch_master(home=master_from), home=home)
    cfg = config.default_config()
    cfg["destination"] = dest_spec
    cfg["machine"] = machine
    config.save(cfg, home)


def flip_last_byte(dest, key) -> None:
    """Tampering, at its cheapest: one bit of an object's ciphertext."""
    blob = bytearray(dest.read(key))
    blob[-1] ^= 0x01
    dest.write(key, bytes(blob))


def landed_project(home) -> pathlib.Path:
    return (home / ".claude" / "projects"
            / rekey.encode_project_dir(str(home / "code" / "app")))


def two_session_archive(tmp_path, capsys):
    """A pushed Archive and a second machine ready to pull from it."""
    home_a = build_home_with_two_sessions(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True), home_a) == 0
    home_b = tmp_path / "home_u"
    (home_b / ".claude").mkdir(parents=True)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    capsys.readouterr()
    return home_a, home_b, DirectoryDestination(tmp_path / "archive")


def test_a_tampered_session_costs_that_session_and_not_the_pull(tmp_path,
                                                                capsys):
    """A CryptoError used to end the pull where it was found - halfway
    through, with earlier Sessions and often the Setup already written to
    $HOME and no report saying what had landed.

    It is still a failure, and the pull still exits non-zero for it: after
    ADR-0009 the recovery key is known good by the time anything gets here,
    because load_index opened the Index with it, so the Archive is holding an
    object no key holder wrote. What changes is when. Everything else lands
    first, the object is named in the report, and the exit comes at the end
    where it costs nothing."""
    home_a, home_b, dest = two_session_archive(tmp_path, capsys)
    master = keyring.fetch_master(home=home_a)
    flip_last_byte(dest, archive.session_key(master, UUID_ONE))

    with pytest.raises(SystemExit) as exc:
        sync.pull(ns(apply=True), home_b)
    out = capsys.readouterr().out

    landed = landed_project(home_b)
    assert (landed / (UUID_TWO + ".jsonl")).is_file(), \
        "the good Session went down with the bad one"
    assert not (landed / (UUID_ONE + ".jsonl")).exists(), \
        "a Session that failed its integrity check was written anyway"
    assert UUID_ONE in out, "the skipped Session is not named in the report"
    assert "integrity" in out, \
        "the report must say the object failed its integrity check"
    assert "Sessions:" in out, "the pull ended before it printed its report"
    assert (home_b / ".claude" / "settings.json").is_file(), \
        "the Setup half never ran"
    assert UUID_ONE in str(exc.value)


def test_a_tampered_project_residue_is_skipped_the_same_way(tmp_path, capsys):
    """Residue comes back through the same untrusted path as a Session, and
    is fetched after every Session has been written - the latest point in a
    pull at which stopping there costs the most."""
    home_a, home_b, dest = two_session_archive(tmp_path, capsys)
    objects = dest.list(archive.PROJECTS_PREFIX)
    assert len(objects) == 1, "the fixture should push exactly one residue"
    flip_last_byte(dest, objects[0])

    with pytest.raises(SystemExit):
        sync.pull(ns(apply=True), home_b)
    out = capsys.readouterr().out

    assert (landed_project(home_b) / (UUID_ONE + ".jsonl")).is_file()
    assert (landed_project(home_b) / (UUID_TWO + ".jsonl")).is_file()
    assert not (landed_project(home_b) / "memory.md").exists()
    assert "integrity" in out and "~/code/app" in out
    assert "Setup:" in out, "the Setup half never ran"


# --- the payload itself, which is the one object with no tag -----------------
#
# ADR-0005 leaves the pairing blob unauthenticated because the joining machine
# holds no key to check a tag with, and _pairing_payload is the whole of what
# stands in for one: unwrapped bytes are a pairing payload only if they parse
# and carry what carryon writes. Two things it did not ask, both reached only
# with the pairing secret in hand - which is the same corruption-and-skew class
# as a damaged Archive object, in the object carryon deliberately leaves bare.


def replant_payload(tmp_path, home, code, **fields) -> tuple:
    """Re-wrap the pairing blob under the same code with a payload of ours.

    Under the real secret, so everything up to and including the unwrap
    succeeds and what is being tested is the check after it.
    """
    parts = sync.parse_pairing_code(code)
    dest = DirectoryDestination(tmp_path / "archive")
    key = archive.pairing_key(parts.locator)
    payload = dict(master=keyring.fetch_master(home=home).hex())
    payload.update(fields)
    dest.write(key, crypto.wrap_key(
        json.dumps(payload).encode("utf-8"), parts.secret))
    return dest, key


def test_a_pairing_payload_nested_past_the_limit_is_refused_by_name():
    """json.loads answers nesting past the interpreter's limit with a
    RecursionError, which is neither a ValueError nor a UnicodeDecodeError -
    the omission this project has now made in five places and fixed in four.
    Unwrapping is what it takes to reach it, so this is a damaged blob rather
    than an attack, and a damaged blob is refused by name like any other."""
    with pytest.raises(SystemExit):
        sync._pairing_payload(b"[" * 200000)


def test_a_payload_that_records_no_creation_time_does_not_burn_the_code(
        tmp_path, capsys):
    """`float(payload.get("created_at", 0))` sat one line AFTER the one-time
    delete, so a payload carryon did not write burnt the object and then
    raised ValueError out of `carryon init --join`. The read/delete split
    exists to make exactly that impossible: everything a payload has to prove
    is proved before the code is spent."""
    home_a, dest_spec = paired_machine(tmp_path)
    code = mint(home_a, capsys)
    dest, key = replant_payload(tmp_path, home_a, code)

    home_b = fresh_home(tmp_path, "home_b")
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=dest_spec, join=code, machine="machine-b"), home_b)

    assert "pairing" in str(exc.value), "the refusal does not name the object"
    assert keyring.fetch_master(home=home_b) is None
    assert dest.read(key) is not None, \
        "a payload carryon did not write burnt the pairing code"


def test_a_payload_whose_creation_time_is_not_a_number_is_refused(tmp_path,
                                                                  capsys):
    """Same field, the other way it can be wrong. A string here is a
    TypeError out of float() rather than a refusal, and it lands after the
    delete too."""
    home_a, dest_spec = paired_machine(tmp_path)
    code = mint(home_a, capsys)
    dest, key = replant_payload(tmp_path, home_a, code,
                                created_at="yesterday afternoon")

    home_b = fresh_home(tmp_path, "home_b")
    with pytest.raises(SystemExit):
        sync.init(ns(dest=dest_spec, join=code, machine="machine-b"), home_b)

    assert keyring.fetch_master(home=home_b) is None
    assert dest.read(key) is not None, \
        "a payload carryon did not write burnt the pairing code"


def test_a_creation_time_of_nan_does_not_mint_a_code_that_never_expires(
        tmp_path, capsys, monkeypatch):
    """NaN is legal JSON to Python's parser, survives float(), and loses every
    comparison it takes part in - so `now - created_at > TTL` is False forever
    and the 24-hour life of a pairing code quietly becomes unlimited. The
    guard has to ask for a finite number, not for a number."""
    home_a, dest_spec = paired_machine(tmp_path)
    code = mint(home_a, capsys)
    replant_payload(tmp_path, home_a, code, created_at=float("nan"))

    real_now = time.time()
    monkeypatch.setattr(sync.time, "time",
                        lambda: real_now + sync.PAIRING_TTL_SECONDS * 100)
    home_b = fresh_home(tmp_path, "home_b")
    with pytest.raises(SystemExit):
        sync.init(ns(dest=dest_spec, join=code, machine="machine-b"), home_b)

    assert keyring.fetch_master(home=home_b) is None, \
        "a code with no usable creation time paired a machine anyway"


def test_an_ordinary_pairing_payload_still_joins(tmp_path, capsys):
    """The positive control the three refusals above are measured against."""
    home_a, dest_spec = paired_machine(tmp_path)
    code = mint(home_a, capsys)
    home_b = fresh_home(tmp_path, "home_b")

    assert sync.init(ns(dest=dest_spec, join=code, machine="machine-b"),
                     home_b) == 0
    assert keyring.fetch_master(home=home_b) == keyring.fetch_master(
        home=home_a)
