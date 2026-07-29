"""Fixtures for the credential scanner. Every credential here is fake.

A false negative is a leaked credential, so MUST_DETECT is the half that
matters. MAY_SUPPRESS exists so the scanner stays quiet enough to be worth
reading - one that fires on every SDK example is one you learn to ignore.

Run: python3 -m pytest tests/ -q       (or: python3 tests/test_secrets.py)
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon.secrets import scan  # noqa: E402

MUST_DETECT = [
    ("anthropic key", b'ANTHROPIC_API_KEY=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAA'),
    ("openai key", b'sk-proj-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'),
    ("github token", b'ghp_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'),
    ("github pat", b'github_pat_DDDDDDDDDDDDDDDDDDDDDD'),
    ("aws key", b'AKIAIOSFODNN7EXAMPLE'),
    ("slack token", b'xoxb-1234567890-ABCDEFGHIJ'),
    ("google key", b'AIzaSyA12345678901234567890123456789012'),
    # Assembled at runtime rather than written as a literal. GitHub's push
    # protection matches the sk_live_ prefix on shape alone, so a fake one in
    # the source blocks the push. The bytes the scanner sees are identical.
    ("stripe key", b'sk_' + b'live_' + b'E' * 24),
    ("jwt", b'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk'),
    ("private key", b'-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB\n-----END RSA PRIVATE KEY-----'),
    ("gitlab token", b'glpat-FFFFFFFFFFFFFFFFFFFF'),
    ("hf token", b'hf_GGGGGGGGGGGGGGGGGGGGGGGG'),
    # keyed secrets with literal values - suppression must not swallow these
    ("password literal", b'password="hunter2correct"'),
    ("api_key literal", b'api_key: "a7f3c9e1b4d8f2a6c0e5"'),
    ("token in json", b'"auth_token": "9f8e7d6c5b4a3f2e1d0c"'),
    ("escaped json quotes", b'password=\\"s3cr3tvalue\\"'),
    # near-misses: begin with a dummy word but are still literal secrets.
    # These are why the suppression uses fullmatch rather than a prefix match.
    ("value starting 'example'", b'client_secret=exampleXK92mfQ7zLpR4'),
    ("value starting 'os.environ'", b'API_KEY=os.environ_backup_KEY_9f8e7d6c5b4a'),
]

MAY_SUPPRESS = [
    ("env indirection js", b'apiKey: process.env.CURSOR_API_KEY!,'),
    ("env indirection py", b'api_key=os.environ["CURSOR_API_KEY"],'),
    ("getenv", b'api_key=os.getenv("KEY")'),
    ("shell var", b'API_KEY=$CURSOR_API_KEY'),
    ("braced shell var", b'API_KEY=${CURSOR_API_KEY}'),
    ("windows var", b'API_KEY=%CURSOR_KEY%'),
    ("doc ellipsis", b'API_KEY="cursor_..."'),
    ("angle placeholder", b'api_key: <your-api-key>'),
    ("your- placeholder", b'api_key: your-key-here'),
    ("template", b'api_key: {{ api_key }}'),
    ("masked", b'api_key: "****"'),
    ("null", b'client_secret: null'),
]


def test_detects_real_credentials():
    missed = [name for name, blob in MUST_DETECT if not scan(blob)]
    assert not missed, f"MISSED CREDENTIALS: {missed}"


def test_suppresses_documentation_placeholders():
    noisy = [name for name, blob in MAY_SUPPRESS if scan(blob)]
    assert not noisy, f"false positives: {noisy}"


if __name__ == "__main__":
    fails = 0
    print("MUST DETECT (a miss here is a leaked credential)")
    for name, blob in MUST_DETECT:
        hits = scan(blob)
        fails += not hits
        print(f"  {'PASS' if hits else 'FAIL'}  {name:<26} {hits}")

    print("\nMAY SUPPRESS (noise trains you to ignore the scanner)")
    noisy = 0
    for name, blob in MAY_SUPPRESS:
        hits = scan(blob)
        noisy += bool(hits)
        print(f"  {'quiet' if not hits else 'NOISY'}  {name:<26} {hits}")

    print(f"\n{len(MUST_DETECT) - fails}/{len(MUST_DETECT)} detected, "
          f"{len(MAY_SUPPRESS) - noisy}/{len(MAY_SUPPRESS)} suppressed")
    sys.exit(1 if fails else 0)
