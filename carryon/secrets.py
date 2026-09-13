"""Credential detection for captured files.

This module names what it finds and never refuses (ADR-0014). It used to
refuse in a Setup, on the reasoning that a Setup should contain no credentials
at all - so a hit meant the capture list was wrong and was therefore fixable.
That reasoning broke on `.claude/settings.json`, whose `env` block is where an
API key goes and which no Adapter change can stop carrying: the hit was real,
the cure did not exist, and the user was left with a push nothing could
unblock.

What made refusing load-bearing was storage, not detection - a Setup went to
the Archive in the clear, so stopping the push was the only thing between that
`env` block and a readable object in a bucket. Both halves are sealed now, so
the scan keeps its whole job and loses its veto.

Nothing about secrecy may rest on it. It is a list of shapes somebody
maintains, and carryon's own master key is bare hex that no pattern here
matches; encryption is what protects the bytes, and a quiet report means "no
shape I know", never "there was nothing there".

Rule set follows entangle's internal/redact (MIT).
"""

from __future__ import annotations

import re

SECRET_RULES = [
    ("private-key", re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("anthropic-key", re.compile(rb"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-key", re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("github-token", re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("github-pat", re.compile(rb"github_pat_[A-Za-z0-9_]{20,}")),
    ("slack-token", re.compile(rb"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("google-key", re.compile(rb"AIza[A-Za-z0-9_\-]{35}")),
    ("aws-access-key", re.compile(rb"A(?:KIA|SIA|ROA|IDA)[0-9A-Z]{16}")),
    ("hf-token", re.compile(rb"hf_[A-Za-z0-9]{20,}")),
    ("gitlab-token", re.compile(rb"glpat-[A-Za-z0-9_\-]{20,}")),
    ("stripe-key", re.compile(rb"[rs]k_(?:live|test)_[A-Za-z0-9]{20,}")),
    ("jwt", re.compile(rb"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("keyed-secret", re.compile(
        rb"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
        rb"auth[_-]?token|client[_-]?secret)\\?['\"]?\s*[:=]+\s*\\?['\"]?"
        rb"(?P<value>[^\s'\"\\]{6,})")),
]

# A keyed-secret whose VALUE matches one of these is an indirection, not a
# credential. Docs and config templates are full of them, and a scanner that
# fires on every SDK example is one you learn to click through - which is how a
# real key eventually gets out.
#
# Matched with fullmatch, NOT as a prefix. That distinction is the whole safety
# property: prefix-matching `example` silently swallows
# `client_secret=exampleXK92mfQ7z`, and prefix-matching `os.environ` swallows
# `API_KEY=os.environ_backup_9f8e7d`. Both are real credentials that merely
# begin with a dummy word. tests/test_secrets.py fails if either returns.
NOT_A_SECRET = re.compile(
    rb"(?i)(?:"
    rb"process\.env\.[A-Za-z_][A-Za-z0-9_]*|"      # process.env.NAME
    rb"os\.environ\[?|os\.getenv\(?|env\[|"        # python env lookup
    rb"\$\{?[A-Z_][A-Z0-9_]*\}?|%[A-Z_]+%|"        # $VAR, ${VAR}, %VAR%
    rb"\{\{.*|<[a-z][a-z0-9_-]*>|"                 # templates, <placeholder>
    rb"(?:your|my)[-_][a-z0-9-]*|"                 # your-key-here
    rb"x{3,}|"                                     # xxxxxxx
    rb"example|placeholder|redacted|changeme|"     # bare dummy words only
    rb"null|none|true|false|undefined"
    rb")[!,;)\]]*")

# An elision anywhere in the value marks it illustrative: docs write
# API_KEY="cursor_..." to show a key's shape. Real credentials contain no "...".
ELIDED = re.compile(rb"\.\.\.|<[a-zA-Z_-]+>|\bxxxx+|\*\*\*\*")


def scan(data: bytes) -> list:
    """Return names of the secret rules that matched, ignoring indirections."""
    hits = []
    for name, rx in SECRET_RULES:
        for match in rx.finditer(data):
            if name == "keyed-secret":
                value = match.groupdict().get("value") or b""
                if NOT_A_SECRET.fullmatch(value) or ELIDED.search(value):
                    continue
            hits.append(name)
            break
    return hits
