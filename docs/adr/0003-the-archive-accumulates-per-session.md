# The Archive accumulates per Session, under one envelope key

A Destination could hold a single Snapshot that each push overwrites. That
loses data the same way whole-snapshot pull did (ADR-0002), one layer up: laptop
pushes, desktop pushes, and the laptop's Sessions are gone from the only copy
that is not on the laptop. It is also not incremental — on the machine this was
measured on, 13MB of Transcripts churn per week against a 29MB History, so every
push would re-upload everything and the cost would grow forever.

So an Archive stores one encrypted object per Session, and a push uploads only
what changed. Filenames are HMACed under a key derived from the master key for
naming, so the Destination learns object count and sizes but not Session UUIDs.
The name is where an object sits, not what it is: each object is additionally
sealed under its own logical identity, so a Destination cannot serve one
object's bytes at another object's key and have them open (ADR-0009).

A Session is a tree rather than a file — the main Transcript plus every subagent
transcript and workflow journal beneath it, of which a single workflow run
produced 27 — so the stored object is the whole subtree, tarred and then
encrypted. That keeps the STORED Session atomic, so what a pull fetches is one
push's tree entire and never a conversation carrying subagent journals from a
different upload; it compresses well, since those workflow files are
near-identical; and it keeps object counts sane on Destinations that charge per
operation. What lands under `$HOME` is that tree unioned member by member with
what this machine already held, which is ADR-0002's rule and not a hole in this
one — the atomicity being claimed here is the object's. The cost is
re-uploading an active Session's whole tree while it is being worked on, which
is a handful of objects per push.

An encrypted Index holds per-Session metadata — project path, main Transcript
size and hash, source machine, timestamp. A pull fetches the Index first and
downloads only the Sessions it actually needs, which makes pull incremental as
well as push, and gives ADR-0002's collision rule something to compare without
decrypting every object.

## Envelope encryption, because per-file PBKDF2 is not affordable

carryon's existing `crypto.py` runs PBKDF2 at 600,000 iterations per file, which
measured at 0.28s. Per-Session that is 16s for a 56-Session History and around
nine minutes for a heavy user's 2,000 — prohibitive for something meant to run
daily.

Instead the recovery key derives a master key **once** (`hashlib.pbkdf2_hmac`,
stdlib), and each Session file is encrypted under that master key with a random
salt, passed to openssl on stdin at `-iter 1`. Measured at ~2ms per file: 2,000
Sessions in about four seconds. One iteration is sound here because the input is
a 256-bit random key rather than a password — iterations exist to slow
brute-force of low-entropy secrets, and a master key has none of that weakness.
The derivation at the top is a single iteration for the same reason: what goes
into it is the generated recovery key (ADR-0004), which is high-entropy by
construction, so this is a fixed derivation and not a stretch. The full 600,000
are spent where a low-entropy secret actually occurs — wrapping the master key
under a pairing code. The key never appears in argv, preserving the property
`crypto.py` was written to guarantee.

Encryption is not the whole object format. AES-CBC is malleable, and a
ciphertext says nothing about where it was meant to live, so every object is
encrypt-then-MAC: a tag over the object's label and its ciphertext, checked
before openssl sees anything. The MAC key is derived from the master key rather
than being it — one key, one job — and the reasoning is ADR-0009's.

## Consequences

Encrypted-in-git becomes viable rather than merely tolerable: only new blobs are
added per push, so the repository grows by roughly the real new data instead of
re-adding the whole History on every commit.

An Archive needs periodic compaction once a Session has been superseded many
times, and that is not built.
