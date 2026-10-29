# What carryon protects, and what it trusts

This page is the trust model: what is encrypted, what a
[Destination](../CONTEXT.md) can and cannot do with your Archive, and what the
recovery key is for. The terms are defined in [CONTEXT.md](../CONTEXT.md), and
the reasoning behind each decision is in [docs/adr/](adr/).

## What is encrypted

Both halves of a Snapshot, the Setup and the History, are sealed under a
master key before they leave the machine (ADR-0014). Sealed means encrypted,
and also checked before it is opened: every object carries a tag over its own
name, so a pull refuses an object that was edited at the Destination or served
in place of another one.

Because both halves are sealed, a credential found in either is reported and
carried, never redacted or blocked. That covers an API key in
`settings.json`'s `env` block, or a token echoed into a transcript. The scan
is a list of shapes it recognises rather than a proof (an opaque token matches
none), which is why the promise rests on encryption and not on the scan.

Encryption shells out to `openssl` (AES-256-CBC with an HMAC-SHA256 tag), so
the machine you move to needs nothing installed beyond carryon itself. CI
checks that an Archive sealed with macOS's LibreSSL opens with Linux's
OpenSSL 3, and the other way round.

What a capture may *read* is bounded too. carryon refuses a Setup whose
capture set reads its own state or anything outside `$HOME`, or when it cannot
tell whether it did.

## What a Destination can and cannot do

carryon holds no credentials for a Destination; it borrows whatever you
already have (a synced folder's account, git's keys, rclone's config). Where
`init` helps set up an rclone remote, the credential passes through to rclone
and is never kept.

A Destination is treated as untrusted storage (ADR-0009). It cannot read what
you carried, and it cannot change it without the pull noticing. A pull also
refuses an older Setup served back in place of the current one, which an
encrypted object alone cannot rule out, and a push refuses an Archive whose
Index has gone backwards since this machine last saw it.

What a Destination can still see is the shape: how many objects, how large,
when they changed, and the machine names in each Setup's key. Session names
are hashed, so it does not see your Session IDs or project paths.

Whether the storage is private is your call. `init` checks that write, read
and delete work, using a probe of random bytes under a random name, but no
check can tell whether anyone else can read the storage.

Prefer a Destination that forgets when you have the choice. A pairing code is
deleted from the Archive once it is used, but on a git Destination that delete
is a commit, and the wrapped master key stays in the history for anyone who can
clone the repository.

An Archive pushed before the Setup was sealed holds it as a plaintext tree, and
a pull refuses that tree by name. One full `carryon push --apply` replaces it
with the sealed object and removes the plaintext files. On a git Destination
they stay in the repository's history.

## The master key and the recovery key

`init` on the first machine generates the master key and stores it in the OS
keychain (`security` on macOS, `secret-tool` on Linux). On a machine with
neither, it falls back to `~/.carryon/master.key` with mode 0600 and says so.

A Linux server often has `secret-tool` installed but no keyring running for it
to talk to. carryon does not guess that it is safe to use the file there,
because the same error comes from a desktop whose keyring is only unreachable
over SSH. Run `carryon init --key-file` (with `--join` or `--recover` if you
need them) to keep the key in the file. Once the file exists, every command
uses it.

It also prints your **recovery key**, once:

```
Your recovery key - shown once, never stored by carryon:

    ABCD-EFGH-JKLM-NOPQ-RSTU-VWXY-Z234-5672
```

Put it in your password manager. The master key is derived from it (ADR-0004).
If every machine loses its key, the recovery key is the only way back in.
There is no reset.

## Pairing

`carryon pair` hands the master key to another machine without anyone typing
it (ADR-0005). It prints a one-time code. Six of its characters name an object
on the Destination, and the other ten wrap the master key inside it with
600,000 PBKDF2 iterations, so the name anyone can read off the Destination does
not give away the secret that opens it.

The code is good for one use within 24 hours. The joining machine deletes the
object once it has read it.

## If a machine loses its key

A new laptop, a wiped keychain, a machine restored without its keychain: the
cure depends on whether another machine still holds the key.

- **Another machine still has it:** run `carryon pair` there and
  `carryon init --join CODE` here. If this machine still has its
  `config.json`, joining keeps it exactly as it was, so `--dest` can be left
  off.
- **No machine has it:** type the recovery key back in with
  `carryon init --recover`.

carryon asks for the recovery key at a prompt that does not echo. It never
takes the key as an argument, and without a terminal it refuses. It keeps the
key only once the key has opened the Archive's Index. A key from another
Archive, or a typo that still parses, is asked for again with nothing stored,
and Ctrl-D stops. A right key says so first: `recovery key accepted`, then the
Destination check, then `recovered as NAME`. A pairing code does the same with
`pairing code accepted`.

Both ways keep a `config.json` this machine still has. They use that file's
Destination and machine name and leave the file exactly as it was, your
excludes and handpicked paths included. A `--dest` or `--machine` that
disagrees with it is refused before anything is stored, and before a pairing
code is spent.

## What carryon will not do to your files

A pull never deletes anything under `$HOME`, and carryon never writes through a
path another tool already holds: a dotfiles symlink, a second hard link, a name
this machine will not answer about (ADR-0007). Such a path is skipped and named
in the report rather than silently overwritten. `--force` writes through a
symlink or hard link on the Setup half; it still refuses a path no adapter here
declares, one landing in carryon's own state, and anything that is not an
ordinary file.

Before a pull overwrites a file, it backs that file up under
`~/.carryon/backups/<timestamp>/`.

## What the tests do not cover

A History is your transcripts, so what the suite does *not* cover is worth
knowing before you point carryon at them. No agent binary is involved: the
suite builds agent directories itself, so what is verified is carryon's
behaviour against the layouts each adapter records, not against a live agent
or a vendor who has since reorganised. The keyring runs through its file
backend with the real keychain pinned out, so `security(1)` and `secret-tool`
are covered by the arguments carryon builds for them rather than by use.
`openssl` and `git` are the real binaries. `rclone` is a stand-in, so a
Provider is checked against the arguments carryon builds and rclone's own
backend source, never against a live bucket. Two carryon runs against one
Archive at the same time is not tested.
