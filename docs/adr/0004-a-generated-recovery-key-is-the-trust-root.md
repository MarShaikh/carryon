# A generated recovery key is the trust root

A History is always encrypted, so every machine that reads one needs the master
key. The OS keychain only helps after the first unlock on a given machine, which
leaves the question of how machine two gets it — and losing it means the Archive
is unrecoverable, with no reset.

carryon generates a high-entropy recovery key at `init` and displays it once,
for the user to keep in a password manager. The master key is derived from it,
so it is the trust root and the one route into the Archive that does not sit on
a machine. Adding a machine does not use it: machines pair with a one-time
code — sixteen characters, of which ten wrap the master key and six only say
where the wrapped copy sits (ADR-0009) — and the key lands in the receiving
machine's keychain without being typed.

Typing it back in is the part that is not built. Nothing in the CLI takes a
recovery key, and nothing takes a passphrase that has anything to do with an
Archive — `encrypt` and `decrypt` prompt for one, but that pair is a standalone
file cipher which touches no Destination and no master key. `init` on a machine
that holds no key mints a fresh one, which orphans the Archive the old one
opened; a key file that is there and merely unreadable is a refusal naming the
file rather than a machine that holds no key, which is ADR-0010's. So the
recovery key is today what makes recovery possible rather than what performs
it: a machine whose keychain entry is gone re-pairs from one whose entry is
not, and an Archive with no machine left holding the key needs a command that
does not exist. Written down here rather than left implied, because the rest of
this document reads as though the last resort were reachable by hand.

A trust root can be lost, and it can also be over-shared. A master key that has
travelled through a Destination which keeps its own history is only as private
as that history for as long as it exists; ADR-0005 says what to do about it.

Only a History is encrypted, so `push --category config` needs no key at all.
The burden falls on people who opt into carrying History, not everyone. But
the key does one more job when it is present: a Setup is plaintext and its
content is executable — a hook in settings.json, a skill — so a Destination
that could rewrite one would hold code execution on every pulling machine. A
keyed push therefore authenticates the Setup, tagging a manifest of the whole
tree into the Archive beside it, and where the Index records a Setup as
authenticated a pull refuses the tree whole when the tag is missing, forged, or
vouches for different bytes. The keyless push still works — locked keychain,
machine never paired — and warns plainly that what it pushed carries no tag and
cannot be verified by the machines that pull it.

Which machines are authenticated is recorded in the encrypted Index, never
inferred from the tag's presence. The tag sits in the Archive's plaintext
half, which anyone with write access edits at will, so "no tag here" is the
cheapest sentence an attacker can compose — honouring it would let stripping
the tag downgrade every pull to the keyless path. A tag an attacker can strip
is not a guard; the sealed Index is the one side of the question they cannot
author, so its word decides which posture a pull takes. The Index records
which tree the key holder means to be current as well, because a tag alone
vouches for every superseded tree equally, and a versioned Destination keeps
them all. That the Index decides the posture does not make a tag it says
nothing about a file worth walking past — ADR-0009 has the other half.

## Typing it back in

> Amendment, 2026-10-18.

The command the paragraph above says is missing now exists:
`carryon init --recover`. It is `--join`'s sibling, because it makes the same
move. A key arrives on a machine that holds none, and the machine is set up to
use it. The only difference is where the key comes from. The two flags cannot
be used together.

**The key is never an argument.** `--join CODE` can put its code on argv
because the code is one-time and expires in a day. A recovery key does
neither, so on argv it would stay in shell history and in `ps` for the whole
run. `--recover` takes no value and asks for the key at a prompt that does
not echo.

**It needs a terminal.** ADR-0011 has one rule for when carryon may take an
answer: a terminal on both ends. A stdin fallback for scripts would be a second
rule, made for the most sensitive input carryon takes. Without a terminal,
`--recover` refuses before it touches the network or the keychain. Piping the
key in from a password manager's CLI is a real use and is deferred. If it is
ever added, it will be an explicit flag. Recovery is rare and done by a person,
and a pipe nudges people towards keeping the trust root in a file.

**A key that parses is proved before it is kept.** The parse comes first. It is
a pure string check, so a typo is re-asked before any Destination prompt and
before the network. Next come the Destination and the reachability probe. Then
comes the Archive's Index, opened under the derived master key. Only an Index
that unseals lets the key be stored, and its revision becomes this machine's
High-water mark. An Index that will not unseal is the wrong key for this
Archive, and nothing is stored or written. No Index at all is refused too:
with an empty Destination there is nothing to recover, and plain `init` starts
an Archive. With objects there and no Index, the Index-removal refusal applies.
The alternative was to prove the key against a sealed Setup when the Index is
missing, and it was not taken. That Archive restores no Setup (ADR-0014) and
pushes nothing over itself, so a recovered machine could do nothing with it.
Its cure is getting the Index back.

There is one risk that stays open. A Destination can serve an older sealed
Index, and a machine meeting the Archive for the first time cannot tell. That
is true of any first contact. `--join` avoids it only because the paired
machine puts its revision inside the wrap.

**An existing config is kept.** The usual reason to recover is ADR-0014's: a
machine whose keychain entry is gone. That machine usually still has its
`config.json`, with its Destination, its machine name and its handpicked Items
(ADR-0008). `init` and `--join` overwrite that file with a fresh one. For
recovery that would undo the handpicking without saying so, and a hostname
that differs from the chosen name would make this machine a new one in the
Archive. So when a valid config exists, `--recover` uses its Destination and
machine name and leaves the file alone. A `--dest` or `--machine` that
disagrees with it is refused, because changing either is not recovery. If that
machine still has a High-water mark for the Destination, the rollback and
Index-removal checks apply to the Index it reads, so the open risk above
becomes a refusal there. `--join` overwriting an existing config is the same
gap in the sibling path. It is recorded here and left for a separate change.

**It is only for a machine that holds no key.** `--recover` runs exactly where
`init` would. A stored key, or one that cannot be read, is refused, and
`--recover` never overwrites a keychain entry. A locked keychain and a corrupt
one both arrive as a failure to read, and telling them apart inside `--recover`
would mean it learning the keyring's failures. The sentences a stuck user reads
name `--recover` instead. The refusal for a machine with no key names it next to
pairing, and the corrupt-key sentence says to remove the entry and recover. An
unreadable key file is left out, because the key may be fine and recovery is the
wrong cure for a permission problem.

This makes the recovery key what performs recovery, not only what makes it
possible. An Archive with no machine left holding the key can be opened by
hand.

## Considered options

**A user-chosen passphrase as the only root.** Rejected as the default: it
protects every credential ever echoed to a terminal, and users pick weak ones
and forget them. Worth supporting for those who ask, and not built. It would
come in at the same place `init --recover` does (see the amendment above), and
it needs a warning against a strength meter that teaches people to satisfy the
meter.

**Wrapping the master key to an existing SSH key**, age-style, so there is
nothing new to remember. The best fit for carryon's principle of borrowing
credentials the user already has, and deferred rather than rejected — SSH keys
cannot be assumed present on an arbitrary machine, rotation would lock the user
out, and multi-recipient wrapping is more machinery than a first version needs.
