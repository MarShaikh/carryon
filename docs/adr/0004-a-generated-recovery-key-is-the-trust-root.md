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

## Considered options

**A user-chosen passphrase as the only root.** Rejected as the default: it
protects every credential ever echoed to a terminal, and users pick weak ones
and forget them. Worth supporting for those who ask, and not built — it needs
the same missing command a typed recovery key does, and the same warning
against a strength meter that teaches people to satisfy the meter.

**Wrapping the master key to an existing SSH key**, age-style, so there is
nothing new to remember. The best fit for carryon's principle of borrowing
credentials the user already has, and deferred rather than rejected — SSH keys
cannot be assumed present on an arbitrary machine, rotation would lock the user
out, and multi-recipient wrapping is more machinery than a first version needs.
