# Pairing goes through the Destination; there is no peer-to-peer Destination

Adding a machine should not mean typing a 32-character recovery key, so machines
pair with a short one-time code. The obvious way to carry that code is a direct
connection between the two machines, as entangle's `send`/`receive` does.
carryon does not do this.

Instead, pairing reuses the Destination both machines already have. The paired
machine writes the master key into the Archive wrapped under a one-time code
and stored at an object that code names; the new machine reads it with the code,
and it is deleted once the unwrapped bytes have proved to be a pairing payload. No new transport, no relay, and it
works across networks and asynchronously — strictly better than a live channel
for this particular job.

The code is two halves drawn independently: a six-character **locator** that
names the object on the Destination and is published there as a filename, and a
ten-character **secret** that is the only thing the wrap's key derivation ever
sees. They are separate because naming the object after the secret publishes the
secret, which is what the first version did — ADR-0009 has the arithmetic.

## Why not a peer-to-peer Destination

A Destination is *somewhere a Snapshot can be put and later fetched*. A live
stream stores nothing: there is no Archive behind it, no third machine, no
pulling it again next month. It is a one-off transfer wearing the word, and
keeping it would mean one of four Destinations does not support `pull` — the
kind of exception that infects every code path that touches the abstraction.

It also could not be built without breaking something carryon states about
itself. Two machines meeting by short code need a rendezvous, and someone has to
run it. magic-wormhole would add a Python dependency to a tool whose README
promises none and whose `crypto.py` shells out to openssl precisely because the
receiving machine is the bare one. Delegating to entangle moves the same problem
to a Go binary the new machine also lacks. Running a relay makes carryon a
service. LAN-only is the one route that breaks nothing, but it fails across
networks and needs hand-rolled pairing crypto.

## Consequences

**One-time only holds on a Destination that forgets.** Deleting the object is a
real deletion on a directory or an rclone remote. On a git Destination the
delete is a commit, and the wrapped master key stays in the history for anyone
who can clone the repository — indefinitely, and offline, which is precisely the
attacker the code's fifty secret bits are a thin guard against. A code also
expires twenty-four hours after it is minted, which bounds the window a joining
machine will use one in and does nothing about this: an attacker holding the
blob out of a git history unwraps it themselves, and an expiry carryon enforces
is not a fact about their copy. So a master key paired over a
history-preserving Destination should be rotated afterwards.
carryon has no rotation command, so today that means a fresh `init` and pushing
into a fresh Archive: a real cost, and the reason to prefer pairing over a
Destination that forgets when there is a choice.

Someone migrating with nothing configured, whose machines are not on the same
network, has no direct transfer. They configure a Destination first — a synced
folder needs no account — or they use entangle, which does this well and
continues to exist.

## Joining keeps the config

> Amendment, 2026-10-18.

ADR-0004's amendment of the same date gave `init --recover` a rule for an
existing config, and recorded that `--join` lacked it. `--join` now follows the
same rule, because it is the same move: a key arrives on a machine that holds
none. The usual machine is the one ADR-0014 describes, whose keychain entry is
gone and whose `config.json` is not. Re-pairing it from another machine used to
write a fresh config over that file. That undid its handpicked Items (ADR-0008)
without saying so, and a hostname that differs from its chosen name made it a
new machine in the Archive.

So `--join` treats an existing config the way `--recover` does:

- **A valid config that names a Destination is kept.** Its Destination and
  machine name are used, and the file is not rewritten.
- **A `--dest` or `--machine` that disagrees with it is refused.** Two specs
  agree when they name the same place, so `~/…` and its expansion are one
  Destination. Changing either is not joining this machine back.
- **A config that names no Destination is built on.** Its machine name and its
  handpicks stay, and the Destination is filled in.
- **A config that will not load is refused,** with a cure that says to fix or
  remove it. Overwriting it would throw away whatever in it was still good.

Every one of these refusals comes before the code is spent. The code is
one-time, so a refusal that came after the delete would cost the user the code
as well. The checks are local and need no network, so they run straight after
the code is parsed, before any Destination prompt.

`carryon pair` prints the join command with `--dest`, and people paste it, so
`--join` meets a `--dest` more often than `--recover` does. A spec that names
the same place under another spelling passes. Two machines that reach one
bucket through differently named rclone remotes are refused, although the place
is the same. The refusal says to drop `--dest`, which is the cure, since the
config already names the Destination.

With a kept config, `--join CODE` needs neither `--dest` nor a terminal,
because the config answers the question the prompt would ask.

Plain `init` still writes a fresh config over an existing one. It is left alone
on purpose. It makes a new Archive, and `confirm_fresh` already refuses a
Destination that holds one, so it meets an existing config in two cases: a
rotation into a fresh Archive, and starting again after an Archive is lost. In
both the user usually wants a different Destination, so "keep the config and
refuse a disagreeing `--dest`" is the wrong rule there. The right one, perhaps
keeping the handpicks and taking the new Destination, is a separate decision.
