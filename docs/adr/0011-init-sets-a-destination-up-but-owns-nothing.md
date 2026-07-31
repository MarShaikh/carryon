# init sets a Destination up, and owns nothing it sets up

`init` detected what a machine already had — synced folders, an SSH key, every
remote in `rclone.conf` — printed the list, and made the user retype one as
`--dest`. Detection led nowhere, so the friction it existed to remove stayed.
For anyone without a synced folder that meant configuring rclone by hand first,
which is a fifteen-question wizard in another program, and the verdict on it was
fair: users still have to set things up.

So `init` now asks. With a terminal on both ends it offers what it found, and a
short list of Providers when it found nothing; it prompts for that Provider's
few fields, hands them to `rclone config create`, and verifies before it
finishes. Without a terminal — over SSH with no tty, in CI, in a container — it
prints the candidates and exits exactly as it did, so nothing that used to be
scriptable stopped being scriptable.

**Nothing is decided for the user, including the case where there is one obvious
answer.** `init` used to take a lone candidate silently, which meant a machine
with `~/Dropbox` had where-its-transcripts-live chosen for it by a tool that
merely announced the fact. A prompt with that candidate offered costs one
keypress and puts a person behind the decision.

## What carryon will and will not do on your behalf

It creates a **Remote**, because that is a line in a config file belonging to a
tool the user already installed, and the credential passes through carryon
without being kept — rclone obscures and stores it. It offers to create a
**bucket**, and asks first, because that is a billable resource in a region and
under a name carryon has no business choosing; the user names it and answers
for it.

It creates nothing else, and it never writes a credential of its own. Native S3
was rejected for that reason and one other: it would own SigV4, retries and
every Provider's quirks in order to duplicate what rclone already does for the
people most likely to have it. Shelling out to `gcloud`, `aws` and `az` as
transports was rejected for the same duplication, plus four more binaries no
test can reach.

Values reach `rclone config create` on argv, where `ps` can see them for the
life of the call. That is the constraint `keyring.py` already documents for
macOS's `security(1)`: the exposure is same-uid, and anyone able to read it can
read `rclone.conf` itself, so it is recorded rather than worked around.

## Verifying, and what a green tick means

`init` asks the Destination two different questions. **Occupancy** — is an
Archive already here — is a read of one known key and needs no write; it is what
catches the mistake that costs most. Running `init` without `--join` against an
Archive that already exists mints a *second* recovery key, prints it as though
it were the one that mattered, and fails only at the first push, by which point
the user holds two keys and cannot tell them apart, and `init` refuses to run
again. Occupancy present without `--join`, or absent with it, is a refusal
naming the cure.

**Reachability** — do write, read and delete work with these credentials — takes
a probe of random bytes under a random name. Random because it lands in the
plaintext half of untrusted storage before any master key exists, so it must
carry no machine name, no home path, and no timestamp; random name so two
machines probing at once cannot collide.

Neither answers the question that matters most for a Setup, which is whether the
storage is private. No probe can, and the wording says what was checked rather
than implying what was not.

## A pairing code cannot bootstrap Destination access

`_join` builds the Destination and only then reads the wrapped key out of it, so
a machine needs working credentials before a code is worth anything. Putting the
Remote's definition into the pairing payload therefore cannot work, and is
recorded here because it is the obvious thing to try. It would also be a bad
trade: the payload sits behind fifty bits and, on a git Destination, stays in
history for good (ADR-0005) — tolerable for a key that opens one Archive, not
for a cloud credential that is rarely scoped to one bucket.

So `init --join` runs the same Provider prompts and then spends the code. The
second machine is the one this ADR is about — a VM, a laptop on someone else's
network, a box with no SSH — and leaving it as the only path still needing
rclone configured by hand would have put the friction exactly where it hurts.

## Consequences

A first-time user with no cloud account still has an account to open. carryon
can remove the second tool, not the storage.

Provider field tables are per-Provider knowledge and live in one declarative
table, the way `adapters/` holds per-agent knowledge, so the engine keeps no
Provider branches. rclone's own full Provider list, for anything the table does
not name, is a later addition rather than part of this.
