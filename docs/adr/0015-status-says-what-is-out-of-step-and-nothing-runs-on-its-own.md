# status says what is out of step, and nothing runs on its own

ADR-0012 ended by naming automation as the obvious next request: `sync` run on
a schedule, so two machines used in turn stay level without anyone typing it.
That request was grilled on 2026-10-19 and turned down. What the user wanted
was never a loop. It was to be told, the way `git status` tells you, that this
machine and the Archive have drifted apart and which command closes the gap.

So carryon gains `carryon status`, which reads and reports and writes nothing,
and it gains no scheduler, daemon or relay.

## Why nothing runs on its own

**A scheduled `sync` was rejected.** It would have meant carryon writing and
owning a launchd agent or a systemd timer, and each of those breaks in a place
the user cannot see. A LaunchAgent's `PATH` is `/usr/bin:/bin:/usr/sbin:/sbin`,
so `shutil.which("rclone")` misses a Homebrew rclone and every run refuses. The
master key is read with `security(1)`, which works only while the user is logged
in. Nothing serialises two runs, so a scheduled one and a typed one could
overlap and write the High-water mark and the Bases out of order. And a run
that needs a person, such as a landed divergence or an unreachable
Destination, needs a channel to reach one. ADR-0012's own sentence applies: a
report nobody reads is not a report. Every one of those is a question about
timing, and the user's answer was not to have timing at all.

**A sync server in the cloud was rejected.** An Obsidian-style relay that
compares the two machines would have to read what it compares. Every object in
an Archive is sealed under the master key (ADR-0004, ADR-0014), so the relay
would need the key, and handing it to a server undoes the trust model. Without
the key it is only storage, and the Archive already is that. It would also be
infrastructure the user has to create and pay for, which carryon has avoided
since ADR-0011 made a plain directory a first-class Destination.

**Live continuation is somebody else's problem.** Claude Code's remote control
already lets a person carry on a running Session from another device, while
the machine it runs on is awake. That does not move a Session, covers no other
agent, and carries no memory, so it does not replace carryon. It does remove
the one reason to want carryon to run every few minutes.

## What status answers, and from what

`status` reads the Index and this machine, and downloads no object. Its answers
are advisory. That is safe only because it writes nothing: the push or pull it
suggests still makes every check of its own before it writes, including the
downloads `_push_skip_reason` makes. An Index can veto an overwrite and never
authorise one, and `status` neither overwrites nor authorises.

Per Session, against its Index entry:

| This machine | The Index | Reported as |
|---|---|---|
| holds it | has no entry | to push |
| does not hold it | has an entry | to pull |
| same tree hash | same | in step, not shown |
| main Transcript shorter, or its prefix differs | | to pull (behind, or diverged) |
| main Transcript longer, prefix matches | | to push |
| same main Transcript, other members differ | | to push, and the push compares before it writes |

Per-project memory is judged against its Base: only the local copy moved means
to push, only the Archive's means to pull, and both means to pull, which files
the divergence. A divergence already filed is reported as filed. For
per-project memory it points at `carryon resolve`. For a Session it names
where the copy is filed, because ADR-0002's missing protocol is still missing
and no command resolves one.

**The Setup needs a record this machine keeps.** The Index's entry for a Setup
holds a random stamp, not a digest of what was sealed, so nothing in the
Archive says whether a Setup changed. And a pull does not restore this
machine's own Setup. It restores the newest one any vouched machine pushed
(`_choose_setup_source`), so a Setup can be behind as well as ahead. `push` and
`pull` therefore keep a Setup mark in `~/.carryon/`: the stamp of the last
Setup this machine sealed or laid down, and a digest of what it held. `status`
compares the Index's newest stamp against the mark, and a fresh capture
against the digest. Until a push or pull has written a mark, the Setup is
reported as not known. Downloading and unsealing this machine's Setup on every
`status` was the alternative, and was rejected for costing a download each
time.

## What it says, and its exit code

Counts by default, one line per half, each carrying the command that closes
it, written like git's hints:

```
status: rclone remote carryon:carryon-archive
History: 3 to push, 2 to pull - run `carryon sync --apply`
Setup: home-mac pushed changes (2026-10-19 09:12) - run `carryon pull --apply` to bring them here
Setup: changed here since your last push - run `carryon push --apply` to send it
```

A machine with nothing to do gets one line, `in step with <Destination>`.
`--verbose` lists each item behind a count. The History's hint is `sync`
because that is the History both ways in ADR-0012's order. A Setup's hint is
the half that moves it, because `sync` leaves the Setup alone by default. When
a Setup has moved on both sides, the pull hint says the pull replaces the
changes made here, after backing them up.

`status` exits 0 whenever it could answer, out of step or not. carryon's other
codes mean that something landed which a person has to deal with, or that a
command refused. "You could push" is neither. If it cannot reach the
Destination, it refuses with the sentence `push` and `pull` use, rather than
reporting the local half alone. "Nothing to pull" from a machine that never
looked is a confident wrong answer. A rolled-back Index or an unreadable record
gets the warnings `push` and `pull` print, and the High-water mark is not
moved.

It takes no `--category` and no `--agent`. It reports on everything, because a
filter on a read-only report only hides what it would have said. `doctor` is
unchanged.

## Consequences

**The advice can be wrong in one direction.** A Session whose main Transcript
matches but whose other members differ is reported as to push, and the push
may then skip it as behind after comparing the bytes. That costs one wasted
suggestion and nothing else, and is the price of not downloading.

**A machine is not known on its first `status` after upgrading,** as far as
its Setup goes, until it pushes or pulls once. The History needs no mark and is
reported at once.

**There is still no lock.** Nothing runs unattended, so the overlap that made
one necessary no longer arises. If anything runs carryon on its own later, the
lock comes with it.

**Surfacing `status` without typing it is deferred.** A Claude Code
`SessionStart` hook could run it whenever an agent opens, which is the moment a
person arrives at a machine. It costs a round trip to the Destination before
every agent starts and has no equivalent for Codex or Cursor, so it is its own
decision, taken once `status` exists and its cost is measured.
