"""Choosing a Destination, and what `init` settles before it commits to one.

`init` detected what a machine already had, printed the list, and made the
user retype one as `--dest`; detection led nowhere, so the friction it existed
to remove stayed. This module is the other half of ADR-0011: with a terminal
on both ends it offers what it found and a short list of Providers when it
found nothing, and without one it prints the candidates and exits - a script
names its Destination with --dest, and the one scripted spelling the ADR
removed is the silent adoption of a lone candidate, which was a decision and
not an answer.

It is a module rather than a stretch of `sync.init` because what it holds are
decisions - which Destination, whose Provider, what a green tick means - and
sync.py sequences commands. What each Provider needs lives one level further
out again, in `destinations/providers.py`, so the engine keeps no Provider
branches (the way `adapters/` holds per-agent knowledge).

The two checks are separate functions rather than steps of the dialogue for
a reason worth stating: they run on EVERY init, prompted or not. Their
subject is not convenience - occupancy is what stands between a user and two
recovery keys they cannot tell apart - and a script that sets up a machine
against a Destination nobody can write to has set up nothing at all.
"""

from __future__ import annotations

from . import archive, prompting
from .destinations import SPEC_FORMS, providers, rclone_setup


def choose_destination(home, candidates) -> str:
    """The spec this machine's Archive will live at, chosen by a person.

    Only ever called with a terminal on both ends (`prompting.available` is
    the caller's gate), and nothing is decided for the user, including the
    case where there is one obvious answer: a lone ~/Dropbox is offered, not
    taken, because a prompt with that candidate costs one keypress and puts
    a person behind where their transcripts live.

    What it returns is a SPEC - stored verbatim, expanded per machine - and
    everything it sets up on the way (an rclone Remote, an offered bucket)
    belongs to the tool that owns it afterwards. carryon keeps nothing.
    """
    usable = [(spec, label) for spec, label in candidates
              if "<" not in spec]
    git_offered = any("<" in spec for spec, _label in candidates)

    options = [f"{label} - {spec}" for spec, label in usable]
    if git_offered:
        options.append("a private git repository (type its URL)")
    options.append("a cloud service (carryon sets one up through rclone)")
    options.append("somewhere else (type a Destination spec)")

    picked = prompting.choose("Where should the Archive live?", options)
    if picked < len(usable):
        return usable[picked][0]
    if git_offered and picked == len(usable):
        url = prompting.ask("Git remote URL")
        return (url if url.startswith(("git:", "git@", "ssh://"))
                or url.endswith(".git") else "git:" + url)
    if picked == len(options) - 1:
        # `ask` refuses a NUL the way cli._spelling refuses one in --dest,
        # so what comes back is storable; what it MEANS is from_spec's,
        # asked by init before anything is minted.
        return prompting.ask(f"Destination spec ({SPEC_FORMS})")
    return _provider_flow()


def _provider_flow() -> str:
    """One Provider's few questions, then rclone owns everything typed.

    The fields come off the declarative table (destinations/providers.py),
    so this loop knows nothing about any particular service - which service
    needs which keys is per-Provider knowledge, held the way adapters/
    holds per-agent knowledge.
    """
    picked = prompting.choose("Which service?",
                              [p.name for p in providers.PROVIDERS])
    provider = providers.PROVIDERS[picked]

    name = prompting.ask("Name for the rclone remote", default="carryon")
    answers = {}
    for field in provider.fields:
        if field.question is None:
            continue
        if field.secret:
            answers[field.key] = prompting.secret(field.question)
        else:
            answers[field.key] = prompting.ask(field.question,
                                               default=field.default)
    rclone_setup.create_remote(name, provider.rclone_type,
                               providers.config_pairs(provider, answers))
    print(f"rclone remote {name!r} created - the credential went to "
          "rclone's config, and carryon kept nothing.")

    place = prompting.ask(provider.place_question)
    if provider.place_costs:
        print(f"A {provider.place} is a billable resource in your account, "
              "so carryon never creates one silently.")
        make = prompting.confirm(
            f"Create {provider.place} {place!r} now?", default=False)
    else:
        make = prompting.confirm(
            f"Create {provider.place} {place!r} on the remote now?",
            default=True)
    if make:
        why = rclone_setup.make_place(f"{name}:{place}",
                                      provider.mkdir_flags)
        if why is not None:
            raise SystemExit(
                f"rclone could not create {provider.place} {place!r}: {why}\n"
                f"The remote {name!r} is saved in rclone's config, so "
                "`carryon init` will offer it next time - create the "
                f"{provider.place} by hand, or run init again and name "
                "another.")
        print(f"{provider.place} {place!r} created.")
    else:
        print(f"Not created - if the {provider.place} is not there, the "
              "reachability probe will say so before anything is minted.")
    return f"rclone:{name}:{place}"


def confirm_fresh(dest) -> None:
    """Refuse unless a machine that is NOT joining may set up against this.

    Occupancy first, because it needs no write: an Archive that is already
    there is `--join`'s case and nothing else's. The refusal names the cure,
    since it is a state a person is in honestly - a second machine being set
    up the way the first one was.

    Then reachability, which is the write. It comes second so the mistake
    that costs most is caught by the question that costs least, and so a
    user who is about to be refused for occupancy is not first made to wait
    for a probe - or, on an Archive that is already somebody's, made to
    write to it.
    """
    if archive.occupied(dest):
        raise SystemExit(
            f"there is already an Archive at {dest.describe()}, and this "
            "machine is not joining it.\n"
            "Setting up over one mints a SECOND recovery key: the two open "
            "different Archives, nothing tells them apart, and the first "
            "push fails long after the key was printed. To put this machine "
            "on that Archive, run `carryon pair` on a machine already on it "
            "and then `carryon init --join CODE --dest SPEC` here. To start "
            "a separate Archive, name a Destination nothing has been pushed "
            "to.")
    _confirm_reachable(dest)


def confirm_joining(dest) -> None:
    """The same probe for the machine that IS joining, asked at a different
    moment - after the pairing blob has been found and before the code is
    spent.

    The join leg's occupancy question is not the Index: a machine pairs
    before its first push whenever a second machine is set up the same day,
    and the Archive it joins is, at that moment, a wrapped key and nothing
    else. What that leg needs present is the blob its code names, and
    `_join` reads it first thing - one known key, no write - with a refusal
    either way round (no Archive at all, or an Archive with no blob for
    that code). This function is what remains: a code is one-time, so
    spending it against a Destination this machine cannot write to would
    cost the code AND leave the machine unable to push. The probe runs
    before the unwrap, so a Destination that fails it leaves the blob in
    place and the code still good.
    """
    _confirm_reachable(dest, joining=True)


def _confirm_reachable(dest, joining: bool = False) -> None:
    """The probe, unless this type answers that probing it costs something
    a probe has no business spending - a git Destination, where every write
    is a commit that stays in history (the type says so itself, and the
    report repeats it rather than printing a tick over a delete git's own
    record contradicts).

    The refusal's last line depends on the leg, because what a user must
    know differs: on a join, that the one-time code was NOT spent; on a
    fresh init, that nothing was minted - and that an rclone remote this
    dialogue created is not nothing, it survives in rclone's config and a
    re-run will offer it.
    """
    if dest.skips_probe() is not None:
        return
    why = archive.reachable(dest)
    if why is None:
        return
    tail = (
        "The pairing code was NOT spent: the blob is still in the Archive, "
        "and the same code works once the Destination is fixed - run the "
        "same `carryon init --join` again."
        if joining else
        "No key was minted and no config was written on this machine. If "
        "this init created an rclone remote, that remote is saved in "
        "rclone's config and a re-run of `carryon init` will offer it as a "
        "candidate. Fix the Destination and run `init` again.")
    raise SystemExit(
        f"{dest.describe()} did not pass the reachability probe: {why}.\n"
        "carryon writes a few random bytes, reads them back and deletes "
        "them, because a Destination that authenticates is not necessarily "
        "one that works.\n" + tail)


def report(dest) -> None:
    """What a green tick means, in the words the ADR settles on.

    It says what was checked rather than implying what was not - which is
    also why a Destination whose probe was skipped gets the reason printed
    instead of a tick. Neither check answers the question that matters most
    for a Setup - whether the storage is private - and no probe can, so the
    line that would be read as "this is safe" is the one thing this must
    not print.
    """
    skipped = dest.skips_probe()
    if skipped is not None:
        print(f"Destination not probed: {skipped}.")
    else:
        print(f"Destination checked: write, read and delete work at "
              f"{dest.describe()}.")
        print("That is all it says.", end=" ")
    print("Nothing here can tell whether the storage is private, and a "
          "Setup travels in the clear.")
