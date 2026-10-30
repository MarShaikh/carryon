"""`carryon handover` - carry Codex over to Claude Code (ADR-0018).

Codex's own `/import` already carries a Claude Code install into Codex, so
that direction is named and nothing else. The other direction has no
importer, so each Codex rollout becomes a new Claude Code Session holding the
conversation only: user and assistant turns as plain text, each tool call
folded into the assistant's turn as one line, and Codex's reasoning left
behind because it is stored encrypted. The Setup goes through Claude Code's
own front doors: ~/.codex/AGENTS.md is imported from ~/.claude/CLAUDE.md, and
each MCP server in ~/.codex/config.toml is added with `claude mcp add-json`.

What is written is the oldest and plainest part of Claude Code's format,
checked by resuming two real rollouts with `claude --resume`: alternating
user and assistant records, each with uuid, parentUuid, sessionId,
timestamp, cwd and one text block. None of a live record's other fields was
needed, and the less of the format this writes, the less of it can move.

The non-obvious decisions:

  the new UUID  is derived from the Codex one (uuid5), never random. Handing
                the same Session over twice then lands on the same name, and
                an exclusive write refuses the second - so nothing records
                what was handed over, and nothing can lose that record. The
                file is Claude Code's once written: resuming it appends, and
                carryon never writes it again.
  drift         every record kind this was checked against is listed below.
                A kind outside the list is left out and named, with an issue
                link carrying the kinds and the versions - never content. A
                Codex or Claude Code release newer than the one checked is
                said once, because that is when an unknown kind becomes
                likely, not proof that one is there.
  the source    is read through the gate every other leg uses and never
                written: the rollout stays resumable in Codex afterwards.

Touches no Destination and needs no key: nothing leaves this machine.
"""

from __future__ import annotations

import collections
import json
import pathlib
import re
import shutil
import subprocess
import urllib.parse
import uuid as uuidlib

from . import config, external, history, rekey, secrets
from .adapters import ADAPTERS, is_installed
from .destinations.base import printable
from .session import _rel_to_home

try:
    import tomllib
except ImportError:   # Python 3.9 and 3.10
    tomllib = None

CHECKED_AGAINST = {"codex": "0.128", "claude-code": "2.1"}
TOOL_OUTPUT_CHARS = 300
ISSUES = "https://github.com/MarShaikh/carryon/issues/new"
NAMESPACE = uuidlib.UUID("3b0c5c4e-6f2a-5d7e-9c41-0a8f2e6d1b37")

# (record type, payload type) -> what becomes of it. Anything not here is
# left out and named, which is the whole drift check.
TEXT = {("event_msg", "user_message"): "user",
        ("event_msg", "agent_message"): "assistant"}
CALLS = {("response_item", "function_call"),
         ("response_item", "custom_tool_call"),
         ("response_item", "web_search_call")}
OUTPUTS = {("response_item", "function_call_output"),
           ("response_item", "custom_tool_call_output")}
LEFT_BEHIND = {
    # Encrypted, so there is nothing to carry.
    ("response_item", "reasoning"), ("event_msg", "agent_reasoning"),
    # The same turns as user_message and agent_message, plus the developer
    # and environment preamble Codex injects - carried once, from the events.
    ("response_item", "message"),
    # Bookkeeping about the run rather than the conversation.
    ("session_meta", None), ("turn_context", None),
    ("event_msg", "token_count"), ("event_msg", "task_started"),
    ("event_msg", "task_complete"), ("event_msg", "turn_aborted"),
    # Duplicates of a call's output, already carried from OUTPUTS.
    ("event_msg", "exec_command_end"), ("event_msg", "patch_apply_end"),
    ("event_msg", "web_search_end"),
}
_PATCHED = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$", re.M)


def _kind(record) -> tuple:
    payload = record.get("payload")
    return (record.get("type"),
            payload.get("type") if isinstance(payload, dict) else None)


def _call_line(payload) -> str:
    """One line naming what a tool call did."""
    name = payload.get("name") or payload.get("type")
    if payload.get("type") == "web_search_call":
        action = payload.get("action")
        query = action.get("query") if isinstance(action, dict) else None
        return f"searched the web: {query}" if query else "searched the web"
    if payload.get("type") == "custom_tool_call":
        files = _PATCHED.findall(str(payload.get("input") or ""))
        return f"{name}: {', '.join(files)}" if files else str(name)
    try:
        args = json.loads(payload.get("arguments") or "{}")
    except (ValueError, RecursionError):
        args = {}
    cmd = None
    if isinstance(args, dict):
        cmd = args.get("cmd") or args.get("command")
    if isinstance(cmd, list):
        cmd = " ".join(str(part) for part in cmd)
    return f"{name}: {cmd}" if cmd else str(name)


def conversation(data: bytes) -> tuple:
    """([(role, text, timestamp)], meta, unknown kinds) for one rollout.

    Turns alternate and the first is the user's, which is the shape Claude
    Code resumes: runs of one role are joined, and a Session that opens with
    the assistant gets a one-line user turn before it. `meta` is the
    session_meta payload, for the Codex version that wrote it.
    """
    turns, meta, calls = [], {}, {}
    unknown = collections.Counter()
    for line in data.decode("utf-8", errors="replace").splitlines():
        try:
            record = json.loads(line)
        except (ValueError, RecursionError):
            unknown["unreadable line"] += 1
            continue
        if not isinstance(record, dict):
            unknown["unreadable line"] += 1
            continue
        kind = _kind(record)
        payload = record.get("payload") if isinstance(
            record.get("payload"), dict) else {}
        stamp = record.get("timestamp")
        if kind == ("session_meta", None):
            meta = payload
        if kind in TEXT:
            turns.append((TEXT[kind], str(payload.get("message") or ""),
                          stamp))
        elif kind in CALLS:
            said = _call_line(payload)
            if payload.get("call_id"):
                calls[payload["call_id"]] = said
            else:
                turns.append(("assistant", f"[{said}]", stamp))
        elif kind in OUTPUTS:
            said = calls.pop(payload.get("call_id"), "tool call")
            out = str(payload.get("output") or "").strip()
            if len(out) > TOOL_OUTPUT_CHARS:
                out = out[:TOOL_OUTPUT_CHARS] + " …"
            turns.append(("assistant", f"[ran {said}]\n{out}".rstrip(),
                          stamp))
        elif kind not in LEFT_BEHIND:
            unknown["/".join(str(part) for part in kind if part)] += 1

    merged = []
    for role, text, stamp in turns:
        if not text.strip():
            continue
        if merged and merged[-1][0] == role:
            merged[-1][1] += "\n\n" + text
        else:
            merged.append([role, text, stamp])
    if merged and merged[0][0] != "user":
        merged.insert(0, ["user", "(continuing a Codex session)",
                          merged[0][2]])
    return [tuple(turn) for turn in merged], meta, unknown


def claude_session(turns, session_id: str, cwd: str) -> bytes:
    """The JSONL Claude Code resumes, one record per turn, chained by
    parentUuid. Record UUIDs derive from the Session's, so the same rollout
    always produces the same bytes."""
    lines, parent = [], None
    for index, (role, text, stamp) in enumerate(turns):
        me = str(uuidlib.uuid5(NAMESPACE, f"{session_id}/{index}"))
        message = {"role": role, "content": [{"type": "text", "text": text}]}
        if role == "assistant":
            message.update(id=f"msg_handover_{me[:8]}", type="message",
                           model="codex-handover", stop_reason="end_turn")
        lines.append(json.dumps({
            "type": role, "uuid": me, "parentUuid": parent,
            "sessionId": session_id, "timestamp": stamp, "cwd": cwd,
            "isSidechain": False, "userType": "external", "message": message,
        }, ensure_ascii=False))
        parent = me
    return ("\n".join(lines) + "\n").encode("utf-8")


def target_id(codex_uuid: str) -> str:
    return str(uuidlib.uuid5(NAMESPACE, f"codex:{codex_uuid}"))


def _claude_version():
    """'2.1.312' for the installed Claude Code, or None."""
    exe = shutil.which("claude")
    if exe is None:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True,
                             text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"\d+\.\d+\.\d+", out or "")
    return match.group(0) if match else None


def _newer(version, checked: str) -> bool:
    """True when `version` is past the major.minor this was checked on."""
    if not version:
        return False
    try:
        have = tuple(int(p) for p in version.split(".")[:2])
        want = tuple(int(p) for p in checked.split(".")[:2])
    except ValueError:
        return True
    return have > want


def _issue_link(unknown, codex_versions, claude_version) -> str:
    body = ("Record kinds `carryon handover` left out:\n\n"
            + "\n".join(f"- `{kind}` ({count})"
                        for kind, count in sorted(unknown.items()))
            + f"\n\nCodex: {', '.join(sorted(codex_versions)) or 'unknown'}"
            + f"\nClaude Code: {claude_version or 'unknown'}\n")
    query = urllib.parse.urlencode({
        "title": "handover: Codex record kinds it does not know",
        "body": body})
    return f"{ISSUES}?{query}"


def _plan(home):
    """(plans, skipped, unknown, codex versions) for every Codex Session."""
    codex = ADAPTERS["codex"]
    found = history.discover(home, [codex])
    plans, skipped = [], []
    unknown, versions = collections.Counter(), set()
    for rel, why in found.unreadable:
        skipped.append((rel, why))
    for rel in found.withheld:
        skipped.append((rel, config.WHY_STATE))
    identities = config.state_identities(home)
    for session in found.sessions:
        source = home / session.project_dir / session.main_path
        rel = _rel_to_home(source, home)
        if session.cwd is None:
            skipped.append((rel, "it recorded no project folder"))
            continue
        data, why = config.read_carryable(source, home, identities)
        if why is not None:
            skipped.append((rel, why))
            continue
        turns, meta, kinds = conversation(data)
        unknown.update(kinds)
        if meta.get("cli_version"):
            versions.add(str(meta["cli_version"]))
        if not turns:
            skipped.append((rel, "it holds no conversation"))
            continue
        session_id = target_id(session.uuid)
        target = (home / ".claude" / "projects"
                  / rekey.encode_project_dir(session.cwd)
                  / f"{session_id}.jsonl")
        plans.append((rel, target, session_id, session.cwd, turns))
    return plans, skipped, unknown, versions


# --- the Setup ---------------------------------------------------------------

IMPORT_LINE = "@~/.codex/AGENTS.md"
# Codex keys carried into Claude Code's server JSON, by transport.
STDIO_KEYS = {"command", "args", "env"}
HTTP_KEYS = {"url", "http_headers"}
# Keys that change nothing about how the server is reached.
QUIET_KEYS = {"enabled", "startup_timeout_sec", "startup_timeout_ms",
              "tool_timeout_sec"}
_SERVER_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]*$")
_SERVER_HEADER = re.compile(r"^\s*\[\s*mcp_servers\.([^\].]+)\s*\]", re.M)


def _instructions(home, identities, apply):
    """(said, refused) about reaching ~/.codex/AGENTS.md from Claude Code.

    An import line rather than a copy, so an edit made for Codex reaches
    Claude Code too, and appended to ~/.claude/CLAUDE.md rather than
    replacing it, because that file is the user's. AGENTS.md goes through the
    gate even though carryon never reads it for itself: Claude Code will, and
    a hard link from there to carryon's master key would put the key in
    every conversation.
    """
    agents = home / ".codex" / "AGENTS.md"
    if not agents.exists():
        return None, None
    _data, why = config.read_carryable(agents, home, identities)
    if why is not None:
        return None, ("~/.codex/AGENTS.md", why)
    claude_md = home / ".claude" / "CLAUDE.md"
    existing = b""
    if claude_md.exists() or claude_md.is_symlink():
        existing, why = config.read_carryable(claude_md, home, identities)
        if why is not None:
            return None, ("~/.claude/CLAUDE.md", why)
    text = existing.decode("utf-8", errors="replace")
    spellings = {IMPORT_LINE, f"@{agents}"}
    if any(line.strip() in spellings for line in text.splitlines()):
        return "~/.claude/CLAUDE.md already imports ~/.codex/AGENTS.md.", None
    if apply:
        joined = text + ("\n" if text and not text.endswith("\n") else "") \
            + ("\n" if text else "") + IMPORT_LINE + "\n"
        why = external.write_owned(claude_md, joined.encode("utf-8"), home)
        if why is not None:
            return None, ("~/.claude/CLAUDE.md", why)
        return "~/.claude/CLAUDE.md now imports ~/.codex/AGENTS.md.", None
    return "~/.claude/CLAUDE.md would import ~/.codex/AGENTS.md.", None


def claude_server(server) -> tuple:
    """(JSON for `claude mcp add-json`, keys left out) for one Codex server,
    or (None, why)."""
    if not isinstance(server, dict):
        return None, "it is not a table"
    if server.get("enabled") is False:
        return None, "it is turned off in Codex"
    if server.get("bearer_token_env_var") or server.get("env_http_headers"):
        return None, ("it reads its token from the environment; add it with "
                      "`claude mcp add` by hand")
    if isinstance(server.get("command"), str):
        spec = {"type": "stdio", "command": server["command"],
                "args": [str(a) for a in server.get("args") or []]}
        if isinstance(server.get("env"), dict) and server["env"]:
            spec["env"] = {str(k): str(v) for k, v in server["env"].items()}
        carried = STDIO_KEYS
    elif isinstance(server.get("url"), str):
        spec = {"type": "http", "url": server["url"]}
        if isinstance(server.get("http_headers"), dict):
            spec["headers"] = {str(k): str(v)
                               for k, v in server["http_headers"].items()}
        carried = HTTP_KEYS
    else:
        return None, "it names neither a command nor a url"
    left = sorted(set(server) - carried - QUIET_KEYS)
    return spec, left


def _claude_mcp_add(name, spec) -> tuple:
    """('added' | 'already' | 'refused', detail) from Claude Code's own
    `claude mcp add-json`, which owns ~/.claude.json and refuses a name it
    already has. The spec is an argument, so an env value is briefly in this
    machine's process list - the price of not editing Claude Code's state
    file behind its back."""
    exe = shutil.which("claude")
    if exe is None:
        return "refused", "the claude command is not on PATH"
    try:
        done = subprocess.run(
            [exe, "mcp", "add-json", "--scope", "user", name,
             json.dumps(spec)],
            capture_output=True, text=True, timeout=60,
            stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        return "refused", str(exc)
    said = (done.stdout + done.stderr).strip()
    if done.returncode == 0:
        return "added", said
    if "already exists" in said:
        return "already", said
    return "refused", said.splitlines()[0] if said else \
        f"claude exited {done.returncode}"


def _mcp_servers(home, identities, apply):
    """(said lines, refused (name, why) pairs) for Codex's MCP servers."""
    path = home / ".codex" / "config.toml"
    if not path.exists():
        return [], []
    data, why = config.read_carryable(path, home, identities)
    if why is not None:
        return [], [("~/.codex/config.toml", why)]
    text = data.decode("utf-8", errors="replace")
    if tomllib is None:
        names = _SERVER_HEADER.findall(text)
        if not names:
            return [], []
        return [], [(f"MCP server {printable(n.strip())}",
                     "reading Codex's config.toml needs Python 3.11 or "
                     "later; add it with `claude mcp add` by hand")
                    for n in names]
    try:
        servers = tomllib.loads(text).get("mcp_servers") or {}
    except (ValueError, RecursionError) as exc:
        return [], [("~/.codex/config.toml", f"it does not parse ({exc})")]
    if not isinstance(servers, dict):
        return [], [("~/.codex/config.toml", "mcp_servers is not a table")]

    said, refused = [], []
    added = already = 0
    for name, server in sorted(servers.items()):
        label = f"MCP server {printable(name)}"
        if not _SERVER_NAME.match(name):
            refused.append((label, "Claude Code does not take that name"))
            continue
        spec, left = claude_server(server)
        if spec is None:
            refused.append((label, left))
            continue
        hits = secrets.scan(json.dumps(spec).encode())
        if apply:
            status, detail = _claude_mcp_add(name, spec)
        else:
            status, detail = "added", ""
        if status == "already":
            already += 1
            continue
        if status == "refused":
            refused.append((label, detail))
            continue
        added += 1
        if left:
            said.append(f"  {label}: left out {', '.join(map(printable, left))}"
                        ", which Claude Code has no place for")
        if hits:
            said.append(f"  {label} holds what looks like a credential "
                        f"({', '.join(hits)}); it is in Claude Code's config "
                        "too")
    if added or already:
        verb = "Added" if apply else "Would add"
        said.insert(0, f"{verb} {added} MCP server(s) to Claude Code"
                    + (f"; {already} already there" if already else "") + ".")
    return said, refused


def run(args, home) -> int:
    home = pathlib.Path(home)
    source, target = args.source, args.target
    if (source, target) == ("claude-code", "codex"):
        print("Codex brings a Claude Code setup over itself, Sessions "
              "included: start `codex` and type /import.")
        return 0
    if (source, target) != ("codex", "claude-code"):
        raise SystemExit(
            f"refusing to hand over from {printable(source)} to "
            f"{printable(target)}: carryon hands over from codex to "
            "claude-code. From claude-code to codex, use Codex's own /import.")
    if not is_installed("claude-code", home):
        raise SystemExit("Claude Code is not set up on this machine (no "
                         "~/.claude). Run `claude` once, then hand over.")

    apply = bool(getattr(args, "apply", False))
    verbose = bool(getattr(args, "verbose", False))
    plans, skipped, unknown, codex_versions = _plan(home)
    claude_version = _claude_version()

    written, already, refused = [], [], []
    for rel, path, session_id, cwd, turns in plans:
        if path.exists():
            already.append((rel, path))
            continue
        if not apply:
            written.append((rel, path, len(turns)))
            continue
        why = external.write_owned(path, claude_session(turns, session_id,
                                                        cwd),
                                   home, exclusive=True)
        if why is None:
            written.append((rel, path, len(turns)))
        else:
            refused.append((rel, why))

    verb = "Handed over" if apply else "Would hand over"
    print(f"{verb} {len(written)} Codex Session(s) to Claude Code"
          + (f"; {len(already)} already handed over" if already else "")
          + ".")
    if verbose:
        for rel, path, count in written:
            print(f"  {'wrote' if apply else 'write'}  "
                  f"~/{printable(_rel_to_home(path, home))}  <- "
                  f"~/{printable(rel)} ({count} turn{'' if count == 1 else 's'})")
        for rel, path in already:
            print(f"  already  ~/{printable(_rel_to_home(path, home))}")
    for rel, why in skipped + refused:
        print(f"  not handed over  ~/{printable(rel)} - {why}")
    if written:
        print("Each one holds the conversation, with tool calls as one-line "
              "notes. Codex's reasoning is encrypted and stays behind.")

    newer = [f"Codex {v}" for v in sorted(codex_versions)
             if _newer(v, CHECKED_AGAINST["codex"])]
    if _newer(claude_version, CHECKED_AGAINST["claude-code"]):
        newer.append(f"Claude Code {claude_version}")
    if newer:
        print(f"This was checked against Codex {CHECKED_AGAINST['codex']} "
              f"and Claude Code {CHECKED_AGAINST['claude-code']}; this "
              f"machine has {', '.join(newer)}.")
    if unknown:
        kinds = ", ".join(f"{printable(k)} ({n})"
                          for k, n in sorted(unknown.items()))
        print(f"Left out record kinds carryon does not know: {kinds}. If a "
              "Session looks wrong in Claude Code, please report it (no "
              "content is included):\n  "
              + _issue_link(unknown, codex_versions, claude_version))

    identities = config.state_identities(home)
    instructions, why = _instructions(home, identities, apply)
    if instructions:
        print(instructions)
    if why is not None:
        refused.append(why)
        print(f"  not handed over  {printable(why[0])} - {why[1]}")
    lines, servers_refused = _mcp_servers(home, identities, apply)
    for line in lines:
        print(line)
    for label, why in servers_refused:
        print(f"  not handed over  {label} - {why}")
    refused += servers_refused

    if apply:
        if written:
            print("\nResume one with `claude --resume` from its project "
                  "folder.")
    else:
        print("\nDry run. Re-run with --apply to write them.")
    return 1 if refused else 0
