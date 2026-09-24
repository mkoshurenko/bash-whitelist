#!/usr/bin/env python3
"""PreToolUse(Bash) gate — a whitelist that decides every shell call an agent writes.

Four verdicts:

  deny      — the command can break the work or the machine (force-push,
              --no-verify, reset --hard, rm -rf, curl|sh, sudo, reading .env…).
              No prompt, no override from the agent.
  recompose — deny's reason string wearing a teaching voice: the shape is
              refused AND the allowed equivalent is named. See below.
  allow     — on the curated whitelist (read-only inspection, the git flow, the
              verify gate). Runs without a prompt.
  ask       — anything else. Falls through to the normal permission prompt, so a
              new-but-harmless command costs one keypress, not a redesign.

Chained commands (&& || ; |) are split and EVERY segment must pass; the
strictest verdict of any segment wins. The split respects quotes — a `|` inside
a search pattern is part of the pattern, not a second command. Command
substitution, backticks, redirects into files and background `&` are refused
outright, because they smuggle a second command past the segment check. `2>&1`
is the one exception — it duplicates a file descriptor, it cannot start a
command.

The deny rules read the raw string, with one narrow exception: when every
segment of a chain is a tool that cannot start a process, its quoted arguments
are blanked first, so that searching FOR a dangerous word is not mistaken for
running it. See `deny_view` — that exemption is the part most worth
distrusting, and the one the fixtures spend most of their cases on.

WHY RECOMPOSE EXISTS. The reason string on a `deny` is returned to the AGENT;
the reason on an `ask` is shown only to the HUMAN. The repo this gate grew in
spent four days computing a precise diagnosis — "not on the whitelist: for" —
and handing it to the only party who could not act on it, while the agent
learned nothing and wrote the same shape again: 828 prompts in five days, 48 of
them inline heredocs and 35 of them for-loops. A shape that has a whitelisted
equivalent is therefore refused WITH that equivalent, and the agent recomposes
instead of interrupting a human to rubber-stamp a search.

What a recompose rule must never contain: anything that deletes. An equivalent
turns a stop into a detour, and there is no equivalent for removing a file.
Deletion stays an `ask`, and the human gets to hear what breaks and what the way
back is before it runs.

THE RULES ARE NOT IN THIS FILE. They live in JSON profiles so a second project
can adopt the engine without forking 500 lines of regex — see `profiles/` and
`--rules`. This file is the mechanism; the profiles are the policy.

CURATE BOTH BY HAND. They are the leash — never let an agent widen either. The
install instructions deny Edit/Write on this file, on the profiles and on the
project's rules.json for exactly that reason.

Usage:
    bash-whitelist.py                    # as a PreToolUse hook (JSON on stdin)
    bash-whitelist.py --explain '<cmd>'  # what would this command get, and why
    bash-whitelist.py --self-test        # engine fixtures + every case in the rules
    bash-whitelist.py --rules <path>     # against a specific rules.json
    bash-whitelist.py --show-rules       # the merged profile chain, as loaded
"""

import argparse
import importlib.util
import json
import os
import re
import shlex
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# Loading the rules
# --------------------------------------------------------------------------
#
# A rules file is:
#
#   {
#     "extends": ["base", "git", "node"],
#     "vars":    {"protected_branches": ["main", "master"], "branch_prefix": "feature/"},
#     "disable": ["git.checkout-protected"],
#     "deny":      [{"id": …, "pattern": …, "reason": …, "note": …}],
#     "recompose": [{"id": …, "pattern": …, "why": …, "instead": …}],
#     "allow":     [{"id": …, "pattern": …, "note": …}],
#     "no_exec":   ["rg", "grep", …],
#     "request_command": "python3 .claude/scripts/whitelist-request.py",
#     "cases":   [["git status", "allow"], ["rm -rf x", "deny", "why it matters"]]
#     "unmatched": "allow" | "agent" | "human",   what an unvetted command becomes (default human)
#     "escalate":  [{"id": …, "pattern": …, "why": …}],   unvetted and destructive: ask the human
#     "opaque":    [{"id": …, "pattern": …, "why": …, "instead": …}],   unreadable: refuse to the agent
#     "route_cases": [["git push", "human"], ["sqlite3 x", "agent"]]
#   }
#
# `extends` is merged first, in order, then the file's own lists are appended.
# `{{var}}` in any pattern is substituted: a string goes in raw (it is regex
# source), a list becomes an escaped alternation `(?:a|b|c)`.
# `disable` drops inherited rules by id, so a project can narrow what it
# inherited without forking the profile.
# Later cases with the same command override earlier ones — that is how a
# project overrides a case it deliberately made untrue.

VERDICTS = ("allow", "ask", "deny")
VAR = re.compile(r"\{\{(\w+)\}\}")


class RulesError(Exception):
    """A rules file that cannot be trusted to decide anything."""


def profile_dirs(config_path):
    """Where a bare `extends` name is looked up, nearest first."""
    dirs = []
    if config_path is not None:
        dirs += [config_path.parent / "profiles", config_path.parent]
    dirs += [HERE / "profiles", HERE.parent / "profiles", HERE.parent / "whitelist" / "profiles"]
    return dirs


def resolve_profile(name, config_path):
    """A path for one `extends` entry: a path if it looks like one, else a name."""
    if name.endswith(".json") or "/" in name:
        base = config_path.parent if config_path is not None else Path.cwd()
        candidate = (base / name) if not Path(name).is_absolute() else Path(name)
        if candidate.is_file():
            return candidate.resolve()
        raise RulesError("profile not found: %s" % name)
    for directory in profile_dirs(config_path):
        candidate = directory / (name + ".json")
        if candidate.is_file():
            return candidate.resolve()
    raise RulesError("profile not found: %s (looked in %s)"
                     % (name, ", ".join(str(d) for d in profile_dirs(config_path))))


def substitute(pattern, variables):
    """`{{name}}` → the variable, as regex source."""
    def one(match):
        name = match.group(1)
        if name not in variables:
            raise RulesError("pattern uses {{%s}}, which no `vars` block defines" % name)
        value = variables[name]
        if isinstance(value, (list, tuple)):
            if not value:
                raise RulesError("vars.%s is empty — it would match everything" % name)
            return "(?:" + "|".join(re.escape(str(v)) for v in value) + ")"
        return str(value)
    return VAR.sub(one, pattern)


def normalize(entry, kind):
    """One rule, as a dict, whatever spelling the file used."""
    if isinstance(entry, str):
        entry = {"pattern": entry}
    if not isinstance(entry, dict) or "pattern" not in entry:
        raise RulesError("%s entry is not a rule: %r" % (kind, entry))
    if kind == "deny" and not entry.get("reason"):
        raise RulesError("deny rule %r has no `reason` — the agent is told nothing"
                         % entry.get("id", entry["pattern"]))
    if kind == "recompose" and not (entry.get("why") and entry.get("instead")):
        raise RulesError("recompose rule %r needs both `why` and `instead`: a refusal with "
                         "nowhere to go is a wall, and an agent in front of a wall improvises"
                         % entry.get("id", entry["pattern"]))
    if kind in ("escalate", "opaque") and not entry.get("why"):
        raise RulesError("%s rule %r has no `why` — a stop with no reason teaches nothing"
                         % (kind, entry.get("id", entry["pattern"])))
    return dict(entry)


def normalize_case(case):
    """`["<command>", "<verdict>"]` or `{"command": …, "verdict": …}`."""
    if isinstance(case, dict):
        command, verdict = case.get("command"), case.get("verdict")
    elif isinstance(case, (list, tuple)) and len(case) >= 2:
        command, verdict = case[0], case[1]
    else:
        raise RulesError("case is not [command, verdict]: %r" % (case,))
    if verdict not in VERDICTS:
        raise RulesError("case %r has verdict %r, which is not one of %s"
                         % (command, verdict, "/".join(VERDICTS)))
    if not isinstance(command, str) or not command.strip():
        raise RulesError("case has no command: %r" % (case,))
    return (command, verdict)


ROUTES = ("human", "agent", "allow", "deny")


def normalize_route_case(case):
    """`["<command>", "human" | "agent" | "allow" | "deny"]`."""
    if not (isinstance(case, (list, tuple)) and len(case) >= 2 and case[1] in ROUTES):
        raise RulesError("route case is not [command, %s]: %r" % ("/".join(ROUTES), case))
    return (case[0], case[1])


def empty_rules():
    return {"deny": [], "recompose": [], "allow": [], "escalate": [], "opaque": [],
            "no_exec": [],
            "vars": {}, "cases": [], "route_cases": [], "unmatched": None,
            "request_command": None, "sources": []}


def load_rules(path, _seen=None):
    """One rules file and everything it extends, merged into one dict.

    A profile already pulled in by this chain contributes once and is then
    skipped — a diamond (`extends: ["git", "git-branch-policy"]`, both of which
    rest on `git`) is the normal shape here, not an error. Skipping also makes a
    genuine cycle terminate instead of recursing.
    """
    _seen = _seen if _seen is not None else set()
    path = Path(path).resolve()
    if path in _seen:
        return empty_rules()
    _seen.add(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RulesError("%s is not valid JSON — %s" % (path, exc))
    if not isinstance(data, dict):
        raise RulesError("%s must hold a JSON object" % path)

    merged = empty_rules()

    for name in data.get("extends", []):
        parent = load_rules(resolve_profile(name, path), _seen)
        for key in ("deny", "recompose", "allow", "escalate", "opaque", "no_exec", "cases",
                    "route_cases", "sources"):
            merged[key] += parent[key]
        merged["vars"].update(parent["vars"])
        merged["request_command"] = parent["request_command"] or merged["request_command"]
        merged["unmatched"] = parent["unmatched"] or merged["unmatched"]

    merged["sources"].append(str(path))
    merged["vars"].update(data.get("vars") or {})
    for key in ("deny", "recompose", "allow", "escalate", "opaque"):
        merged[key] += [normalize(e, key) for e in (data.get(key) or [])]
    merged["no_exec"] += list(data.get("no_exec") or [])
    merged["cases"] += [normalize_case(c) for c in (data.get("cases") or [])]
    merged["route_cases"] += [normalize_route_case(c) for c in (data.get("route_cases") or [])]
    if data.get("unmatched"):
        if data["unmatched"] not in ("allow", "agent", "human"):
            raise RulesError("`unmatched` is %r — it must be allow, agent or human" % data["unmatched"])
        merged["unmatched"] = data["unmatched"]
    if data.get("request_command"):
        merged["request_command"] = data["request_command"]

    disabled = set(data.get("disable") or [])
    unknown = disabled - {r.get("id") for key in ("deny", "recompose", "allow", "escalate", "opaque")
                          for r in merged[key] if r.get("id")}
    if unknown:
        raise RulesError("`disable` names rules that do not exist: %s — a typo here silently "
                         "keeps a rule the project believes it removed" % ", ".join(sorted(unknown)))
    for key in ("deny", "recompose", "allow", "escalate", "opaque"):
        merged[key] = [r for r in merged[key] if r.get("id") not in disabled]

    return merged


class Rules(object):
    """The merged, compiled policy — everything `verdict()` consults."""

    def __init__(self, merged):
        self.sources = merged["sources"]
        self.request_command = merged["request_command"]
        self.no_exec = set(merged["no_exec"])
        variables = merged["vars"]

        def compiled(entries):
            out = []
            for rule in entries:
                source = substitute(rule["pattern"], variables)
                try:
                    out.append((re.compile(source, re.IGNORECASE if rule.get("kind") == "deny"
                                           else 0), source, rule))
                except re.error as exc:
                    raise RulesError("rule %r is not a valid regex — %s"
                                     % (rule.get("id", rule["pattern"]), exc))
            return out

        for rule in merged["deny"]:
            rule["kind"] = "deny"
        self.deny = compiled(merged["deny"])
        self.recompose = compiled(merged["recompose"])
        self.allow = compiled(merged["allow"])
        self.allow_sources = [source for _, source, _ in self.allow]
        self.escalate = compiled(merged["escalate"])
        self.opaque = compiled(merged["opaque"])
        self.unmatched = merged["unmatched"] or "human"
        self.route_cases = list(dict(merged["route_cases"]).items())
        self.path = merged["sources"][-1] if merged["sources"] else None

        seen = {}
        for command, want in merged["cases"]:
            seen[command] = want          # a later case for the same command wins
        self.cases = list(seen.items())


def find_rules_path(explicit=None):
    """The rules file to use: --rules, then $BASH_WHITELIST_RULES, then the project."""
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise RulesError("no rules file at %s" % path)
        return path.resolve()

    env = os.environ.get("BASH_WHITELIST_RULES")
    if env:
        path = Path(env).expanduser()
        if not path.is_file():
            raise RulesError("BASH_WHITELIST_RULES points at %s, which does not exist" % path)
        return path.resolve()

    starts = []
    project = os.environ.get("CLAUDE_PROJECT_DIR")
    if project:
        starts.append(Path(project))
    starts += [Path.cwd(), HERE]
    for start in starts:
        for directory in [start] + list(start.resolve().parents):
            candidate = directory / ".claude" / "whitelist" / "rules.json"
            if candidate.is_file():
                return candidate.resolve()

    # Vendored next to the hook, or running straight out of the utility repo.
    for candidate in (HERE.parent / "whitelist" / "rules.json",
                      HERE / "rules.json",
                      HERE.parent / "profiles" / "default.json",
                      HERE / "profiles" / "default.json"):
        if candidate.is_file():
            return candidate.resolve()
    raise RulesError("no rules.json found — pass --rules or set BASH_WHITELIST_RULES")


# --------------------------------------------------------------------------
# The engine
# --------------------------------------------------------------------------

# Constructs that would smuggle a command past the per-segment check.
#
# The last one is named by a constant because three places need to agree on it:
# it is the only smuggler whose spelling is also ordinary English, so it is the
# only one judged on the blanked view rather than the raw line. See smuggled().
WORDS_SMUGGLER = "eval / exec / source"
REDIRECT_SMUGGLER = "redirect into a file"
BACKGROUND_SMUGGLER = "background execution / fd duplication"
SUBST_SMUGGLER = "command substitution $( )"
BACKTICK_SMUGGLER = "backtick substitution"

# The two judged on the blanked view rather than the raw line. eval, exec and
# source because they are also ordinary English; `>` because it is also a
# comparison operator — `jq 'select(.ts > "x")' f` redirects nothing, the shell
# never reads that character as a redirect, and it was refused three times in
# one session on 2026-09-15. The three guarantees that keep the eval exemption
# narrow hold here word for word: blank_haystack leaves a double-quoted run
# carrying $ or a backtick raw, the other four smugglers still read the raw
# line, and no allowed program treats a quoted argument as shell — base.shell-c
# now denies the one that did.
#
# `&` joined them on 2026-09-23. Inside quotes the shell reads it as a letter:
# `gh run list --workflow "Build & Test"`, `"Bag & Checkout"` in a PR title
# and `&quot;` in a grep pattern were 7 of the week's asks and none of them
# backgrounded anything. A double-quoted run carrying $ or a backtick is still
# left raw, so `"$X & y"` is caught as before.
#
# `$(` and the backtick joined on 2026-09-24, for the same reason: inside single
# quotes the shell reads them as letters. `grep -n -e 'fun `' f` asked twice that
# day. blank_haystack never blanks a double-quoted run carrying $ or a backtick, so
# `grep "$(id)" f` and `echo "`id`"` still reach the scan raw and still ask.
QUOTE_BLIND = {WORDS_SMUGGLER, REDIRECT_SMUGGLER, BACKGROUND_SMUGGLER,
               SUBST_SMUGGLER, BACKTICK_SMUGGLER}

SMUGGLERS = [
    (re.compile(r"\$\("), SUBST_SMUGGLER),
    (re.compile(r"`"), BACKTICK_SMUGGLER),
    (re.compile(r"(?<![0-9])>>?(?!\s*/dev/null)"), REDIRECT_SMUGGLER),
    (re.compile(r"(?<!&)&(?!&)"), BACKGROUND_SMUGGLER),
    (re.compile(r"<\("), "process substitution"),
    (re.compile(r"\beval\b|\bexec\b|\bsource\b|^\s*\.\s"), WORDS_SMUGGLER),
]

SPLIT = re.compile(r"&&|\|\||[;|\n]")

# `2>&1` / `>&2` duplicate a descriptor — they cannot introduce a command, so
# they are removed before the smuggler scan instead of costing a prompt.
FD_DUP = re.compile(r"\d?>&\d")

# One single- or double-quoted run — what a no-exec tool treats as its haystack.
QUOTED = re.compile(r"'[^']*'|\"(?:\\.|[^\"\\])*\"")

# ...but a DOUBLE-quoted run still expands: `grep "$(rm -rf /)" f` runs the rm
# before grep ever sees an argument. Such a run is left raw for the deny rules.
# Single quotes expand nothing, so they are always safe to blank.
EXPANDS = re.compile(r"[$`]")

# Flags that hand a no-exec tool a program to run — ripgrep executes `--pre`
# and `--hostname-bin`. A segment carrying one is not a haystack, it is a
# launcher, so it is scanned raw like any other command.
EXEC_FLAGS = re.compile(r"--(pre|hostname-bin)\b")

# A quoted run that is nothing BUT a path to an env file is a filename, not a
# search pattern, and blanking it would let `grep -n . ".env"` print the very
# secrets the deny list protects — the one thing a search tool can do to a file
# without executing anything. A run containing whitespace is a pattern and is
# blanked as usual; only the bare path is held back.
ENV_PATH = re.compile(r"""^['"](\S*/)?\.env(\.[\w.-]+)?['"]$""")

# A leading `VAR=value` is an environment prefix, not the program being run.
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# The gate inspecting itself. `--explain 'rm -rf x'` names a shape; it does not
# run one, so its quoted argument is a haystack exactly like grep's. Without
# this, the one question worth asking before typing — "what would this get?" —
# is refused for every shape a DENY rule covers, and the answer has to be
# guessed instead.
#
# This MUST stay no looser than the `base.gate-self` ALLOW rule. A spelling this
# recognises but that rule does not gets its quotes blanked and then fails to
# match any allow — turning a hard DENY on `sudo rm -rf /` into an ASK, which is
# a keypress where there used to be a wall. So: `python3` exactly, the path
# exactly, no leading directory, no `.next` staging copy. Verifying a staged copy
# is what `--rules <copy> --self-test` is for.
GATE_SELF = re.compile(
    r"^\s*python3\s+\.claude/hooks/(?:bash-whitelist|bash-advise|py-inline-guard"
    r"|permission-audit)\.py\s+--\S")


def split_segments(text):
    """Split a chain on `&& || ; | \\n`, ignoring separators inside quotes.

    SPLIT alone is quote-blind, so `grep -n "rm|xargs|sudo" file` arrived as
    three commands — one of them the bare word `sudo`, which the deny list duly
    refused as privilege escalation. The shell does not read it that way and
    neither should the gate. Unbalanced quoting falls back to the blind split,
    which is the stricter reading of an ambiguous string.
    """
    try:
        shlex.split(text)
    except ValueError:
        return SPLIT.split(text)

    out, buf, quote, i = [], [], None, 0
    while i < len(text):
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(text):
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif text.startswith("&&", i) or text.startswith("||", i):
            out.append("".join(buf))
            buf = []
            i += 2
            continue
        elif ch in ";|\n":
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    out.append("".join(buf))
    return out


def argv0(segment):
    """The program a segment runs — past any VAR=value prefix, without its path."""
    try:
        tokens = shlex.split(segment)
    except ValueError:  # unbalanced quoting: assume the worst, scan raw
        return ""
    for token in tokens:
        if ASSIGN.match(token):
            continue
        return token.rsplit("/", 1)[-1]
    return ""


def blank_haystack(match):
    """Erase one quoted argument — unless it is a double-quoted run that expands."""
    run = match.group(0)
    if run.startswith('"') and EXPANDS.search(run):
        return run
    if ENV_PATH.match(run):
        return run
    return " "


def deny_view(text, no_exec):
    """What the DENY rules get to read.

    For a no-exec tool the quoted arguments are blanked: they are the haystack,
    and matching a deny keyword there blocks a read-only call — `grep -n
    "rm|sudo" bash-whitelist.py` was refused for "privilege escalation" though
    it only reads a file, which is how a prompt stops meaning anything.

    Everything else is returned RAW and unchanged. That pass is the backstop:
    `node -e "fs.rmSync(…recursive:true)"` hides its damage in exactly those
    quotes, so blanking them there would be the loosening this must not be.
    Blanking is also all-or-nothing per chain — one non-no-exec segment and the
    whole string is scanned raw, so nothing rides in on a leading `grep`.

    A `--explain`/`--self-test` call on one of these hooks counts as a no-exec
    segment for this purpose: it prints a verdict and runs nothing, so the shape
    it quotes is a haystack. Without it `--explain 'rm -rf x'` is refused for
    naming the shape it was asked about, which makes the cheap way to aim
    unavailable for exactly the rules worth aiming at. The all-or-nothing rule is
    unchanged, so `… --explain 'ls'; sudo id` still gets scanned raw and denies.
    """
    if EXEC_FLAGS.search(text):
        return text
    segments = [s.strip() for s in split_segments(FD_DUP.sub("", text)) if s.strip()]
    if segments and all(argv0(s) in no_exec or GATE_SELF.match(s) for s in segments):
        return QUOTED.sub(blank_haystack, text)
    return text


def smuggled(text):
    """The first smuggler in `text`, as a reason string, or None.

    Every smuggler is judged on the raw line, with one exception: eval, exec and
    source are also ordinary English, so those three are judged on the view with
    quoted runs blanked. `git commit -m "single-source the script"` and a grep
    for this very list were both ASK'd — 24 of the 318 asks in the week to
    2026-09-09 — and neither has another spelling, so the prompt taught nobody
    anything.

    The exemption is narrower than it looks, in three ways that must all stay
    true. blank_haystack never blanks a double-quoted run carrying $ or a
    backtick, so `cmd "$(eval x)"` still stops on the $( ) rule. The other five
    smugglers still read the raw line. And no allowed program interprets a
    quoted argument as shell: `bash -c` and `sh` have no allow rule at all, so
    `bash -c 'source x'` still reaches the human on the segment check, while
    `bash -c 'exec rm -rf /'` is a DENY from deny_view before this runs, and
    `python3 -c "exec(…)"` is refused by py-inline-guard's ast pass.
    """
    stripped = FD_DUP.sub("", text)
    blanked = QUOTED.sub(blank_haystack, stripped)
    for regex, why in SMUGGLERS:
        if regex.search(blanked if why in QUOTE_BLIND else stripped):
            return why
    return None


def recomposable(text, rules):
    """The first recomposable shape found in `text`, as a reason string.

    A rule carrying `blank_quotes` is matched against the view with quoted runs
    blanked, the same view smuggled() uses for its quote-blind set. Only
    base.redirect asks for it: base.subst must keep reading the raw line,
    because a `$( )` inside double quotes really does run.
    """
    blanked = None
    for regex, _, rule in rules.recompose:
        haystack = text
        if rule.get("blank_quotes"):
            if blanked is None:
                blanked = QUOTED.sub(blank_haystack, FD_DUP.sub("", text))
            haystack = blanked
        if regex.search(haystack):
            message = ("refused by the project bash whitelist — %s. Recompose: %s."
                       % (rule["why"], rule["instead"]))
            if rules.request_command:
                message += (" If no allowed form does the job, do not retry a variant: "
                            "file it with `%s --pattern … --why … --case …` and say so."
                            % rules.request_command)
            return message
    return None


def nearest(name, rules):
    """The ALLOW rules that mention this program — the real lines, not a summary.

    A digest of the whitelist kept anywhere else drifts away from the regexes
    within a week, and an agent studying a stale copy is worse off than one
    reading nothing. So the rules quote themselves.
    """
    if not name:
        return []
    word = re.compile(r"(?<![\w\\])" + re.escape(name) + r"(?![\w])")
    return [source for source in rules.allow_sources if word.search(source)][:3]


def verdict(command, rules):
    """(decision, reason) for one command line."""
    cmd = command.strip()
    if not cmd:
        return "ask", "empty command"

    whole = deny_view(cmd, rules.no_exec)
    for regex, _, rule in rules.deny:
        if regex.search(whole):
            return "deny", "blocked by the project bash whitelist: %s" % rule["reason"]

    # Before the smugglers, so that a redirect is taught rather than escalated.
    # After DENY, so that nothing destructive is ever answered with a tidier
    # spelling of itself.
    teach = recomposable(cmd, rules)
    if teach:
        return "deny", teach

    why = smuggled(cmd)
    if why:
        return "ask", "contains %s — the whitelist cannot vet it, asking the human" % why

    for raw in split_segments(FD_DUP.sub("", cmd)):
        segment = raw.strip()
        if not segment:
            continue
        scanned = deny_view(segment, rules.no_exec)
        for regex, _, rule in rules.deny:
            if regex.search(scanned):
                return "deny", "blocked by the project bash whitelist: %s" % rule["reason"]
        try:  # a segment that will not even tokenize is not whitelistable
            shlex.split(segment)
        except ValueError:
            return "ask", "unbalanced quoting"
        teach = recomposable(segment, rules)
        if teach:
            return "deny", teach
        if not any(re.fullmatch(source, segment, re.DOTALL) for source in rules.allow_sources):
            name = argv0(segment) or segment.split()[0]
            hits = nearest(name, rules)
            if hits:
                hint = " the rules that mention it: " + " · ".join(hits)
            elif rules.request_command:
                hint = (" no rule allows it at all — recompose, or file it with `%s`"
                        % rules.request_command)
            else:
                hint = " no rule allows it at all — recompose it into an allowed shape"
            return "ask", "not on the project bash whitelist: %s —%s" % (name, hint)

    return "allow", "on the project bash whitelist"


# --------------------------------------------------------------------------
# Routing — who answers an `ask`
# --------------------------------------------------------------------------
#
# verdict() says whether a command is vetted. route() says what an unvetted one
# becomes. Deny and recompose rules have already fired by then.
#
#   escalate match  -> ask the human: it deletes, overwrites or publishes
#   opaque match    -> refused to the agent with rewrite help: code the gate cannot read
#   otherwise       -> by "unmatched": "allow" runs it, "agent" refuses it with help,
#                      "human" (the default) asks, which is the behaviour before 2026-09-24
#
# Added 2026-09-24. The gate exists to stop a mistaken command from destroying
# data. As an allowlist it was asking a person about every unfamiliar shape, and
# the person approved them without reading. The threat is an agent's mistake, and
# a mistake looks like an ordinary command, so a denylist sees it.

AGENT_PREFIX = "not vetted, refused to you; the human was not asked. "

# bash-advise writes for a prompt the human is about to see. Refused to the agent,
# the same text has to stop telling it to let the prompt stand.
ADVICE_REWORDING = (
    ("bash-advise (the whitelist ASK'd this call; the gate's own reason went to the human only):",
     "rewrite help:"),
    ("bash-advise (the whitelist ASK'd this call):", "rewrite help:"),
    ("so it asks.", "so it refuses."),
    ("Either recompose the work into an already-allowed shape, or let the prompt stand and tell "
     "the human in one line what this call does and why it is needed, so the approval is informed.",
     "Recompose the work into an already-allowed shape: the Read, Grep, Glob and Edit tools, "
     "or a reviewed script under .claude/scripts."),
    ("If this shape will recur, file the rule instead of paying the prompt again: ",
     "If nothing allowed does the job, file the rule: "),
)


def agent_advice(command, rules):
    """bash-advise's rewrite text for `command`, reworded for a refusal. None if none."""
    try:
        spec = importlib.util.spec_from_file_location("bash_advise", HERE / "bash-advise.py")
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        gate = types.SimpleNamespace(split_segments=split_segments, FD_DUP=FD_DUP,
                                     smuggled=smuggled, argv0=argv0, SMUGGLERS=SMUGGLERS)
        text = module.compose(command, gate, rules, module.load_advice(rules.path))
    except Exception:  # noqa: BLE001 — advice is help, never a reason to fail the call
        return None
    if not text:
        return None
    for old, new in ADVICE_REWORDING:
        text = text.replace(old, new)
    return text


UNREADABLE = ("empty command", "unbalanced quoting")


def route(command, decision, reason, rules, with_advice=True):
    """(decision, reason) after deciding what an unvetted command becomes."""
    if decision != "ask" or rules.unmatched == "human":
        return decision, reason
    for regex, _, rule in rules.escalate:
        if regex.search(command):
            return "ask", "%s (escalated to the human by %s: %s)" % (
                reason, rule.get("id", "escalate"), rule["why"])
    opaque = None
    for regex, _, rule in rules.opaque:
        if regex.search(command):
            opaque = rule
            break
    if opaque is None and rules.unmatched == "allow" and reason not in UNREADABLE:
        return "allow", ("not on the whitelist, and no deny, escalate or opaque rule matched: "
                         "allowed by unmatched=allow")
    parts = [AGENT_PREFIX + reason]
    if opaque is not None:
        parts.append("%s: %s. Instead: %s" % (opaque.get("id", "opaque"), opaque["why"],
                                             opaque.get("instead", "run the commands directly")))
    if with_advice:
        advice = agent_advice(command, rules)
        if advice:
            parts.append(advice)
    policy = ("Recompose the call into an allowed shape and retry. After two refusals for the "
              "same step, stop trying variants")
    if rules.request_command:
        policy += ": file `%s --pattern … --why … --tried … --case …`" % rules.request_command
    policy += (", then do the step another way or list it as blocked in your final summary. "
               "Do not ask the human to run it.")
    parts.append(policy)
    return "deny", "\n".join(parts)


def route_label(decision, reason):
    """What a route case compares: human, agent, or the plain verdict."""
    if decision == "ask":
        return "human"
    if decision == "deny" and reason.startswith(AGENT_PREFIX):
        return "agent"
    return decision


def routed_away(command, rules):
    """True when route() turns this command's `ask` into something other than an ask."""
    decision, reason = verdict(command, rules)
    return decision == "ask" and route(command, decision, reason, rules, with_advice=False)[0] != "ask"


# --------------------------------------------------------------------------
# Fixtures — the engine's own, plus every case the loaded rules carry
# --------------------------------------------------------------------------

def engine_checks():
    """What the mechanism promises, independent of any policy.

    These are the parts a project can break without touching a single regex: the
    quote-aware split, the no-exec blanking, and the rule loader's refusal to
    accept a rule it cannot be trusted to apply.
    """
    no_exec = {"grep", "rg"}
    return [
        ("a `|` inside quotes is not a second command",
         lambda: split_segments('grep -n "a|b" f'), ['grep -n "a|b" f']),
        ("a real pipe still splits",
         lambda: [s.strip() for s in split_segments("ls | wc -l")], ["ls", "wc -l"]),
        ("&& splits", lambda: [s.strip() for s in split_segments("a && b")], ["a", "b"]),
        ("unbalanced quoting falls back to the blind split",
         lambda: len(split_segments('grep "a|b f')), 2),
        ("argv0 sees past an env prefix",
         lambda: argv0("FOO=1 npm run lint"), "npm"),
        ("argv0 strips the path", lambda: argv0("/usr/bin/git status"), "git"),
        ("a search tool's quoted haystack is blanked",
         lambda: "sudo" in deny_view('grep -n "sudo" f', no_exec), False),
        ("...but one segment that can execute and the whole chain is read raw",
         lambda: "sudo" in deny_view('grep -n "sudo" f && ls', no_exec), True),
        ("...and a double-quoted substitution is never blanked",
         lambda: "rm -rf" in deny_view('grep "$(rm -rf /)" f', no_exec), True),
        ("...and a quoted .env path is a filename, not a haystack",
         lambda: ".env" in deny_view('grep -n . ".env"', no_exec), True),
        ("--pre makes ripgrep a launcher, not a haystack",
         lambda: "sudo" in deny_view('rg --pre "sudo" src', no_exec), True),
        ("a quoted eval/exec/source word is a message, not a keyword",
         lambda: smuggled('git -C repo commit -m "single-source the script"'), None),
        ("...but an unquoted one is still caught",
         lambda: smuggled('eval "$CMD"'), WORDS_SMUGGLER),
        ("...and one hiding in a double-quoted substitution stops earlier still",
         lambda: smuggled('cmd "$(eval x)"'), "command substitution $( )"),
        ("the gate explaining a shape does not run it",
         lambda: "rm -rf" in deny_view(
             "python3 .claude/hooks/bash-whitelist.py --explain 'rm -rf x'", no_exec), False),
        ("...but one segment that can execute and the whole chain is read raw, quotes included",
         lambda: "sudo" in deny_view(
             "python3 .claude/hooks/bash-whitelist.py --explain 'ls'; bash -c 'sudo id'",
             no_exec), True),
        ("...and a foreign prefix on the real hook name does not count",
         lambda: "rm -rf" in deny_view(
             "python3 /tmp/evil/.claude/hooks/bash-whitelist.py --explain 'rm -rf x'",
             no_exec), True),
        ("...nor `python` without the 3, which the allow rule does not accept either",
         lambda: "rm -rf" in deny_view(
             "python .claude/hooks/bash-whitelist.py --explain 'rm -rf x'", no_exec), True),
        ("...nor a staged .next copy, which is not the installed gate",
         lambda: "rm -rf" in deny_view(
             "python3 .claude/hooks/bash-whitelist.next.py --explain 'rm -rf x'",
             no_exec), True),
        ("a quoted & is text, not background execution",
         lambda: smuggled('gh run list --workflow "Build & Test"'), None),
        ("...but an unquoted one is still caught",
         lambda: smuggled('./gradlew build &'), BACKGROUND_SMUGGLER),
        ("...and one inside an expanding double-quoted run is still caught",
         lambda: smuggled('echo "$X & y"'), BACKGROUND_SMUGGLER),
        ("a single-quoted backtick is a letter",
         lambda: smuggled("grep -n -e 'fun `' f"), None),
        ("...and so is a single-quoted $(",
         lambda: smuggled("grep -n '$(' f"), None),
        ("...but a double-quoted substitution still runs and is still caught",
         lambda: smuggled('grep "$(id)" f'), SUBST_SMUGGLER),
        ("...and so is a double-quoted backtick",
         lambda: smuggled('echo "`id`"'), BACKTICK_SMUGGLER),
        ("...and an unquoted one",
         lambda: smuggled('echo $(whoami)'), SUBST_SMUGGLER),
        ("2>&1 is not a redirect into a file",
         lambda: FD_DUP.sub("", "cmd --flag 2>&1"), "cmd --flag "),
        ("a list variable becomes an escaped alternation",
         lambda: substitute(r"\b{{b}}\b", {"b": ["main", "v1.0"]}), r"\b(?:main|v1\.0)\b"),
        ("a string variable goes in as regex source",
         lambda: substitute("{{p}}\\S+", {"p": "feature/"}), "feature/\\S+"),
        ("an undefined variable is refused, not silently emptied",
         lambda: _refused(substitute, "{{nope}}", {}) is not None, True),
        ("an empty list variable is refused — it would match everything",
         lambda: _refused(substitute, "{{b}}", {"b": []}) is not None, True),
        ("a deny rule with no reason is refused",
         lambda: _refused(normalize, {"pattern": "x"}, "deny") is not None, True),
        ("a recompose rule with no equivalent is refused",
         lambda: _refused(normalize, {"pattern": "x", "why": "y"}, "recompose") is not None, True),
        ("a case with an unknown verdict is refused",
         lambda: _refused(normalize_case, ["ls", "maybe"]) is not None, True),
        ("a fixture that raises is one FAIL, not a dead run",
         _boom, "raised RuntimeError('fixture blew up')"),
    ]


def _boom():
    raise RuntimeError("fixture blew up")


def _refused(call, *args):
    """The message `call` refused with, or None if it accepted."""
    try:
        call(*args)
    except Exception as exc:  # noqa: BLE001 — the fixture asks only "did it refuse"
        return str(exc)
    return None


def self_test(rules, verbose=False):
    """Engine fixtures, then every case the rule chain carries. In-process."""
    failed = 0
    total = 0
    for name, probe, want in engine_checks():
        try:
            got = probe()
        except Exception as exc:  # noqa: BLE001 — a raising fixture is a FAIL, not a dead run
            got = "raised %r" % (exc,)
        ok = got == want
        total += 1
        failed += 0 if ok else 1
        if verbose or not ok:
            print(("ok   " if ok else "FAIL ") + name
                  + ("" if ok else "\n     got %r want %r" % (got, want)))

    if not rules.cases:
        print("\nWARNING: the rules carry no cases. A policy nobody tested is a policy "
              "nobody can change safely — add a `cases` list to rules.json.")
    for command, want in rules.cases:
        try:
            got, reason = verdict(command, rules)
        except Exception as exc:  # noqa: BLE001
            got, reason = "raised %r" % (exc,), ""
        ok = got == want
        total += 1
        failed += 0 if ok else 1
        if verbose or not ok:
            print("%s %-5s (want %-5s)  %s%s"
                  % ("ok  " if ok else "FAIL", got, want, command,
                     "" if ok else "\n     %s" % reason))

    for command, want in rules.route_cases:
        try:
            decision, reason = verdict(command, rules)
            decision, reason = route(command, decision, reason, rules, with_advice=False)
            got = route_label(decision, reason)
        except Exception as exc:  # noqa: BLE001
            got, reason = "raised %r" % (exc,), ""
        ok = got == want
        total += 1
        failed += 0 if ok else 1
        if verbose or not ok:
            print("%s route %-5s (want %-5s)  %s%s"
                  % ("ok  " if ok else "FAIL", got, want, command,
                     "" if ok else "\n     %s" % reason))

    if rules.unmatched != "human" and rules.opaque:
        probe = "bash /tmp/x.sh"
        decision, reason = route(probe, *verdict(probe, rules), rules=rules)
        ok = decision == "deny" and "rewrite help:" in reason and "Do not ask the human" in reason
        total += 1
        failed += 0 if ok else 1
        if verbose or not ok:
            print(("ok   " if ok else "FAIL ") + "a refusal to the agent carries the rewrite help"
                  + ("" if ok else "\n     %s" % reason))

    print("\n%d/%d passed  (rules: %s)"
          % (total - failed, total, " → ".join(Path(s).name for s in rules.sources)))
    return 1 if failed else 0


# --------------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------------

def hook(rules_path):
    """The PreToolUse contract: JSON in, one permissionDecision out."""
    try:
        data = json.load(sys.stdin)
    except Exception:  # noqa: BLE001 — never break the session on malformed input
        return 0
    if data.get("tool_name") != "Bash":
        return 0

    command = (data.get("tool_input") or {}).get("command", "")
    try:
        rules = Rules(load_rules(find_rules_path(rules_path)))
        decision, reason = verdict(command, rules)
        decision, reason = route(command, decision, reason, rules)
    except RulesError as exc:
        # A gate that cannot read its own policy must not silently allow. Ask,
        # and say why — a broken rules.json is a five-second fix once it is named.
        decision, reason = "ask", "the bash whitelist could not load its rules: %s" % exc

    json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                      "permissionDecision": decision,
                                      "permissionDecisionReason": reason}}, sys.stdout)
    return 0


def main():
    ap = argparse.ArgumentParser(add_help=True, description=__doc__.split("\n")[0])
    ap.add_argument("--rules", help="path to a rules.json (default: the project's)")
    ap.add_argument("--explain", metavar="CMD", help="print the verdict and reason for one command")
    ap.add_argument("--self-test", action="store_true",
                    help="run the engine fixtures and every case in the rules; touches no files")
    ap.add_argument("--show-rules", action="store_true",
                    help="print the merged rule chain as it was loaded")
    ap.add_argument("-v", "--verbose", action="store_true", help="print passing checks too")
    args = ap.parse_args()

    if not (args.explain or args.self_test or args.show_rules):
        return hook(args.rules)

    try:
        path = find_rules_path(args.rules)
        rules = Rules(load_rules(path))
    except RulesError as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2

    if args.show_rules:
        print("rules:   %s" % " → ".join(rules.sources))
        print("no_exec: %s" % " ".join(sorted(rules.no_exec)))
        print("request: %s" % (rules.request_command or "—"))
        print("unmatched: %s" % rules.unmatched)
        for kind, entries in (("DENY", rules.deny), ("RECOMPOSE", rules.recompose),
                              ("ALLOW", rules.allow), ("ESCALATE", rules.escalate),
                              ("OPAQUE", rules.opaque)):
            print("\n%s (%d)" % (kind, len(entries)))
            for _, source, rule in entries:
                print("  %-34s %s" % (rule.get("id", ""), source))
        print("\nCASES (%d)" % len(rules.cases))
        return 0

    if args.explain:
        decision, reason = verdict(args.explain, rules)
        routed, routed_reason = route(args.explain, decision, reason, rules)
        print("%s  %s" % (decision.upper(), args.explain))
        print("       %s" % reason)
        if (routed, routed_reason) != (decision, reason):
            print("ROUTED %s" % route_label(routed, routed_reason).upper())
            print("       %s" % routed_reason.replace("\n", "\n       "))
        return 0

    return self_test(rules, verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
