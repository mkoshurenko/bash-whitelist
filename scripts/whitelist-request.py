#!/usr/bin/env python3
"""File a request for a new bash-whitelist rule. Records; never applies.

An agent that hits a shape the whitelist has no form for has exactly two honest
moves: recompose into an allowed form, or ask for the FORM to be allowed. A
permission prompt is neither — it approves one invocation, teaches the system
nothing, and spends a human's attention on a decision they will have to make
again tomorrow. This script is the second move.

It appends to .claude/whitelist/requests.jsonl and prints the patch the human
would apply to rules.json. It does not touch the rules: whoever can widen the
leash does not have one.

    python3 .claude/scripts/whitelist-request.py \\
        --pattern 'gh\\s+pr\\s+(list|view)\\b.*' \\
        --why 'reading PR state needs the gh CLI; no allowed form reaches it' \\
        --tried 'git ls-remote shows refs, not PR bodies' \\
        --case 'gh pr list|allow' \\
        --case 'gh pr merge 12|ask'

    python3 .claude/scripts/whitelist-request.py --self-test

Refused outright: anything that deletes. Deletion is not a shape with a better
spelling, and autonomy over it is not something to be won one rule at a time.

--self-test exists because DESTRUCTIVE below is the only thing standing between
an agent and a rule that would authorise `rm`, and in the repo this came from
not one of its sixteen probes had ever been run against the shape it is meant to
catch. A probe that silently matches nothing does not fail loudly — it clears a
pattern, and the request reaches a human already carrying the reviewer's
presumption that the script checked it. The fixtures are pure: no file is read,
no repository is needed.
"""

import argparse
import datetime
import json
import os
import pathlib
import re
import sys


def queue_path():
    override = os.environ.get("BASH_WHITELIST_REQUESTS")
    if override:
        return pathlib.Path(override).expanduser()
    project = os.environ.get("CLAUDE_PROJECT_DIR")
    root = pathlib.Path(project) if project else pathlib.Path.cwd()
    return root / ".claude" / "whitelist" / "requests.jsonl"


# A proposed pattern that could match any of these is rejected. The test is on
# the PATTERN TEXT, not on a command: this asks "could the rule you want ever
# authorise a delete", and the answer has to be no before anyone reads further.
DESTRUCTIVE = [
    (r"\brm\b", "rm"),
    (r"\bunlink\b", "unlink"),
    (r"\bshred\b", "shred"),
    (r"\btrash\b", "trash"),
    (r"-delete\b", "find -delete"),
    (r"\bgit\s*\\?s?\+?clean\b|\bclean\b", "git clean"),
    (r"\bgit\s*\\?s?\+?rm\b", "git rm"),
    (r"\bprune\b", "prune"),
    (r"\bdrop\b", "stash drop / db drop"),
    # `fs\\?\.rm` and not `fs\.rm`: a rule is written as a regex, so the dot
    # arrives escaped. The bare spelling matched nothing a real request contains.
    (r"\brmtree\b|\brmSync\b|\bfs\\?\.rm\b", "recursive delete in inline code"),
    (r"\bcache\s*\\?s?\+?clean\b|\bcache\b", "cache clearing"),
    (r"\btruncate\b", "truncate"),
    (r"\bmkfs\b|\bdd\b", "raw device write"),
    (r"\breset\b", "git reset"),
    (r"\bsudo\b", "privilege escalation"),
    (r"--force\b|-f\b", "a forcing flag"),
]

# Proposed-pattern fixtures per DESTRUCTIVE entry, keyed by its name. These are
# pattern TEXTS, spelled the way a rule is written (`\s+`, not a space), so each
# probe is exercised against the escaping it will really meet.
#
# Every ALTERNATION BRANCH needs a fixture of its own, not every entry: where a
# narrow branch sits beside a broad one — `\bcache\s*\\?s?\+?clean\b|\bcache\b` —
# the broad one answers for both, and the narrow one can be broken to match
# nothing without a single check going red.
SAMPLES = {
    "rm": [r"rm\s+-r\s+\S+"],
    "unlink": [r"unlink\s+\S+"],
    "shred": [r"shred\s+-u\s+\S+"],
    "trash": [r"trash\s+\S+"],
    "find -delete": [r"find\s+\S+\s+-name\s+\S+\s+-delete"],
    "git clean": [r"git\s+clean\s+-fd"],
    "git rm": [r"git\s+rm\s+--cached\s+\S+"],
    "prune": [r"git\s+remote\s+prune\s+origin"],
    "stash drop / db drop": [r"git\s+stash\s+drop"],
    "recursive delete in inline code": [r"node\s+-e\s+.*rmtree\(.*",
                                        r"node\s+-e\s+.*rmSync\(.*",
                                        r"node\s+-e\s+.*fs\.rm\(.*",
                                        r"node\s+-e\s+.*fs.rm\(.*"],
    "cache clearing": [r"npm\s+cache\s+clean\s+--force", r"npm\s+cache\s+verify"],
    "truncate": [r"truncate\s+-s\s+\S+"],
    "raw device write": [r"mkfs\.ext4\s+\S+", r"dd\s+if=\S+\s+of=\S+"],
    "git reset": [r"git\s+reset\s+--hard\s+\S+"],
    "privilege escalation": [r"sudo\s+launchctl\s+\S+"],
    "a forcing flag": [r"git\s+push\s+--force\s+\S+", r"git\s+push\s+-f\s+\S+"],
}

VERDICTS = {"allow", "ask", "deny"}

# A proposed pattern is regex SOURCE, so a destructive verb can arrive glued to
# the escape that anchors it. `\brm\s+-rf\s+\S+` puts a word character — the `b`
# of `\b` — immediately before `rm`, so `\brm\b` finds no boundary there and
# matches nothing at all: such a pattern was once cleared as harmless.
#
# So each probe is run twice: against the pattern as written, and against a copy
# with the escapes blanked out. Only LETTER escapes can hide a verb this way;
# `\.` and `\+` end in a non-word character and leave the boundary intact. A
# blanked spelling can only ever ADD a match, so no catch that works today is
# lost, and a false positive here refuses a request — which is the safe way for
# this particular script to be wrong.
ESCAPE = re.compile(r"\\[A-Za-z]")


def spellings(pattern):
    """The pattern as written, and with its regex escapes blanked to spaces."""
    return (pattern, ESCAPE.sub(" ", pattern))


def destructive(pattern):
    """The first destructive shape the proposed pattern could authorise."""
    for probe, name in DESTRUCTIVE:
        for spelling in spellings(pattern):
            if re.search(probe, spelling, re.IGNORECASE):
                return name
    return None


def parse_case(raw):
    """`<command>|<verdict>` — the shape the rules files store cases in."""
    command, sep, verdict = raw.rpartition("|")
    if not sep or verdict.strip() not in VERDICTS:
        raise argparse.ArgumentTypeError(
            "case must end in |allow, |ask or |deny — got %r" % raw)
    if not command.strip():
        raise argparse.ArgumentTypeError("case has no command: %r" % raw)
    return (command.strip(), verdict.strip())


def parse_cases_text(text):
    """Every case in a --cases-file body. Blank lines and # comments ignored.

    Raises ValueError as `<line number>: <what was wrong>` — the number is the
    line in the FILE, so a malformed case can be found without counting.
    """
    cases = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            cases.append(parse_case(line))
        except argparse.ArgumentTypeError as exc:
            raise ValueError("%d: %s" % (number, exc))
    return cases


def patch_line(pattern, rule_id=None):
    """The `allow` entry to paste into rules.json — as JSON, because the rules are JSON.

    It must parse BACK to the pattern asked for. An earlier version of this
    printed a Python `r'…'` literal whose repr() doubled the backslashes: the
    pasted rule then matched a literal `\\s` and therefore nothing any command
    contains. It fails CLOSED — a dead rule, not a wide one — which is exactly
    why nobody noticed, and why a script whose job is to be trusted by a reviewer
    has to prove its own output round-trips.
    """
    entry = {"pattern": pattern}
    if rule_id:
        entry = {"id": rule_id, "pattern": pattern}
    return "    " + json.dumps(entry, ensure_ascii=False) + ","


def only_happy(cases):
    """True when no case names a command the proposed rule must NOT authorise."""
    return not any(verdict in ("ask", "deny") for _, verdict in cases)


def _boom():
    """A fixture that raises, so the harness can prove it survives one."""
    raise RuntimeError("fixture blew up")


def _refused(call, *args):
    """The message `call` refused with, or None if it accepted."""
    try:
        call(*args)
    except Exception as exc:  # noqa: BLE001 — the fixture asks only "did it refuse"
        return str(exc)
    return None


def self_test():
    """Fixtures for every probe and every parser. Touches no file, needs no repo.

    Each check holds a CALLABLE, not a value: an eagerly-built list computes
    every fixture before the first line prints, so one raising expression takes
    the whole run down — including the check written for that very case. A
    fixture that raises has to be one FAIL.
    """
    checks = [
        ("every DESTRUCTIVE probe has a fixture",
         lambda: sorted(SAMPLES), sorted(name for _, name in DESTRUCTIVE)),
        # splitting a probe on `|` is only the same alternation when no group
        # carries one of its own; assert that rather than assume it.
        ("no probe hides an alternation inside a group",
         lambda: [probe for probe, _ in DESTRUCTIVE if "(" in probe], []),
    ]
    for probe, name in DESTRUCTIVE:
        for branch in probe.split("|"):
            checks.append(("the %s probe branch %s matches a fixture" % (name, branch),
                           lambda b=branch, n=name: any(re.search(b, sample, re.IGNORECASE)
                                                        for sample in SAMPLES.get(n, [])), True))
    for name, samples in SAMPLES.items():
        for sample in samples:
            checks.append(("a %s pattern is refused: %s" % (name, sample),
                           lambda s=sample: destructive(s) is not None, True))
    # …and every fixture again, spelled the way a rule anchors itself. A probe
    # opening with `\b` cannot see a verb that a `\b` already precedes, so this
    # is the spelling that matters most and the one that was never tested.
    for name, samples in SAMPLES.items():
        for sample in samples:
            checks.append(("a %s pattern anchored with a boundary is refused: \\b%s" % (name, sample),
                           lambda s=sample: destructive(r"\b" + s) is not None, True))
    checks += [
        ("a read-only pattern passes",
         lambda: destructive(r"gh\s+pr\s+(list|view)\b.*"), None),
        ("a test-runner pattern passes",
         lambda: destructive(r"npx\s+playwright\s+test\s+\S+"), None),
        # blanking the escapes must not invent a verb that was never proposed
        ("a boundary-anchored read-only pattern still passes",
         lambda: destructive(r"\bgh\s+pr\s+(list|view)\b.*"), None),
        # the patch the human is handed has to mean what the request asked for
        ("the printed allow entry parses back to the pattern asked for",
         lambda: json.loads(patch_line(r"gh\s+pr\s+(list|view)\b.*").strip().rstrip(","))["pattern"],
         r"gh\s+pr\s+(list|view)\b.*"),
        ("...even when the pattern carries a quote",
         lambda: json.loads(patch_line(r"echo\s+'\S+'").strip().rstrip(","))["pattern"],
         r"echo\s+'\S+'"),
        ("...and it keeps the id it was given",
         lambda: json.loads(patch_line(r"gh\s+pr\b.*", "gh.read").strip().rstrip(","))["id"],
         "gh.read"),
        ("a case keeps a pipe inside its command",
         lambda: parse_case("grep foo | wc -l|allow"), ("grep foo | wc -l", "allow")),
        ("a case with no verdict is refused",
         lambda: _refused(parse_case, "ls -la") is not None, True),
        ("a case with an unknown verdict is refused",
         lambda: _refused(parse_case, "ls -la|maybe") is not None, True),
        ("a case with no command is refused",
         lambda: _refused(parse_case, "|allow") is not None, True),
        ("comments and blank lines are not cases",
         lambda: parse_cases_text("# a note\n\nls -la|allow\n"), [("ls -la", "allow")]),
        ("a malformed line is refused by its line number in the file",
         lambda: (_refused(parse_cases_text,
                           "# a note\n\nls -la|allow\nnot a case\n") or "").split(":")[0],
         "4"),
        ("cases that are all happy paths are not enough",
         lambda: only_happy([("gh pr list", "allow")]), True),
        ("one unhappy case is enough",
         lambda: only_happy([("gh pr list", "allow"), ("gh pr list; sudo id", "deny")]), False),
        # the harness's own promise: a fixture that blows up is ONE failure
        ("a check that raises is reported, not fatal",
         _boom, "raised RuntimeError('fixture blew up')"),
    ]

    failed = 0
    for name, probe_value, want in checks:
        try:
            got = probe_value()
        except Exception as exc:  # noqa: BLE001 — a raising fixture is a FAIL, not a dead run
            got = "raised %r" % (exc,)
        ok = got == want
        failed += 0 if ok else 1
        print(("ok   " if ok else "FAIL ") + name
              + ("" if ok else "\n     got %r want %r" % (got, want)))
    print("\n%d/%d passed" % (len(checks) - failed, len(checks)))
    return 1 if failed else 0


def main():
    argv = sys.argv[1:]
    if "--self-test" in argv:
        if argv != ["--self-test"]:
            print("refused: --self-test takes no other arguments", file=sys.stderr)
            return 2
        return self_test()

    ap = argparse.ArgumentParser(description="Request a bash-whitelist rule.")
    ap.add_argument("--pattern", required=True,
                    help="the allow regex you are asking for, anchored as the rules are")
    ap.add_argument("--why", required=True,
                    help="what work this unblocks — in terms of the task, not of convenience")
    ap.add_argument("--tried", required=True,
                    help="which allowed form you tried and why it does not do the job")
    ap.add_argument("--id", help="the rule id to file it under, e.g. gh.read")
    ap.add_argument("--case", action="append", type=parse_case, default=[],
                    metavar="CMD|VERDICT",
                    help="a case for the rules file; repeat. At least one must be `ask` or "
                         "`deny` — a rule with only happy cases has not been thought about")
    # The gate reads a command raw, so the moment a case spells out the dangerous
    # neighbour a rule must NOT authorise — `… ; sudo id`, `… | xargs rm` — the
    # request itself is refused as if it WERE that command. The requirement and
    # the guard contradicted each other, and both were right: the fix is the one
    # heredocs get. The text goes in a file, the command carries a path.
    ap.add_argument("--cases-file", type=pathlib.Path,
                    help="a file of `<command>|<verdict>` lines; use it when a case must name "
                         "a command the gate itself denies. Blank lines and # comments ignored.")
    ap.add_argument("--self-test", action="store_true",
                    help="run the probe and parser fixtures and exit; touches no files")
    args = ap.parse_args(argv)

    if args.cases_file:
        if not args.cases_file.is_file():
            print("refused: %s does not exist" % args.cases_file, file=sys.stderr)
            return 2
        try:
            args.case.extend(parse_cases_text(args.cases_file.read_text(encoding="utf-8")))
        except ValueError as exc:
            print("refused: %s:%s" % (args.cases_file, exc), file=sys.stderr)
            return 2
    if not args.case:
        print("refused: no cases — pass --case or --cases-file", file=sys.stderr)
        return 2

    hit = destructive(args.pattern)
    if hit:
        print("refused: this pattern could authorise %s.\n"
              "Deletion and cache-clearing stay a human decision — state what, why now, "
              "what breaks and the way back, and ask." % hit, file=sys.stderr)
        return 2

    try:
        re.compile(args.pattern)
    except re.error as exc:
        print("refused: %r is not a valid regex — %s" % (args.pattern, exc), file=sys.stderr)
        return 2

    if only_happy(args.case):
        print("refused: every case is a happy path. Add the neighbouring command this rule "
              "must NOT authorise — that case is the reason anyone can trust the rule.",
              file=sys.stderr)
        return 2

    row = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "pattern": args.pattern,
        "id": args.id,
        "why": args.why,
        "tried": args.tried,
        "cases": [{"command": c, "verdict": v} for c, v in args.case],
        "status": "proposed",
    }
    queue = queue_path()
    queue.parent.mkdir(parents=True, exist_ok=True)
    with queue.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    print("queued in %s — nothing was applied. Hand the human this patch:\n" % queue)
    print('  # .claude/whitelist/rules.json, in "allow":')
    print(patch_line(args.pattern, args.id))
    print('\n  # …and in "cases":')
    for command, verdict in args.case:
        print("    " + json.dumps([command, verdict], ensure_ascii=False) + ",")
    print("\n  why:   %s" % args.why)
    print("  tried: %s" % args.tried)
    return 0


if __name__ == "__main__":
    sys.exit(main())
