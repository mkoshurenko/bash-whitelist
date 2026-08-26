#!/usr/bin/env python3
"""PreToolUse(Bash) advisor — the missing half of the whitelist's ASK verdict.

`bash-whitelist.py` returns four verdicts and speaks to a different party in
each. `deny` and `recompose` put their reason in front of the AGENT, so the agent
recomposes and nobody is interrupted. `ask` puts its reason in front of the HUMAN
only — the agent watches a permission prompt appear, learns nothing, and writes
the same shape again next turn. `permission-audit.py --report` is what that
costs: in the repo this was written for, 211 Bash prompts, the same handful of
shapes over and over, four of them the identical `git checkout`.

This hook closes that gap without touching the gate. It re-runs the whitelist's
own `verdict()` — imported, never reimplemented, so the two can never disagree —
and when the answer is `ask` it returns `additionalContext`, which the harness
delivers to the model as non-error feedback. It never returns a
`permissionDecision`. It cannot allow, deny or alter a call: the gate decides,
this only explains.

Three kinds of explanation, and the last two matter more than the first:

  1. An allowed rewrite exists. Name it, and name why the shape the agent wrote
     is off the list. From `advice.json`, curated by hand next to the rules.
  2. The blocker is a smuggler — `$( )`, a backtick, a redirect — and not any one
     program. Say that, because advising such a line against the allow rules
     produces nonsense about a program called `MB=$(git`.
  3. No allowed rewrite exists. Say so explicitly, so the agent stops hunting for
     a spelling that passes, tells the human in one line what the call is for so
     the approval is informed, and — if the shape will recur — files it with
     `whitelist-request.py` instead of paying a prompt every time.

WHY THIS IS A SECOND HOOK AND NOT A BETTER `ask` REASON. `permissionDecisionReason`
is shown to the human; it is the string on the approve/deny dialog. There is no
spelling of it that reaches the model. `additionalContext` is a different channel
with a different audience, and a hook that returns it must not also return a
decision — so the audiences stay separate and the gate stays the only thing that
decides. Keeping it in its own file also means the advice can be edited, and the
advice table curated, without touching the write-protected gate.

Failure is always silent. A missing rules file, a broken `advice.json`, an import
that does not resolve: exit 0, emit nothing. An advisor that breaks a session is
worse than one that says nothing.

Usage:
    bash-advise.py                    # as a PreToolUse hook (JSON on stdin)
    bash-advise.py --explain '<cmd>'  # the advice this would attach, if any
    bash-advise.py --self-test        # fixtures; touches no files
"""

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE = HERE / "bash-whitelist.py"

# How much context is worth spending on one prompt. This text is injected into
# the model's context on every ASK, so it stays a note, not a document.
MAX_SEGMENTS = 3
MAX_ADVICE = 2


def load_gate():
    """The whitelist engine as a module. Its filename has a hyphen, hence this."""
    spec = importlib.util.spec_from_file_location("bash_whitelist", GATE)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load %s" % GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def advice_path(rules_path):
    """`advice.json`, looked for the way the gate looks for its rules.

    Beside the rules file first — that is the installed layout, and it keeps the
    advice with the policy it describes. The fallbacks are for running straight
    out of this repository, where the rules resolve to `profiles/default.json`
    and the shipped table lives in `examples/`.
    """
    candidates = [
        Path(rules_path).parent / "advice.json",
        HERE.parent / "whitelist" / "advice.json",
        HERE / "advice.json",
        HERE.parent / "examples" / "advice.json",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def load_advice(rules_path):
    """The curated rewrite table: [(regex, entry)]. Empty if there is no file."""
    path = advice_path(rules_path)
    if path is None:
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for entry in data.get("advice") or []:
        if not (entry.get("match") and entry.get("instead")):
            continue  # an entry with nowhere to go is not advice
        out.append((re.compile(entry["match"]), entry))
    return out


def offending_segments(command, gate, rules):
    """The segments of `command` that no ALLOW rule matches.

    Mirrors the tail of the gate's own segment loop. Anything the gate stopped on
    earlier — a deny, a recompose — is not our business: those already reach the
    agent with a reason attached.
    """
    out = []
    for raw in gate.split_segments(gate.FD_DUP.sub("", command)):
        segment = raw.strip()
        if not segment:
            continue
        if any(re.fullmatch(source, segment, re.DOTALL) for source in rules.allow_sources):
            continue
        out.append(segment)
    return out[:MAX_SEGMENTS]


def smuggler(command, gate):
    """The reason string of the first smuggler in `command`, or None.

    A smuggler is judged before the per-segment allow check, so a line carrying
    one is ASK'd whatever its segments look like. `MB=$(git merge-base …) && echo`
    is not "the program MB=$(git is not whitelisted"; it is one substitution that
    has to become its own call. Hence a sentence of its own.
    """
    for regex, why in gate.SMUGGLERS:
        if regex.search(gate.FD_DUP.sub("", command)):
            return why
    return None


def compose(command, gate, rules, advice):
    """The advice for one ASK'd command, or None when there is nothing to add."""
    smuggled = smuggler(command, gate)
    if smuggled:
        return ("bash-advise (the whitelist ASK'd this call):\n"
                "- the blocker is %s, not any one program — the gate cannot vet what it "
                "expands to, so it asks.\n"
                "- rewrite as: run the inner command as its own call and use the value in the "
                "next one, or read the file with the Read/Grep tool instead of interpolating it. "
                "One command per call is what the segment check can actually judge."
                % smuggled)

    segments = offending_segments(command, gate, rules)
    if not segments:
        # ASK for a reason that is not "off the whitelist" — unbalanced quoting, or
        # a rules file that would not load. The gate's own reason already describes
        # those, and saying it twice is noise in a context window.
        return None

    matched = []
    for segment in segments:
        for regex, entry in advice:
            if regex.search(segment) and entry not in matched:
                matched.append(entry)
                break

    lines = []
    for entry in matched[:MAX_ADVICE]:
        lines.append("- rewrite as: %s" % entry["instead"])
        if entry.get("why"):
            lines.append("  (%s)" % entry["why"])

    if not matched:
        names = sorted({gate.argv0(s) or s.split()[0] for s in segments})
        lines.append("- no allowed rewrite is known for: %s" % ", ".join(names))
        lines.append("  Do not hunt for a spelling that passes. Either recompose the work into an "
                     "already-allowed shape, or let the prompt stand and tell the human in one "
                     "line what this call does and why it is needed, so the approval is informed.")
        if rules.request_command:
            lines.append("  If this shape will recur, file the rule instead of paying the prompt "
                         "again: `%s --pattern … --why … --tried … --case …`"
                         % rules.request_command)

    return ("bash-advise (the whitelist ASK'd this call; the gate's own reason went to the "
            "human only):\n" + "\n".join(lines))


def advise(command):
    """(verdict, advice-or-None) for one command."""
    gate = load_gate()
    rules_path = gate.find_rules_path(None)
    rules = gate.Rules(gate.load_rules(rules_path))
    decision, _ = gate.verdict(command, rules)
    if decision != "ask":
        return decision, None
    return decision, compose(command, gate, rules, load_advice(rules_path))


def hook():
    """PreToolUse: JSON in, `additionalContext` out. Never a permissionDecision."""
    try:
        data = json.load(sys.stdin)
    except Exception:  # noqa: BLE001 — never break the session on malformed input
        return 0
    if data.get("tool_name") != "Bash":
        return 0
    command = (data.get("tool_input") or {}).get("command", "")
    if not command.strip():
        return 0

    try:
        _, text = advise(command)
    except Exception:  # noqa: BLE001 — a broken advisor must cost nothing but its advice
        return 0
    if not text:
        return 0

    json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                      "additionalContext": text}}, sys.stdout)
    return 0


def self_test():
    """The gate imports, the table compiles, and each kind of ASK routes right.

    The shapes below are checked only if the loaded policy actually ASKs them —
    a project that has since written the rule should not fail someone else's
    fixture. What is asserted unconditionally is the routing: an allowed command
    gets no advice, a smuggler gets the smuggler sentence, and a shape the gate
    already explained to the agent is never explained twice.
    """
    try:
        gate = load_gate()
        rules_path = gate.find_rules_path(None)
        rules = gate.Rules(gate.load_rules(rules_path))
        advice = load_advice(rules_path)
    except Exception as exc:  # noqa: BLE001
        print("FAIL cannot load the gate or its rules: %r" % (exc,))
        return 1

    checks = [
        ("the gate's ALLOW rules loaded", bool(rules.allow_sources), True),
        ("the advice table compiled and is non-empty", bool(advice), True),
        ("an allowed command gets no advice", advise("git status")[1] is None, True),
    ]

    for command in ("git checkout some-branch", "gh pr list", "ps -o pid,command -p 1"):
        decision, text = advise(command)
        if decision != "ask":
            continue  # this policy already allows or denies it; not this hook's case
        checks.append(("`%s` gets advice" % command, text is not None, True))
        checks.append(("`%s` names a rewrite or says there is none" % command,
                       bool(text) and ("rewrite as:" in text or "no allowed rewrite" in text),
                       True))

    decision, text = advise("MB=$(git merge-base HEAD main) && echo done")
    checks.append(("a substitution is explained as a smuggler, not as a program",
                   decision == "ask" and bool(text) and "expands to" in text, True))

    for command in ("rm -rf /tmp/x", "for f in a b; do echo $f; done"):
        checks.append(("`%s` is not explained twice" % command,
                       advise(command)[1] is None, True))

    failed = 0
    for name, got, want in checks:
        ok = got == want
        failed += 0 if ok else 1
        print(("ok   " if ok else "FAIL ") + name
              + ("" if ok else "  got %r want %r" % (got, want)))
    print("\n%d/%d passed  (%d advice entries, rules: %s)"
          % (len(checks) - failed, len(checks), len(advice), Path(rules_path).name))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(add_help=True, description=(__doc__ or "").split("\n")[0])
    ap.add_argument("--explain", metavar="CMD", help="the advice this would attach to one command")
    ap.add_argument("--self-test", action="store_true", help="fixtures; touches no files")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if args.explain:
        try:
            decision, text = advise(args.explain)
        except Exception as exc:  # noqa: BLE001
            print("silent in a session; here it raised: %r" % (exc,), file=sys.stderr)
            return 2
        print("%s  %s" % (decision.upper(), args.explain))
        print(text if text
              else "       (no advice — the gate's own reason already reaches the agent)")
        return 0
    return hook()


if __name__ == "__main__":
    sys.exit(main())
