#!/usr/bin/env python3
"""PermissionRequest — append-only audit of everything that needed a human.

Never decides anything: PreToolUse (bash-whitelist.py) is the gate. This only
records what fell through to a prompt, so the whitelist can be curated from
evidence instead of guesswork — if the same command keeps appearing here, it is
a candidate for the ALLOW list (or for a DENY, if it keeps being refused).

    <project>/.claude/logs/permission-requests.jsonl   (gitignore it: per machine)

That log is the reason the rules in `profiles/` look the way they do. The
`cd <project root> && …` allow rule exists because 181 of one week's 828 prompts
were that prefix; the recompose rules for heredocs and for-loops exist because
48 and 35 of them were those. None were dangerous. All of them cost a person an
interruption, and a person who approves fifty harmless prompts stops reading the
fifty-first.

Read it back with:

    python3 .claude/hooks/permission-audit.py --report
    python3 .claude/hooks/permission-audit.py --report --top 40 --since 7

Set BASH_WHITELIST_LOG to put the log somewhere else.
"""

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_DETAIL = 400


def log_path():
    override = os.environ.get("BASH_WHITELIST_LOG")
    if override:
        return Path(override).expanduser()
    project = os.environ.get("CLAUDE_PROJECT_DIR")
    root = Path(project) if project else Path(__file__).resolve().parent.parent.parent
    return root / ".claude" / "logs" / "permission-requests.jsonl"


def detail_of(tool_input):
    if not isinstance(tool_input, dict):
        return ""
    for key in ("command", "file_path", "url", "pattern", "path", "query"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value[:MAX_DETAIL]
    return ""


def record():
    try:
        data = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        return 0

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "session": str(data.get("session_id") or "unknown"),
        "tool": str(data.get("tool_name") or "unknown"),
        "detail": detail_of(data.get("tool_input") or {}),
    }
    try:
        path = log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 — auditing must never break a session
        pass
    return 0


def shape(command):
    """The first two words of a command — enough to group prompts by habit."""
    words = command.split()
    while words and "=" in words[0] and not words[0].startswith("-"):
        words = words[1:]                       # skip a VAR=value prefix
    return " ".join(words[:2]) if words else "(empty)"


def report(top, since_days):
    path = log_path()
    if not path.is_file():
        print("no log yet at %s — nothing has been prompted for, or the hook is not wired"
              % path)
        return 0

    cutoff = None
    if since_days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)

    tools, shapes, unreadable, total = Counter(), Counter(), 0, 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
            when = datetime.fromisoformat(row["ts"])
        except Exception:  # noqa: BLE001
            unreadable += 1      # a line we cannot read is its own number, never
            continue             # folded into the counts it would distort
        if cutoff and when < cutoff:
            continue
        total += 1
        tools[row.get("tool", "unknown")] += 1
        if row.get("tool") == "Bash":
            shapes[shape(row.get("detail", ""))] += 1

    window = ("last %d days" % since_days) if since_days else "all time"
    print("%d prompts (%s) — %s" % (total, window, path))
    if unreadable:
        print("%d log lines could not be read and are counted in nothing else" % unreadable)

    print("\nby tool")
    for tool, count in tools.most_common():
        print("  %5d  %s" % (count, tool))

    if shapes:
        print("\nthe Bash shapes that keep asking (top %d)" % top)
        for name, count in shapes.most_common(top):
            print("  %5d  %s" % (count, name))
        print("\nEach line is a rule you have not written yet. A prompt approves one")
        print("invocation and teaches the system nothing; a rule approves the shape")
        print("forever. Widen deliberately — never to silence a prompt.")
    return 0


def main():
    if not sys.argv[1:]:
        return record()
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--report", action="store_true", help="read the log back, ranked")
    ap.add_argument("--top", type=int, default=20, help="how many Bash shapes to print")
    ap.add_argument("--since", type=int, metavar="DAYS", help="only the last N days")
    args = ap.parse_args()
    if args.report:
        return report(args.top, args.since)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
