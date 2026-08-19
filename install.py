#!/usr/bin/env python3
"""Install the bash whitelist into a project's .claude/ directory.

    python3 install.py /path/to/project          # copy, wire, verify
    python3 install.py /path/to/project --force   # overwrite files already there
    python3 install.py /path/to/project --dry-run # say what it would do

It copies both hooks, the profiles, the request script and the skill; writes a
starter rules.json if the project has none; merges the hook wiring and the
write-protection deny list into .claude/settings.json (keeping a .bak); and
finishes by running both sets of fixtures inside the target, because an
installed gate nobody verified is a claim, not a guardrail.

Nothing here deletes: an existing file is skipped and named unless --force, and
settings.json is rewritten only after its previous content is copied to
settings.json.bak.
"""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

COPIES = [
    ("hooks/bash-whitelist.py", ".claude/hooks/bash-whitelist.py"),
    ("hooks/py-inline-guard.py", ".claude/hooks/py-inline-guard.py"),
    ("hooks/permission-audit.py", ".claude/hooks/permission-audit.py"),
    ("scripts/whitelist-request.py", ".claude/scripts/whitelist-request.py"),
    ("skills/bash-discipline/SKILL.md", ".claude/skills/bash-discipline/SKILL.md"),
]

PROFILES_TO = ".claude/whitelist/profiles"
RULES_TO = ".claude/whitelist/rules.json"

# Everything an agent must not be able to edit. A gate whose own file is
# writable is a suggestion: six deleted lines and the leash is gone.
PROTECT = [
    "./.claude/settings.json",
    "./.claude/hooks/bash-whitelist.py",
    "./.claude/hooks/py-inline-guard.py",
    "./.claude/hooks/permission-audit.py",
    "./.claude/scripts/whitelist-request.py",
    "./.claude/whitelist/rules.json",
    "./.claude/whitelist/profiles/base.json",
    "./.claude/whitelist/profiles/git.json",
    "./.claude/whitelist/profiles/git-branch-policy.json",
    "./.claude/whitelist/profiles/node.json",
    "./.claude/whitelist/profiles/python.json",
    "./.claude/whitelist/profiles/default.json",
]

# (event, matcher, command, statusMessage). A list and not a dict keyed by event:
# PreToolUse carries two entries, and the second one is the reason the first can
# be trusted about inline python at all.
HOOK_WIRING = [
    ("PreToolUse", "Bash", "python3 \"$CLAUDE_PROJECT_DIR/.claude/hooks/bash-whitelist.py\"",
     "Checking the command"),
    ("PreToolUse", "Bash", "python3 \"$CLAUDE_PROJECT_DIR/.claude/hooks/py-inline-guard.py\"",
     "Reading the inline python"),
    ("PermissionRequest", None,
     "python3 \"$CLAUDE_PROJECT_DIR/.claude/hooks/permission-audit.py\" 2>/dev/null || true", None),
]

GITIGNORE = [".claude/logs/", ".claude/whitelist/requests.jsonl"]


def copy(src, dst, force, dry, done, skipped):
    if dst.exists() and not force:
        skipped.append(str(dst))
        return
    if dry:
        done.append("would copy %s" % dst)
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    done.append(str(dst))


def wire_settings(root, dry, done):
    """Add the two hooks and the deny list to .claude/settings.json, idempotently."""
    path = root / ".claude" / "settings.json"
    settings = {}
    if path.is_file():
        try:
            settings = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print("refused: %s is not valid JSON (%s) — fix it and re-run" % (path, exc),
                  file=sys.stderr)
            return False

    hooks = settings.setdefault("hooks", {})
    for event, matcher, command, status in HOOK_WIRING:
        groups = hooks.setdefault(event, [])
        already = any(command.split("/")[-1].split('"')[0] in h.get("command", "")
                      for group in groups for h in group.get("hooks", []))
        if already:
            continue
        entry = {"type": "command", "command": command}
        if status:
            entry["statusMessage"] = status
        group = {"hooks": [entry]}
        if matcher:
            group["matcher"] = matcher
        groups.append(group)
        done.append("wired %s" % event)

    deny = settings.setdefault("permissions", {}).setdefault("deny", [])
    for target in PROTECT:
        for verb in ("Edit", "Write"):
            rule = "%s(%s)" % (verb, target)
            if rule not in deny:
                deny.append(rule)

    if dry:
        done.append("would write %s" % path)
        return True

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        shutil.copy2(path, path.with_suffix(".json.bak"))
        done.append("kept the previous settings at %s" % path.with_suffix(".json.bak"))
    path.write_text(json.dumps(settings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    done.append(str(path))
    return True


def wire_gitignore(root, dry, done):
    path = root / ".gitignore"
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    missing = [line for line in GITIGNORE if line not in existing]
    if not missing:
        return
    if dry:
        done.append("would add %d line(s) to .gitignore" % len(missing))
        return
    with path.open("a", encoding="utf-8") as fh:
        if existing and not existing.endswith("\n"):
            fh.write("\n")
        fh.write("\n# bash whitelist — per machine, never committed\n")
        fh.write("\n".join(missing) + "\n")
    done.append("%s (+%d)" % (path, len(missing)))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("target", help="the project to install into")
    ap.add_argument("--force", action="store_true", help="overwrite files already there")
    ap.add_argument("--dry-run", action="store_true", help="say what it would do, change nothing")
    args = ap.parse_args()

    root = Path(args.target).expanduser().resolve()
    if not root.is_dir():
        print("refused: %s is not a directory" % root, file=sys.stderr)
        return 2

    done, skipped = [], []
    for src, dst in COPIES:
        copy(HERE / src, root / dst, args.force, args.dry_run, done, skipped)
    for profile in sorted((HERE / "profiles").glob("*.json")):
        copy(profile, root / PROFILES_TO / profile.name, args.force, args.dry_run, done, skipped)
    copy(HERE / "examples" / "rules.json", root / RULES_TO, args.force, args.dry_run,
         done, skipped)

    if not wire_settings(root, args.dry_run, done):
        return 2
    wire_gitignore(root, args.dry_run, done)

    for line in done:
        print("  " + line)
    for line in skipped:
        print("  kept (already there, use --force to replace): " + line)

    if args.dry_run:
        print("\ndry run — nothing was changed")
        return 0

    print("\nverifying the installed gate:")
    result = subprocess.run(
        [sys.executable, str(root / ".claude/hooks/bash-whitelist.py"),
         "--rules", str(root / RULES_TO), "--self-test"],
        capture_output=True, text=True)
    print(result.stdout.strip() or result.stderr.strip())

    guard = subprocess.run(
        [sys.executable, str(root / ".claude/hooks/py-inline-guard.py"), "--self-test"],
        capture_output=True, text=True)
    print(guard.stdout.strip() or guard.stderr.strip())
    if guard.returncode != 0:
        result = guard

    print("\nNext, by hand — the parts nobody else can do for you:")
    print("  1. .claude/whitelist/rules.json: replace the example `allow` entries with")
    print("     this project's verify gate and its reviewed scripts. Add a case per rule.")
    print("  2. Say in CLAUDE.md that the gate exists and that `bash-discipline` is the")
    print("     skill for composing a command. An agent that does not know it is there")
    print("     learns the rules by hitting them, which is the failure mode this replaces.")
    print("  3. Re-run --self-test after every edit. A red case is a rule that does not")
    print("     mean what its author thought.")
    return 0 if result.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
