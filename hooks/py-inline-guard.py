#!/usr/bin/env python3
"""A second PreToolUse(Bash) gate: it reads the Python that `python3 -c` runs.

bash-whitelist.py judges the shape of a command line. It cannot judge the
program inside `-c '…'`, because that program is one quoted argument to the
shell and a regex over it is a spelling test: `os.system` is caught, and
`getattr(os, "sy" + "stem")` is not.

So this hook parses the body with `ast` and judges it by an ALLOW-list — the
imports, calls and attributes a JSON-reading snippet needs, and nothing else.
An allow-list is the whole point: a denylist of bad words loses to string
concatenation, and losing quietly is worse than refusing loudly.

    python3 .claude/hooks/py-inline-guard.py --self-test
    python3 .claude/hooks/py-inline-guard.py --explain "python3 -c 'import json'"

It has an opinion on two shapes: a `python` / `python3` segment carrying `-c`,
and one carrying a script path under a temp directory — a throwaway parser
written minutes ago is the same unreviewed body, only longer. On anything else it
prints nothing and exits 0, which leaves the decision to bash-whitelist.py and
the harness. Both hooks run; the strictest wins.
"""

import argparse
import ast
import json
import os
import re
import shlex
import shutil
import sys
import tempfile

# Modules a snippet may import. Everything reachable from `os` is absent on
# purpose: `import os.path` binds `os`, and `os` carries system, popen, remove,
# rename and execv. Path work is pathlib's job here.
ALLOWED_MODULES = {
    "json", "sys", "re", "pathlib", "collections", "collections.abc",
    "itertools", "functools", "operator", "math", "statistics", "decimal",
    "datetime", "textwrap", "string", "csv", "difflib", "unicodedata",
    "posixpath", "base64", "hashlib", "uuid", "enum", "dataclasses", "typing",
}

# Builtins that turn data into code, or reach the interpreter's own tables.
FORBIDDEN_NAMES = {
    "eval", "exec", "compile", "__import__", "getattr", "setattr", "delattr",
    "globals", "locals", "vars", "input", "breakpoint", "memoryview",
    "help", "copyright", "credits", "license", "quit", "exit",
}

# Attribute names that act on the world instead of on the data. A snippet that
# needs one of these is not a JSON probe and belongs in a reviewed script.
#
# Bare `remove` is deliberately absent: `list.remove(x)` is ordinary data work,
# and the deletion it could hide — `os.remove` — is unreachable anyway, because
# `os` cannot be imported at all. Deletion through pathlib (`unlink`, `rmdir`)
# is reachable, so those two stay.
FORBIDDEN_ATTRS = {
    "system", "popen", "spawn", "spawnl", "spawnv", "spawnve", "fork", "forkpty",
    "execv", "execve", "execl", "execlp", "execvp", "kill", "killpg", "abort",
    "unlink", "rmdir", "removedirs", "rmtree", "rename", "renames",
    "replace_file", "truncate", "chmod", "chown", "chdir", "mkdir", "makedirs",
    "symlink", "link", "mkfifo", "mknod", "setuid", "setgid", "putenv",
    "unsetenv", "urlopen", "urlretrieve", "connect", "connect_ex", "sendall",
    "socket", "create_connection", "check_output", "check_call", "run_shell",
    "Popen", "call", "getoutput", "getstatusoutput", "load_module",
    "loadTestsFromName", "register", "dup2", "write_text", "write_bytes",
    "touch", "mkstemp", "mkdtemp",
}

# `open(p, "w")` is a write; so is "a", "x", "+". Only a literal read mode passes,
# because a mode held in a variable is a mode nobody can read here.
READ_MODES = re.compile(r"^r[bt]?$")

DOTENV = re.compile(r"(^|/)\.env(\.|$)")

# A script under a temp directory is a body written minutes ago for one question
# — the same thing as a `-c` snippet, only longer, so it gets the same reading.
# A script under .claude/scripts is NOT vetted here: it was reviewed, it is named
# by exact path in rules.json, and some of them legitimately shell out.
VET_PREFIXES = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/")

WRITE_RECEIVERS = {"stdout", "stderr"}   # sys.stdout.write is not a file write


class Refusal(Exception):
    """One reason the body cannot be allowed, in the words the agent needs."""


def read_script(path):
    """The text of a temp script, or None when there is nothing to vet."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError:
        return None          # python3 will say so itself; no verdict to add
    except (OSError, UnicodeDecodeError) as exc:
        raise Refusal("%s cannot be read as text (%s), so its body cannot be vetted"
                      % (path, exc))


def inline_programs(command):
    """Every Python body a command line would run, in order.

    Two shapes: a `-c` snippet, and a script under a temp directory. Both are
    code written for one question and reviewed by nobody, so both are read.
    """
    found = []
    try:
        tokens = shlex.split(command)
    except ValueError:
        # Unbalanced quoting: the shell would not run this either, and a blind
        # split here could hand back half a program and vet it as whole.
        raise Refusal("the command has unbalanced quoting, so the inline program "
                      "cannot be read in full — rewrite it, or put it in a file")
    for index, token in enumerate(tokens):
        name = token.rsplit("/", 1)[-1]
        if not re.fullmatch(r"python3?(\.\d+)?", name):
            continue
        for offset in range(index + 1, len(tokens)):
            argument = tokens[offset]
            if argument == "-c" and offset + 1 < len(tokens):
                found.append(tokens[offset + 1])
                break
            if argument.startswith("-c") and len(argument) > 2:
                found.append(argument[2:])
                break
            if not argument.startswith("-"):
                if argument.startswith(VET_PREFIXES) and argument.endswith(".py"):
                    body = read_script(argument)
                    if body is not None:
                        found.append(body)
                break        # a script path: vetted above if temp, else left alone
    return found


def check_call(node):
    if isinstance(node.func, ast.Name) and node.func.id == "open":
        mode = None
        if len(node.args) > 1:
            mode = node.args[1]
        for keyword in node.keywords:
            if keyword.arg == "mode":
                mode = keyword.value
        if mode is None:
            return
        if not (isinstance(mode, ast.Constant) and isinstance(mode.value, str)):
            raise Refusal("open() has a mode this hook cannot read — pass a literal "
                          "'r' or drop the argument; writing files is the Write tool's job")
        if not READ_MODES.match(mode.value):
            raise Refusal("open(..., %r) writes a file — use the Write tool, which "
                          "shows the diff" % mode.value)


def check_attribute(node):
    name = node.attr
    if name.startswith("__") and name.endswith("__"):
        raise Refusal("attribute %r reaches the interpreter's own tables — that is a way "
                      "out of any allow-list, so it is refused whatever it is used for"
                      % name)
    if name in ("write", "writelines"):
        target = node.value
        ok = (isinstance(target, ast.Attribute) and target.attr in WRITE_RECEIVERS) or \
             (isinstance(target, ast.Name) and target.id in WRITE_RECEIVERS)
        if not ok:
            raise Refusal("%r writes somewhere this hook cannot identify — print() for "
                          "output, the Write tool for a file" % name)
        return
    if name in FORBIDDEN_ATTRS:
        raise Refusal("%r acts on the machine, not on the data — a snippet that needs it "
                      "has earned a reviewed script under .claude/scripts" % name)


def check_import(node):
    modules = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
               else [node.module or ""])
    for module in modules:
        root = module.split(".")[0]
        if module not in ALLOWED_MODULES and root not in ALLOWED_MODULES:
            raise Refusal("import %r is not on the inline allow-list (%s) — for anything "
                          "else, write a script under .claude/scripts and run it by path"
                          % (module, ", ".join(sorted(ALLOWED_MODULES)[:8]) + ", …"))
        if isinstance(node, ast.ImportFrom) and root == "os":
            raise Refusal("anything from `os` is refused: it carries system, popen, remove "
                          "and rename — use pathlib for paths")


def check_program(source):
    """Refuse a body that does more than read data. Raises Refusal, or returns."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise Refusal("the inline program does not parse (%s) — a body that cannot be "
                      "parsed cannot be vetted" % exc.msg)

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            check_import(node)
        elif isinstance(node, ast.Attribute):
            check_attribute(node)
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            raise Refusal("%r turns data into code or exposes the interpreter's tables"
                          % node.id)
        elif isinstance(node, ast.Call):
            check_call(node)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and DOTENV.search(node.value):
            raise Refusal("the program names %r — do not read .env, whatever the tool is"
                          % node.value)
        elif isinstance(node, (ast.AsyncFunctionDef, ast.Await)):
            raise Refusal("async code in a one-liner is doing something a one-liner "
                          "should not — put it in a script")


def judge(command):
    """(decision, reason) for one command line, or (None, None) for no opinion."""
    try:
        programs = inline_programs(command)
    except Refusal as exc:
        return "deny", "refused by the inline python guard — %s" % exc
    if not programs:
        return None, None
    for source in programs:
        try:
            check_program(source)
        except Refusal as exc:
            return "deny", "refused by the inline python guard — %s" % exc
    return None, None      # clean: leave the verdict to bash-whitelist.py


CASES = [
    # The JSON probes this exists to keep working.
    ("python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d))'", None),
    ("python3 -c \"import json; print(json.load(open('build/report.json'))['total'])\"", None),
    ("python3 -c 'import json; print(json.dumps(json.load(open(\"x.json\")), indent=2))'", None),
    ("python3 -c 'import pathlib,json; print(json.loads(pathlib.Path(\"a.json\").read_text()))'",
     None),
    ("python3 -c 'import re,sys; print([l for l in sys.stdin if re.search(\"FAIL\", l)])'", None),
    ("python3 -c 'print(1)'", None),
    ("python3 -B -c 'import json; print(1)'", None),
    ("python3 -c 'import collections; print(collections.Counter(\"abc\"))'", None),
    ("cat x.json | python3 -c 'import json,sys; print(json.load(sys.stdin))'", None),

    # Not an inline program at all: no opinion, the whitelist decides.
    ("ls -la", None),
    ("./gradlew test", None),
    ("python3 .claude/scripts/parse_owners.py --diff", None),
    ("node -e 'console.log(1)'", None),

    # Execution and shelling out.
    ("python3 -c \"import os; os.system('id')\"", "deny"),
    ("python3 -c 'import os; os.popen(\"id\").read()'", "deny"),
    ("python3 -c 'import subprocess; subprocess.run([\"id\"])'", "deny"),
    ("python3 -c 'import subprocess as s; s.check_output(\"id\")'", "deny"),
    ("python3 -c 'eval(\"1+1\")'", "deny"),
    ("python3 -c 'exec(open(\"x.py\").read())'", "deny"),
    ("python3 -c 'compile(\"1\", \"x\", \"eval\")'", "deny"),
    ("python3 -c '__import__(\"os\").system(\"id\")'", "deny"),

    # The obfuscation a regex denylist loses to.
    ("python3 -c 'import os; getattr(os, \"sy\" + \"stem\")(\"id\")'", "deny"),
    ("python3 -c 'print(().__class__.__bases__)'", "deny"),
    ("python3 -c 'print([].__class__.__mro__[1].__subclasses__())'", "deny"),

    # Deletion and mutation, however it is spelled.
    ("python3 -c 'import os; os.remove(\"a.txt\")'", "deny"),
    ("python3 -c 'import os; os.unlink(\"a.txt\")'", "deny"),
    ("python3 -c 'd=[1,2]; d.remove(1); print(d)'", None),
    ("python3 -c 'import json; d=json.load(open(\"x.json\"))[\"a\"]; d.remove(1); print(d)'", None),
    ("python3 -c 'import pathlib; pathlib.Path(\"a.txt\").unlink()'", "deny"),
    ("python3 -c 'import pathlib; pathlib.Path(\"d\").rmdir()'", "deny"),
    ("python3 -c 'import shutil; shutil.rmtree(\"build\")'", "deny"),
    ("python3 -c 'import os; os.rename(\"a\", \"b\")'", "deny"),
    ("python3 -c 'import pathlib; pathlib.Path(\"a\").write_text(\"x\")'", "deny"),
    ("python3 -c 'open(\"a.txt\", \"w\").write(\"x\")'", "deny"),
    ("python3 -c 'open(\"a.txt\", \"a\")'", "deny"),
    ("python3 -c 'f = open(\"a.txt\", mode=\"w\")'", "deny"),
    ("python3 -c 'm = \"w\"; open(\"a.txt\", m)'", "deny"),
    ("python3 -c 'import json; json.dump({}, open(\"x.json\", \"w\"))'", "deny"),

    # Reading a file is fine; reading THAT file is not.
    ("python3 -c 'print(open(\"README.md\").read())'", None),
    ("python3 -c 'print(open(\"README.md\", \"r\").read())'", None),
    ("python3 -c 'print(open(\".env\").read())'", "deny"),
    ("python3 -c 'import pathlib; print(pathlib.Path(\"app/.env.local\").read_text())'", "deny"),

    # Network.
    ("python3 -c 'import urllib.request; urllib.request.urlopen(\"http://x\")'", "deny"),
    ("python3 -c 'import socket; socket.socket()'", "deny"),
    ("python3 -c 'import requests; requests.get(\"http://x\")'", "deny"),

    # Output goes to stdout, not into a file by the back door.
    ("python3 -c 'import sys; sys.stdout.write(\"hi\")'", None),
    ("python3 -c 'import sys; sys.stderr.writelines([\"a\"])'", None),

    # A body nobody can read is not a body anybody can allow.
    ("python3 -c \"import json; print(", "deny"),
    ("python3 -c 'def f(:'", "deny"),

    # The second inline program in the same line is judged too.
    ("python3 -c 'print(1)' && python3 -c 'import os; os.system(\"id\")'", "deny"),

    # A reviewed script keeps its own rules; a missing temp file gets no verdict.
    ("python3 /tmp/does-not-exist-9d1f.py", None),
    ("python3 .claude/scripts/parse_owners.py --diff", None),
]

# Temp-script fixtures: the body is what matters, the path only decides whether
# the body is read at all. Written under /tmp by --self-test, then removed.
SCRIPT_FIXTURES = [
    ("import json, pathlib\n"
     "data = json.loads(pathlib.Path('build/report.json').read_text())\n"
     "print(data['total'])\n", None),
    ("import re\n"
     "for line in open('/tmp/build.log'):\n"
     "    if re.search('FAILED', line):\n"
     "        print(line.rstrip())\n", None),
    ("import subprocess\n"
     "subprocess.run(['./gradlew', 'clean'])\n", "deny"),
    ("import shutil\n"
     "shutil.rmtree('build')\n", "deny"),
    ("import pathlib\n"
     "pathlib.Path('app/build.gradle').write_text('x')\n", "deny"),
]


def self_test(verbose=False):
    failed = total = 0

    def check(label, want, got, reason):
        nonlocal failed, total
        total += 1
        ok = got == want
        failed += 0 if ok else 1
        if verbose or not ok:
            print("%s %-4s (want %-4s)  %s%s"
                  % ("ok  " if ok else "FAIL", got or "pass", want or "pass", label,
                     "" if ok else "\n     %s" % (reason or "no opinion")))

    for command, want in CASES:
        got, reason = judge(command)
        check(command, want, got, reason)

    directory = tempfile.mkdtemp(prefix="py-inline-guard-", dir="/tmp")
    try:
        for index, (body, want) in enumerate(SCRIPT_FIXTURES):
            path = os.path.join(directory, "fixture%d.py" % index)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(body)
            command = "python3 %s" % path
            got, reason = judge(command)
            check("%s  <<%s…>>" % (command, body.split("\n")[0]), want, got, reason)
    finally:
        shutil.rmtree(directory, ignore_errors=True)

    print("\n%d/%d passed" % (total - failed, total))
    return 1 if failed else 0


def hook():
    try:
        data = json.load(sys.stdin)
    except Exception:  # noqa: BLE001 — never break the session on malformed input
        return 0
    if data.get("tool_name") != "Bash":
        return 0
    decision, reason = judge((data.get("tool_input") or {}).get("command", ""))
    if decision is None:
        return 0
    json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                      "permissionDecision": decision,
                                      "permissionDecisionReason": reason}}, sys.stdout)
    return 0


def main():
    ap = argparse.ArgumentParser(add_help=True, description=__doc__.split("\n")[0])
    ap.add_argument("--explain", metavar="CMD", help="print this hook's opinion on one command")
    ap.add_argument("--self-test", action="store_true",
                    help="run the fixtures; writes and removes a temp dir under /tmp")
    ap.add_argument("-v", "--verbose", action="store_true", help="print passing checks too")
    args = ap.parse_args()

    if args.explain:
        decision, reason = judge(args.explain)
        print("%s  %s" % ((decision or "no opinion").upper(), args.explain))
        print("       %s" % (reason or "nothing inline to vet — bash-whitelist.py decides"))
        return 0
    if args.self_test:
        return self_test(args.verbose)
    return hook()


if __name__ == "__main__":
    sys.exit(main())
