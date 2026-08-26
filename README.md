# bash-whitelist

A `PreToolUse(Bash)` gate for Claude Code: it decides every shell command an
agent writes, before it runs.

```
deny      git push --force origin main
          blocked by the project bash whitelist: force-push rewrites shared history

deny      for f in a b; do grep -n x $f; done
          refused — a shell loop splits into `do …` segments that no rule can match.
          Recompose: one `grep -rn` over the list of paths, or the Grep tool.

allow     npx tsc --noEmit && npm run lint && npm run build

ask       gh pr list
          not on the project bash whitelist: gh — no rule allows it at all
          bash-advise: no allowed rewrite is known for `gh`. Do not hunt for a
          spelling that passes — say in one line what this call is for so the
          approval is informed, and file the rule if the shape will recur.
```

No dependencies, one Python file, rules in JSON.

## Why it is shaped this way

A whitelist is easy. The hard parts are the three things this one learned by
being wrong:

**A refusal must reach the party who can act on it.** A `deny` reason is
returned to the *agent*; an `ask` reason is shown only to the *human*. The
version this grew from spent four days computing a precise diagnosis — "not on
the whitelist: `for`" — and handing it to the only party who could not rewrite
the command. 828 prompts in five days; 48 were inline heredocs, 35 were shell
loops, 181 were `cd <the directory we are already in> && …`. None were
dangerous. All of them interrupted a person, and a person who approves fifty
harmless prompts stops reading the fifty-first. So a shape that has an allowed
equivalent is denied **with that equivalent**, and the agent recomposes. What is
left — the shapes that genuinely have to reach a human — is what the third hook
is for; see [The third hook](#the-third-hook-explaining-the-ask).

**Searching for a dangerous word is not running it.** `grep -n "rm|sudo" file`
was refused as privilege escalation. The gate now blanks the quoted arguments of
tools that cannot start a process — and only then, and only when *every* segment
of the chain is such a tool, and never a double-quoted run containing `$(` or a
backtick, and never a quoted `.env` path. That exemption is the part most worth
distrusting; most of the fixtures are about it.

**Deletion never gets an equivalent.** `rg -l foo | xargs rm` deleted three
files. `rmSync(process.cwd() + "/e2e", {recursive: true})` deleted a directory.
Both read as an ordinary search and an ordinary probe. Their rules carry those
dates. And nothing that deletes is ever answered with "write it this way
instead" — a way around a stop is not a stop. Deletion stays a prompt, and the
prompt owes the human what, why now, what breaks, and the way back.

## Install

```sh
python3 install.py /path/to/project --dry-run
python3 install.py /path/to/project
```

Or hand the whole job to an agent — that is what `AGENTS.md` is for:

> Read `/path/to/bash-whitelist/AGENTS.md` and install it into this project.

It copies the hook, the profiles, the request script and the `bash-discipline`
skill; wires both hooks into `.claude/settings.json`; adds the write-protection
deny list; and runs the fixtures. It overwrites nothing without `--force`.

## The layout it installs

```
.claude/
  hooks/bash-whitelist.py          the engine — no rules inside it
  hooks/py-inline-guard.py         reads the Python that `python3 -c` runs
  hooks/bash-advise.py             turns an `ask` into advice the AGENT can act on
  hooks/permission-audit.py        logs what still needed a human; --report reads it back
  scripts/whitelist-request.py     how an agent asks for a rule instead of a keypress
  whitelist/rules.json             THIS project's policy — the file you edit
  whitelist/advice.json            what to tell the agent when the answer is `ask`
  whitelist/profiles/*.json        base · git · git-branch-policy · node · python
  skills/bash-discipline/SKILL.md  how an agent composes a command that passes
```

## The second hook: reading the body, not the line

`base` refuses `python3 -c` outright, and for a repo with no Python that is the
right answer. For a repo where an agent reads a build report, a settings file or
a log, it is the rule that gets worked around — so `py-inline-guard.py` exists to
make allowing `-c` defensible instead of optional.

It parses the body with `ast` and judges it by an ALLOW-list: the imports a
data-reading snippet needs, `open()` in a read mode only, no dunder attribute, no
`eval`/`getattr`, nothing that deletes or opens a socket. `os`, `subprocess` and
`shutil` are simply absent, which is why `getattr(os, "sy" + "stem")` loses here
and wins against any denylist of words. A script under a temp directory gets the
same reading: a throwaway parser written minutes ago is the same unreviewed body,
only longer.

To use it, fork `base.inline-interpreter` in your `rules.json` rather than
dropping it — keep the refusal for `node`/`ruby`/`perl`, allow `python3 -c`, and
let the guard judge what is inside:

```json
{
  "disable": ["base.inline-interpreter"],
  "recompose": [
    {"id": "project.inline-interpreter",
     "pattern": "(^|[;&|])\\s*(\\w+=\\S+\\s+)*(node|ruby|perl)\\s+(-\\S+\\s+)*-{1,2}(c|e|eval)\\b",
     "why": "inline interpreter code is arbitrary code with a quiet spelling",
     "instead": "use the Read/Write/Edit tools"}
  ],
  "allow": [
    {"id": "project.python-inline",
     "pattern": "python3?(\\s+-[A-Za-z]+)*\\s+-c\\s+(?:'[^']*'|\"[^\"`$]*\")(\\s+{{arg}})*\\s*"}
  ]
}
```

Leave `base.program-on-stdin` on. `… | python3 -` takes its program from stdin,
where no `PreToolUse` hook can read it, so there is nothing for the guard to
judge — the one shape it cannot cover is the one shape that must stay refused.

What it does not do: it constrains writing and executing, not reading.
`print(open("x").read())` is allowed for any readable file except `.env`.

## The third hook: explaining the `ask`

The first section of this README says a refusal must reach the party who can act
on it, and then names `ask` as the verdict that does not. That was left as a
known hole for a while, on the theory that `ask` is rare. It is not: in the repo
this was last curated in, `--report` counted 211 Bash prompts, 34 of them `git`
and 26 of them `gh`, the same shapes over and over. The human approved each one
and the agent learned nothing from any of them, because
`permissionDecisionReason` is the text on the approval dialog and there is no
spelling of it that reaches the model.

`bash-advise.py` is a second `PreToolUse(Bash)` hook that returns
`additionalContext` instead — the harness's channel for non-error feedback to
the model. It re-runs *this* gate's `verdict()` (imported, so the two cannot
disagree) and speaks only when the answer is `ask`:

```
ask       git checkout release-2
          not on the project bash whitelist: git — the rules that mention it: …
          bash-advise: rewrite as `git switch BRANCH`
          (plain `git checkout X` is off the list because `git checkout src/File.ts`
           has the same spelling and throws that file's edits away)

ask       MB=$(git merge-base HEAD main) && echo $MB
          bash-advise: the blocker is command substitution $( ), not any one
          program — run the inner command as its own call and use the value in
          the next one.
```

It returns **no** `permissionDecision`, ever. It cannot allow, deny or rewrite a
call; the gate still decides and the human still approves. Two consequences worth
keeping:

- **The advice table is data, and it is not write-protected.** `advice.json` lives
  beside `rules.json` and holds `{match, instead, why}`. It changes no verdict, so
  an agent that edits it has misled itself and nothing else — which is why it is
  the one file here an agent may curate. `rules.json` is still off limits.
- **An entry that invents a spelling is worse than no entry.** `instead` must name
  a form genuinely on this project's whitelist, or say plainly that none exists.
  The third kind of advice — "no allowed rewrite is known for `gh`" — is the one
  that stops an agent trying six variants of a command that will never pass, and
  it is the reason the table does not need to be complete to be useful.

Curate it from the same evidence as the rules: every shape on
`--report` either earns a rule or earns an entry here.

## Writing the rules

`rules.json` is small on purpose:

```json
{
  "extends": ["base", "git", "node"],
  "vars": { "protected_branches": ["main"], "work_branch": "feature/\\S+" },
  "allow": [
    {"id": "project.gate", "pattern": "npm\\s+run\\s+(lint|test|build)\\b.*"}
  ],
  "cases": [
    ["npm run build", "allow"],
    ["npm run build && rm -rf dist", "deny"]
  ]
}
```

- **`extends`** — profiles merge in order, then your own lists append. A profile
  pulled in twice contributes once, so diamonds are fine.
- **`vars`** — `{{name}}` in any pattern. A list becomes an escaped alternation
  `(?:a|b)`; a string is inserted as regex *source*.
- **`disable`** — drop an inherited rule by id instead of forking the profile.
  A typo is an error, not a silent no-op.
- **`cases`** — the profiles carry their own; yours append. **Every rule you add
  needs a case that must NOT be allowed.** A rule with only happy cases has not
  been thought about.

The profiles:

| Profile | Holds |
|---|---|
| `base` | the language-agnostic denials and the read-only allow set. Every other profile extends it, so it is always in the chain whether you name it or not. |
| `git` | the ordinary flow allowed, the irreversible refused (force-push, `reset --hard`, `clean -f`, branch delete, history rewrite) |
| `git-branch-policy` | extends `git`: protected branches denied, branch-shaped commands pinned to `{{work_branch}}` |
| `node` | `npm run`, installs, and `npx` restricted to named tools — `npx <anything>` executes a package nobody read |
| `python` | pytest/ruff/mypy and `python -m <named modules>` |

## Checking your work

```sh
python3 .claude/hooks/bash-whitelist.py --self-test          # engine fixtures + every case
python3 .claude/hooks/bash-whitelist.py --explain '<cmd>'    # verdict and reason, runs nothing
python3 .claude/hooks/bash-whitelist.py --show-rules         # the merged chain, ids and all
python3 .claude/hooks/py-inline-guard.py --self-test         # the inline-body fixtures
python3 .claude/hooks/py-inline-guard.py --explain '<cmd>'   # what the guard thinks of one body
python3 .claude/hooks/bash-advise.py --self-test             # the advice routing fixtures
python3 .claude/hooks/bash-advise.py --explain '<cmd>'       # the advice an ask would carry
python3 .claude/hooks/permission-audit.py --report           # what keeps costing a prompt
python3 .claude/scripts/whitelist-request.py --self-test     # the "could this authorise rm" probes
```

`--explain` works on a shape a DENY rule covers: a `--`-flagged call to one of
these hooks has its quoted argument blanked before the deny rules read it, the
same way a `grep` haystack is. It is one segment only — `--explain 'ls'; sudo id`
is still scanned raw and still denied.

`--report` is how the rules get curated: each line is a rule you have not
written yet. Widen deliberately, never to silence a prompt.

## The part that is not code

The installer adds `Edit`/`Write` deny rules for the three hooks, the profiles,
`rules.json` and `settings.json` itself. Keep them. An agent that can delete six
lines from the file registering the hooks has no leash at all; and `settings.json`
is on the list because it is the file that registers the hooks.

`advice.json` is deliberately **not** on that list. Check that distinction if you
change the deny rules: what decides is protected, what explains is not.

Changes to the gate are prepared as a patch, verified with
`--rules <copy> --self-test`, and applied by a human.

## What it does not cover: MCP tool calls

The gate matches `Bash`. An MCP tool that drops a table or posts to a channel is
not a shell command and has no shape these regexes can read, so it is not routed
through here — and it should not be. Two things do apply to it:

- `permission-audit.py` logs **every** prompted call, MCP ones included, with
  the query/path/url that triggered it. `--report` will show a server that keeps
  asking; that is your evidence for what to do next.
- What to do next is `permissions.allow` / `permissions.deny` in
  `.claude/settings.json`, per tool (`mcp__<server>__<tool>`). That is the
  harness's own allowlist, and it is the right place — a shell whitelist that
  grew a second, differently-shaped policy for MCP would be two policies in one
  file, and nobody would know which one refused them.

The same reasoning is why the decision lives in a hook rather than behind an MCP
server: `PreToolUse` is the only point where a Bash call can still be stopped,
it is a file that travels with the repository, and it needs no network. A leash
that depends on a service being up either fails open (no leash) or fails closed
(no session) the first time the service is down. Serving the *rules* from
somewhere central is a reasonable future; serving the *decision* is not.

## Requirements

Python 3.8+. No third-party packages. macOS and Linux.
