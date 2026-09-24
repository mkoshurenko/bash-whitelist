---
name: bash-discipline
description: How to compose a Bash call in this repo so it passes the whitelist gate — the shapes that always pass, the shapes that never will and what to write instead, how to act on each of the three things bash-advise tells you when a call is ASK'd, why a permission prompt is a defect and not a feature, what deletion owes the human before it is proposed, and how to request a new rule when nothing allowed does the job. Use when about to write any Bash command, run a script or an inline python3/node snippet, when a call has just been refused or has cost a permission prompt, when tempted to delete files or clear a cache, and when curating .claude/whitelist/rules.json.
---

# Bash discipline: aim before you type

`.claude/hooks/bash-whitelist.py` decides every Bash call before it runs, from
the rules in `.claude/whitelist/rules.json`. It is not a filter you discover by
hitting it. **Read the shape you need here, then write the command to fit it.**

A permission prompt is not the gate being strict. It is a command composed
without looking, and it hands the safety decision back to the human the gate
exists to spare. In the repo these rules came from, one week logged 828 of them
— 48 inline heredocs, 35 shell loops, and 181 calls that `cd` into the directory
the session already stood in. None were dangerous. All of them cost a person an
interruption, and a person who approves fifty harmless prompts stops reading the
fifty-first.

## The gate in four sentences

1. Every `&&`, `||`, `;`, `|` and newline splits the call, and **each segment is
   checked on its own** — one unmatched segment refuses the whole line.
2. `deny` refuses outright and is not negotiable.
3. A **recompose** rule refuses **and names the allowed equivalent** — that
   reason comes back to you, so act on it instead of retrying a variant.
4. Everything else is routed by `"unmatched"` in rules.json. Under the default,
   `human`, it asks the human: the dialog they see quotes the `allow` rules that
   mention your program, and what comes back to **you** is `bash-advise`, which
   says one of three things. Under `allow` or `agent`:
   - an `escalate` match (delete, overwrite, discard git work, publish) still
     asks the human;
   - an `opaque` match (`bash x.sh`, `./x`, `x.py`, an interpreter, `| sh`,
     `make`) is refused to **you** with rewrite help: run the commands directly;
   - anything else runs (`allow`) or is refused to you with help (`agent`).
   When a refusal says `the human was not asked`, recompose and retry. After two
   refusals for the same step, file a request and move on. Never hand that call
   to the human.

## What `bash-advise` tells you, and what to do with each

It speaks only on `ask`, and it decides nothing — the human still approves.

| It says | Do |
|---|---|
| `rewrite as: <form>` | write that form. It was checked against this project's rules, so it passes. |
| `the blocker is <a smuggler>` | split the line: run the inner command on its own, use the value in the next call. |
| `no allowed rewrite is known for: <program>` | **stop composing variants.** Let the prompt stand and say, in one line, what the call does and why the task needs it. If the shape will recur, file the rule. |

The third one is the one to take literally. A second attempt at a shape that has
no allowed form spends a human's attention twice for the same decision, and the
audit log is full of exactly that.

Its own advice table is `.claude/whitelist/advice.json`, and unlike the rules it
is **not** write-protected: it produces a sentence, never a verdict. If a shape
cost you a prompt and the advice was missing or wrong, fixing the entry is in
scope — that is the file's purpose. Fixing `rules.json` is not; that is a patch
for a human.

## Two commands worth knowing before the rest

```sh
python3 .claude/hooks/bash-whitelist.py --explain 'git push origin feature/x'
python3 .claude/hooks/bash-whitelist.py --show-rules
python3 .claude/hooks/bash-advise.py --explain 'git checkout release-2'
```

`--explain` prints the verdict and the reason without running anything. Use it
when unsure — it is free, and it is the difference between aiming and guessing.
`--show-rules` prints the merged rule chain, which is the only description of
the policy that cannot go stale. The advisor's `--explain` prints the advice an
`ask` would carry, which is the faster question when you already expect a prompt
and want to know whether an allowed form exists at all.

## Shapes that pass

| Job | Write |
|---|---|
| read a file | the Read tool; in a pipe, `cat`/`head`/`tail`/`nl` (never on `.env`) |
| search | `grep`/`rg`/`find`/`fd`/`jq`/`awk`/`sort`/`uniq`/`diff`/`xargs`, or the Grep tool |
| edit text | the Edit/Write tools — `sed -n` reads, `sed -i` is refused |
| git, reading | `status`, `log`, `diff`, `show`, `blame`, `rev-parse`, `ls-files`, `branch --list`, `stash list` |
| git, the flow | `add`, `commit`, `switch`/`checkout -b`, `pull --ff-only`, `merge --no-ff`, `stash push/pop`, `worktree add` |
| the verify gate | whatever `rules.json` names for this project — `--show-rules` lists it |
| a new rule | `python3 .claude/scripts/whitelist-request.py --pattern … --why … --tried … --case …` |
| what keeps prompting | `python3 .claude/hooks/permission-audit.py --report` |

## Shapes that never pass, and the equivalent

| Instead of | Write |
|---|---|
| `for f in …; do … done` | one `grep -rn` over the list of paths, or the Grep tool |
| `python3 -c`, `node -e`, `python3 - <<'PY'` | the Read/Write/Edit tools. If the same snippet recurs, it has earned a reviewed script under `.claude/scripts` |
| any heredoc | Write the file, then run it by path |
| `sed -i`, `perl -pi -e`, `awk -i inplace` | the Edit tool — it fails loudly when the target text is not what you assumed |
| `cmd > file` | let the output come back; write with Write, read with Read |
| bare `curl` / `wget` | the WebFetch tool, or a reviewed script that takes a path, never a URL |
| `sleep 30 && …` | the Monitor tool for a condition, or the runner's own `--wait` |
| `cd /path/to/this/repo && …` | nothing — you are already there |
| `$(…)`, backticks, `&` | split the work into separate calls |
| `grep "…$(x)…"` | single-quote the pattern; `'…'` expands nothing |

## Deletion is not a shape problem

Nothing that removes a file is answered with an equivalent, and nothing ever
will be. An equivalent turns a stop into a detour, and deletion has no
equivalent. It stays a prompt for the human — and the prompt owes them four
things, stated **before** the command:

- **what** exactly — an explicit list, never a glob;
- **why now** — what is blocked while it exists;
- **what breaks** while it is gone;
- **the way back** — tracked in git, regenerated by a named command, or gone
  for good.

"Regenerable" is not "free". A build directory under a running dev server is
process state. Test artifacts are the failure traces you were about to read —
wiping them destroys the evidence, not the mess. `node_modules` costs a
reinstall and can resolve different versions.

This is written from damage, not caution. `rg -l foo | xargs rm` deleted three
files on 2026-08-14; `rmSync(process.cwd() + "/e2e", {recursive:true})` deleted
a directory on 2026-08-13. Both read as an ordinary search and an ordinary
probe. Their deny rules carry those dates in their `note` fields.

## When nothing allowed does the job

Two refusals of the same class is not an invitation to a third attempt. Stop and
choose:

1. **A reviewed script**, if the work recurs — a named file under
   `.claude/scripts/` that validates its own arguments and does one job, allowed
   by exact path and write-protected in `settings.json`. This is the preferred
   answer: a glob over `scripts/` would let an agent write a script and then run
   it, so each one is allowed by name.
2. **A rule request**, if the shape itself is missing:
   `python3 .claude/scripts/whitelist-request.py --pattern … --why … --tried … --case …`
   It records the proposed rule, the reason no allowed form works, and the cases
   the rules file will carry. It queues the request; it does not edit anything.
   Destructive patterns are rejected by the script itself — autonomy over
   deletion is not something to be won one rule at a time.

A prompt approves one invocation and teaches the system nothing. A rule approves
the shape forever. Ask for the rule.

## Curating the gate

`bash-whitelist.py`, `.claude/whitelist/`, `settings.json` and the reviewed
scripts are write-denied to agents on purpose: whoever can edit the leash does
not have one. Prepare the patch **and its cases** in a scratch file, verify it
yourself —

```sh
python3 .claude/hooks/bash-whitelist.py --rules <path-to-your-copy> --self-test
```

— which runs the engine fixtures and every case in the chain, and hand the human
a single line to apply. Never widen a rule to silence a prompt; narrow the
command instead. Every rule you add carries at least one case that must NOT be
allowed — that case is the reason anyone can trust the rule.
