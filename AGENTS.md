# Installing this gate into a project — instructions for an agent

You have been pointed at this file to install the bash whitelist into a
project. Read all of it before running anything. It takes about ten minutes,
and most of that is step 4, which is the only part that makes the gate fit
*this* project rather than the one it came from.

**What you are installing.** A `PreToolUse(Bash)` hook that decides every shell
command before it runs: `deny` (refused, reason returned to the agent),
`allow` (runs silently), or `ask` (falls through to the human's permission
prompt). Plus a `PermissionRequest` hook that logs what fell through, so the
rules can be curated from evidence rather than guesswork.

**What you must not do.** Do not widen a rule to make your current command run.
Do not add a rule that could authorise a delete. Do not edit the gate after
step 3 — from that point the files are write-denied to you, which is the point:
whoever can edit the leash does not have one. If you need a rule, follow step 6.

---

## 1. Check the ground

```sh
python3 --version          # 3.8 or newer; no third-party packages are used
```

The target project needs a `.claude/` directory (create it if missing) and
should be a git repository, so the install is one reviewable diff.

If the project already has `.claude/settings.json` with hooks in it, say so
before installing — the installer merges rather than replaces, and keeps the
previous file at `settings.json.bak`, but the human should know it is being
touched.

## 2. Install

```sh
python3 <path-to-this-repo>/install.py <path-to-project> --dry-run
python3 <path-to-this-repo>/install.py <path-to-project>
```

It copies:

| To | What |
|---|---|
| `.claude/hooks/bash-whitelist.py` | the engine — no rules inside it |
| `.claude/hooks/py-inline-guard.py` | reads the Python that `python3 -c` runs |
| `.claude/hooks/permission-audit.py` | the prompt log and its `--report` reader |
| `.claude/scripts/whitelist-request.py` | how a rule gets asked for |
| `.claude/whitelist/profiles/*.json` | the shipped rule profiles |
| `.claude/whitelist/rules.json` | this project's policy — the file you edit |
| `.claude/skills/bash-discipline/SKILL.md` | how an agent composes a command |

…wires all three hooks into `.claude/settings.json` (two `PreToolUse(Bash)`, one
`PermissionRequest`), adds the write-protection deny list, appends two lines to
`.gitignore`, and runs both sets of fixtures. It
never overwrites an existing file unless you pass `--force`; anything it kept is
printed by name.

## 3. Confirm it decides

```sh
python3 .claude/hooks/bash-whitelist.py --self-test
python3 .claude/hooks/py-inline-guard.py --self-test
python3 .claude/hooks/bash-whitelist.py --explain 'git push --force origin main'
python3 .claude/hooks/bash-whitelist.py --explain 'npm run build'
```

All fixtures must pass. If any is red, stop and report it — a red case means a
rule does not mean what its author thought, and a gate you cannot trust is worse
than none, because everyone stops reading its prompts.

## 4. Fit the rules to this project — the part that matters

Open `.claude/whitelist/rules.json`. It arrived as an example. Make it true.

**`extends`** — keep `base`; every other profile extends it anyway, so naming it
is documentation. Add `git` for any repository. Add `node`, `python`, or both,
matching the stack. Use `git-branch-policy` **instead of** `git` only if this
project forbids agents from touching certain branches (it extends `git` itself).

**`vars`** — `protected_branches` and `work_branch` only matter under
`git-branch-policy`. A list becomes an escaped alternation; a string is inserted
as regex *source*, so `"work_branch": "feature/\\S+"` is a pattern, not a
literal.

**`allow`** — this is where you do the real work. Find what this project
actually runs and name it:

- read `package.json` scripts / `Makefile` / `pyproject.toml` / CI config;
- read `CONTRIBUTING.md` or the README for the verify sequence;
- grep the git log for the commands in the hooks (`.husky/`, `.git/hooks/`).

Write one rule per shape, anchored the way the profiles are (`\\S+`, `\\b.*`),
and give each an `id` prefixed `project.`. **Never a glob over a scripts
directory** — that would let an agent write a script and then run it. Name each
reviewed script by its exact path.

**`cases`** — every rule you add gets at least two: one command it must allow,
and one neighbouring command it must **not**. The second is the reason anyone
can trust the rule. Re-run `--self-test` after each edit.

**`disable`** — if an inherited rule is wrong for this project, drop it by id
(`--show-rules` lists them) rather than forking the profile. Say in your report
which ones you dropped and why.

## 5. Tell the project's agents the gate exists

Add this to the project's `CLAUDE.md` (adjust the paths if the project keeps
them elsewhere):

```markdown
## Guardrails

`.claude/hooks/bash-whitelist.py` gates every Bash call before it runs, from the
rules in `.claude/whitelist/rules.json`: destructive and history-rewriting
commands are denied, the ordinary flow is allowed silently, and everything else
asks the human. A refusal comes back with the allowed equivalent — act on it,
do not retry a variant.

**Aim before you type — read the `bash-discipline` skill before writing a Bash
call.** The whitelist is not a filter you discover by hitting it. Check a shape
for free with:

    python3 .claude/hooks/bash-whitelist.py --explain '<the command>'

A permission prompt is a defect, not a feature: it spends a human's attention on
a decision they will face again tomorrow. If no allowed form does the job, file
a rule request (`.claude/scripts/whitelist-request.py`) instead of asking for a
keypress.

Verify the gate: `python3 .claude/hooks/bash-whitelist.py --self-test`
See what keeps prompting: `python3 .claude/hooks/permission-audit.py --report`

The gate, its rules and `settings.json` are write-denied to agents on purpose.
Changes to them are prepared as a patch and applied by a human.
```

Do not paste this if the project's CLAUDE.md already documents a different
guardrail system — report the conflict instead. Two documented processes are
worse than one, because an agent can follow the wrong one while believing it
followed the process.

## 6. When something you need is refused

In this order, and never past step 3 of this list:

1. **Recompose.** A refusal that names an equivalent means the equivalent works.
   Use it.
2. **A reviewed script.** If the work recurs, write one file under
   `.claude/scripts/` that validates its own arguments and does one job, then
   ask for it to be allowed by exact path and write-protected.
3. **A rule request.**
   ```sh
   python3 .claude/scripts/whitelist-request.py \
       --pattern 'gh\s+pr\s+(list|view)\b.*' \
       --why 'reading PR state; no allowed form reaches it' \
       --tried 'git ls-remote shows refs, not PR bodies' \
       --case 'gh pr list|allow' --case 'gh pr merge 12|ask'
   ```
   It records the request and prints the patch. It does not apply it, and it
   refuses any pattern that could authorise a delete.

Two refusals of the same class is not an invitation to a third attempt.

## 7. Report back

Tell the human, in a few lines:

- which profiles the project now extends, and which inherited rules you disabled;
- which `project.*` rules you added, and what each unblocks;
- the self-test result (`N/N passed`);
- anything you could not decide — a build command you were unsure about is a
  rule left unwritten, not a detail to omit.
