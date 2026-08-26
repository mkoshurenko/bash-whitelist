# bash-whitelist — working on the utility itself

This repository is a `PreToolUse(Bash)` gate for Claude Code. Read `README.md`
for what it is and `AGENTS.md` for how it is installed into a project.

**Installing it somewhere is `AGENTS.md`. Changing it is this file.**

## The split that must not blur

- `hooks/bash-whitelist.py` is the **engine**: splitting, quoting, the deny
  view, the verdict order. It contains no policy — no branch name, no package
  manager, no project path. A rule that belongs to one project's habits belongs
  in a profile, never here.
- `profiles/*.json` are the **policy**. They are data: patterns, reasons,
  equivalents, and the cases that prove them.
- `hooks/bash-advise.py` is neither: it decides nothing. It imports the engine's
  `verdict()` and turns an `ask` into advice the agent can act on. It must never
  grow a `permissionDecision` — the moment it can allow anything, there are two
  gates and no way to tell which one let something through.
- `examples/advice.json` is the advisor's data, and it is the one file the install
  leaves writable to agents. That is only defensible while the advisor stays
  decision-free; check that invariant before changing either.

If a change needs both, it is two changes.

## Every change carries its cases

```sh
python3 hooks/bash-whitelist.py --self-test         # engine fixtures + every profile case
python3 hooks/py-inline-guard.py --self-test        # the inline-body fixtures
python3 hooks/bash-advise.py --self-test            # the advice routing fixtures
python3 scripts/whitelist-request.py --self-test    # the "could this authorise rm" probes
```

Run them from the repository root: with no `.claude/whitelist/rules.json` above
it, the gate falls back to `profiles/default.json` and the advisor to
`examples/advice.json`, which is what the fixtures assume.

A new rule needs at least two cases: one command it must allow, and the
neighbouring command it must **not**. The second is the only reason anyone can
trust the first. A rule whose cases are all happy paths has not been thought
about — `whitelist-request.py` refuses such a request from an agent, and the
same standard applies to changes made here by hand.

Cases that encode an incident keep the date in a comment or a `note`. The dates
are why the rules are trusted; a rule with no story behind it is a guess.

## Three things this file exists to prevent

1. **Widening a rule to make a command run.** Narrow the command instead. The
   only acceptable reason to widen is evidence from
   `permission-audit.py --report` that a harmless shape keeps costing prompts.
2. **Giving a destructive shape an equivalent.** Nothing that deletes goes in
   `recompose`, ever. An equivalent turns a stop into a detour, and deletion has
   no equivalent.
3. **Loosening `deny_view`.** Blanking quoted arguments is the one place where
   the gate deliberately looks away, and it is bounded three ways: only for
   tools that cannot start a process, only when *every* segment is such a tool,
   and never for a double-quoted run that expands or a quoted `.env` path. Any
   change there needs cases on both sides — the search that must stay allowed
   and the command that must stay denied.

## Layout

```
hooks/bash-whitelist.py      the engine, the CLI (--explain / --self-test / --show-rules), the hook
hooks/py-inline-guard.py     the ast allow-list for an inline `python3 -c` body
hooks/bash-advise.py         turns an `ask` into advice for the agent; decides nothing
hooks/permission-audit.py    the prompt log and its --report reader
scripts/whitelist-request.py how a rule gets asked for; refuses destructive patterns
profiles/                    base · git · git-branch-policy · node · python · default
skills/bash-discipline/      the skill installed into the target project
examples/rules.json          the starter policy install.py copies in
examples/advice.json         the starter advice table install.py copies in
install.py                   copy · wire settings.json · protect · verify
```
