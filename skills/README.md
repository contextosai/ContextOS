# Agent skills

Skills that teach coding agents to work with ContextOS. Each directory is a skill in
the open `SKILL.md` format: instructions, references and scripts an agent loads when
the task matches its description.

| Skill | For |
| --- | --- |
| [contextos-pack-authoring](contextos-pack-authoring/SKILL.md) | writing, changing and reviewing Context Packs, checked with `ctx validate`, `ctx test`, `ctx plan` and `ctx gate` |

To use one, copy or link its directory where your agent looks for skills, for example
`.claude/skills/` in your project (or `~/.claude/skills/`) for Claude Code, or
`.agents/skills/` for agents that read that location:

```sh
mkdir -p .claude/skills
ln -s "$(pwd)/skills/contextos-pack-authoring" .claude/skills/contextos-pack-authoring
```

The skill's scripts need `ctx` on `PATH`, in `$CTX` or `$CONTEXTOS_BIN`, in a release
archive's `bin/`, or built in this checkout (`cargo build -p ctx`). `examples/support-refund/check_packs.sh` runs them
in CI, so the commands a skill teaches stay working.
