<p align="center"><img src="docs/guard.svg" width="200" alt="Harness Guard's dog, in a harness with a shield on its chest, keeping watch"></p>

<h1 align="center">Harness Guard</h1>

<p align="center">Check your agent's whole harness before you trust it.</p>

<p align="center">
  <a href="https://github.com/SamBagetAI/harness-guard/actions/workflows/checks.yml"><img alt="Checks" src="https://github.com/SamBagetAI/harness-guard/actions/workflows/checks.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-1a3ad8"></a>
  <img alt="Claude Code" src="https://img.shields.io/badge/for-Claude%20Code-d97757?logo=claude&logoColor=white">
  <img alt="MCP" src="https://img.shields.io/badge/MCP-stdio%20server-black">
  <img alt="Node 18+" src="https://img.shields.io/badge/node-%E2%89%A518-5fa04e?logo=nodedotjs&logoColor=white">
  <img alt="No dependencies" src="https://img.shields.io/badge/dependencies-none-2ea44f">
</p>

![Harness Guard in a terminal: the example harness is blocked, then a skill that reads an SSH key is blocked](docs/demo.gif)

Your agent runs with more than its prompt: hooks that fire on every message, MCP servers that start
with every session, plugins that update themselves, skills you downloaded. Harness Guard reads all of
it, without running any of it, and tells you what it does without asking you.

- **Permissions, not a score.** The commands that run on their own, the servers it starts, the sites
  it contacts, the secrets it reads.
- **A verdict per piece.** ✅ OK, ⚠️ NEEDS REVIEW or ⛔ BLOCKED, with the line behind it.
- **Blocks only what is serious**, like `curl | sh`, a secret read next to a network call, or a
  crypto miner. The rest is for you to decide.
- **An AI judge on top** that must quote its evidence. It can never clear a block.
- **Approve once, then see only changes**: a plugin update or a package moved to `@latest` shows up
  on its own.

## Try it

```bash
npm install -g github:SamBagetAI/harness-guard
harness-guard install
```

`install` adds three Claude Code hooks and the MCP server, for every project (`uninstall` takes
them out). Needs Node 18 or later.

| When | You | Harness Guard |
|---|---|---|
| You open a project | `harness-guard` | Shows what the harness does and each piece's verdict. |
| You have read it | `harness-guard approve` | From now on, reports only what changes. |
| You find a new skill | `harness-guard ./the-skill` | Gives its verdict before you install it. |
| A session starts | nothing | Claude tells you if something is blocked or changed. |
| You ask Claude | "Check my harness" | Claude shows you the report. |
| In CI | `harness-guard ./skills/x --json --no-judge` | Exits `0` OK, `1` review, `2` blocked. |

## How well it works

On 136 real skills (70 from Anthropic, OpenAI, obra/superpowers and Vercel, 66 malicious ones from
[MalSkillBench](https://github.com/lxyeternal/MalSkillBench)), on the half the rules were not tuned on:

| | Malicious caught | Safe ones flagged |
|---|---|---|
| Static analysis | 67 % | 14.3 % |
| With the AI judge | **97 %** | **5.7 %** |

## More

- [How it works](docs/how-it-works.md): the rules, the judge, the measurements and what it cannot see.
- [Examples](examples): defanged skills and a whole harness, each with its expected verdict
  (`npm run examples`).
- [Contributing](CONTRIBUTING.md) and [security](SECURITY.md).

MIT license.
