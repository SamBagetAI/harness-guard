# Harness Guard: how it works

Check your agent's whole harness before you trust it.

Harness Guard is one static engine with no dependencies, an AI judge on top, and three doors onto
them: the command line, Claude Code hooks and an MCP server. It reads files and configuration; it
never executes, imports or installs anything it reads, and it never shows or sends a secret value.

## Where it stands

The code is four files of plain JavaScript (ES modules, Node 18 or later):

| File | What it holds |
|---|---|
| `harness-guard.mjs` | The skill engine (reading a skill, the rules, combinations, permissions, approval and diff), the Claude Code hooks, the MCP server and the command line. |
| `harness.mjs` | The harness: finding every piece of a Claude Code setup, the rules for hooks, MCP servers, settings and permissions, the harness approval, secret redaction, the harness report. |
| `common.mjs` | What the three others share: verdicts, the state folder, safe JSON reading, front matter, secret redaction, a small concurrency helper. |
| `judge.mjs` | The AI judge: the prompt, the two ways to call the model, quote checking, the cache, and how its verdict is merged with the static one. |

State lives in `~/.harness-guard` (or `HARNESS_GUARD_HOME`): `approved/` for skill approvals,
`harness/` for harness approvals, `judge-cache/` for the judge's answers. Nothing else is written.

## How it works

### Verdicts

Every skill and every harness piece gets one of three verdicts: ✅ OK, ⚠️ NEEDS REVIEW or
⛔ BLOCKED. There is no score: what matters is the list of what the piece can do, and the reasons.

### A skill

A skill is a folder with a `SKILL.md`. Every file in it is read, including scripts it calls.
`.gz` and `.br` files holding text are decompressed and read too, within the same 1 MB limit. A
compiled binary, an archive, a file over 1 MB (compressed or not) or a symbolic link cannot be read:
it is reported as needing review, never ignored.

Each line is matched against the rules. Markdown prose is text, not an action: a documentation link
is not network access, and an attack phrase quoted between quotation marks is not an attack.

**What blocks on its own:**

- downloading and running code (`curl … | sh`, `sh -c "$(curl …)"`, `iwr … | iex`);
- decoding hidden text and running it (`base64 -d | sh`, `eval(atob(…))`);
- a reverse shell (`/dev/tcp/…`, `nc -e`);
- wiping the home folder or the disk;
- writing to a shell start-up file (`.zshrc`, `.bashrc`…) or the crontab, or rewriting the agent's
  identity files;
- invisible Unicode text (tag characters, bidirectional overrides);
- a password-protected archive to extract and run, an anonymous paste site, instructions fetched
  from the internet, a ransom note;
- a cryptocurrency miner (a known miner such as `xmrig`, a `stratum+tcp://` pool, miner options),
  or mining described in words together with a service, launch agent or cron that keeps it running;
- a combination: credentials read from the machine (`~/.ssh`, `~/.aws`, keychain…) or every
  environment variable, and a network call, in the same code file or the same Markdown code block;
  or a secret and a raw IP address or collection service (webhook.site, ngrok…).

**What needs review:** mining described in words (not data or text mining), prompt injection and instructions that go behind the user's back (also in
French and Chinese), hidden HTML comments, obfuscated code, `eval`, collection services, raw IP
addresses, browser tokens, writes to the agent's configuration or permanent instructions, compiled
binaries, and `curl | sh` from the skill publisher's own site or a known installer (Homebrew,
rustup…).

**Permissions** are listed under four headings: network (hosts and tools), secrets (variable
names, credential files), execution (subprocess, sudo…) and persistence.

### The whole harness

`harness-guard` with no argument reads the harness of the current project (`--cwd` for another):

| Piece | Where it is read | What is checked |
|---|---|---|
| Hooks | `settings.json` files, plugins' `hooks/hooks.json` | The command **and** the local scripts it runs; a hook that contacts the internet; an `http` hook that sends every event elsewhere; prompt hooks for injection. |
| MCP servers | `~/.claude.json` (user and local), `.mcp.json`, plugins, the desktop app | An `npx`/`uvx`/`pnpm dlx` package with no pinned version or on `@latest`; a remote server on plain `http://`; Docker with wide access; the names of secrets passed in. |
| Settings | user and project `settings.json` and `settings.local.json` | `ANTHROPIC_BASE_URL` pointing elsewhere than Anthropic, a network proxy, TLS checks turned off, prompt telemetry, `apiKeyHelper` and `statusLine` commands, `disableAllHooks`, `enableAllProjectMcpServers`. |
| Permissions | the same files | `bypassPermissions`, access to all of `~` or `/`, allow rules that permit anything (`Bash(*)`, `Bash(curl:*)`, `Bash(python3:*)`…), secrets left in plain text in a rule or in `env`. |
| Instructions and memory | `CLAUDE.md` (user, project, parent folders), `CLAUDE.local.md`, `AGENTS.md`, `.claude/rules/`, the project's auto memory | The text rules: injection, hidden comments, invisible text. |
| Subagents and slash commands | user, project and plugin `agents/` and `commands/` | The text rules, `permissionMode: bypassPermissions`, and `` !`command` `` lines, which run on their own. |
| Plugins and skills | enabled plugins (`enabledPlugins` and `installed_plugins.json`), `~/.claude/skills`, `.claude/skills` | Everything above, and the skill analysis. |

The summary at the top says what the harness does **without asking you**: automatic commands by
event, MCP servers and how many are unpinned, the hosts and secrets of the pieces that act on their
own (hooks, MCP, settings, commands; the docs and skills have their own reports), the number of
allow rules and the risky ones, and where Claude traffic goes.

### Approval and changes

`harness-guard approve` saves, for every piece, its fingerprint, its findings and its permissions.
After that, a finding that was approved stays hidden, and these are reported: a new piece, a
changed piece, a new permission, a removed piece. `harness-guard approve <folder>` does the same
for one skill: an update that adds a host, a secret or an execution is reported, however small.

Approving is for the person, on the command line. It is not an MCP tool and no hook does it.

### The AI judge

- **Which model.** `claude-opus-5-5` by default (`HARNESS_GUARD_MODEL`). It goes through the
  Anthropic SDK when `ANTHROPIC_API_KEY` is set (`npm install @anthropic-ai/sdk`), otherwise
  through the `claude` CLI, run with no tools, no settings and no MCP servers, in an empty folder.
- **What it sees.** The files, each wrapped in a tag with a random name and marked as untrusted
  data, the static findings and the permissions, all with secret values masked.
- **Quotes are checked.** Every piece of evidence must quote an exact passage (at least 8
  characters), which the code looks for in the files. A quote that clears a warning needs at least
  20 characters, from the finding's own file. A quote that is not there is dropped; "malicious" with no quote left becomes
  "suspicious".
- **Floors.** The judge can raise a verdict, or clear a warning with an exact quote. It can never
  clear a block, an unreadable file or a new permission, and it clears nothing when some files were
  too large to show it.
- **Refusals.** When the model's safety filters refuse to read a skill, that skill needs review.
- **Cache.** One answer per version of a piece and per model, in `~/.harness-guard/judge-cache`.
  Cleared findings are stored by their key, so a cached answer never clears another finding when the
  rules or the approvals change. A skill approved unchanged is not judged again. Before a skill is used, the hook only reads the
  cache and judges new skills in the background, so it never makes Claude wait.

### Secrets

`redactText` masks `NAME_KEY=value`, passwords in URLs, `Bearer` tokens, `--password` options and
known token shapes (`sk-`, `re_`, `ghp_`, `xox…`, `AKIA…`, JWTs). Every snippet in a report and
every text sent to the judge goes through it.

## Everyday use

### Install

```bash
npm install -g github:SamBagetAI/harness-guard   # or: git clone, then npm install -g .
harness-guard install                           # hooks and MCP server, for every project
```

`install` merges three hooks into `~/.claude/settings.json` (or `$CLAUDE_CONFIG_DIR/settings.json`)
without touching anything else, keeps the previous file next to it as
`settings.json.before-harness-guard`, and registers the MCP server with
`claude mcp add --scope user`. Running it again changes nothing. It refuses to edit a settings file
that is not valid JSON. Without the `claude` CLI, it adds the hooks and prints the command that
registers the MCP server.

- `--dry-run` says what would change.
- `--no-hooks` or `--no-mcp` leaves that part alone.
- `harness-guard uninstall` takes out only what `install` put in.
- The hooks call Node by its full path: after switching Node versions (nvm), run `install` again.

### A new project

1. `harness-guard` in the project folder. Read the summary at the top: what runs on its own, which
   servers start, where your traffic goes, which allow rules let the agent act without asking.
2. Fix what you do not want (a hook, an unpinned server, a secret in a rule), or accept it.
3. `harness-guard approve`. From then on the report only shows what changed, and so does the
   message at the start of each session.

### A new skill

`harness-guard ./the-skill` before you copy it into `.claude/skills` or `~/.claude/skills`. If you
install it anyway, the PostToolUse hook checks it as Claude writes it, and the PreToolUse hook
checks it again before Claude uses it. `harness-guard approve ./the-skill` accepts what you read,
and its next update is compared with it.

### When something changes

Plugins update themselves, and a teammate can push a new hook or MCP server in the project's
settings. At the start of the next session, Claude tells you which piece is new or changed. Run
`harness-guard` to see why, then `harness-guard approve` once you agree.

### From your agent

Ask Claude "check my harness" or "is this skill safe?". It calls `check_harness` or `check_skill`
and shows you the report. It cannot approve anything for you.

### In CI

```bash
harness-guard ./skills/my-skill --json --no-judge   # exit 0 OK, 1 needs review, 2 blocked
harness-guard audit ./skills --json --no-judge      # every skill in a folder
```

## Hooks and MCP

`harness-guard hook --print-config` prints the hooks, in exec form (no shell quoting):

| Event | What it does |
|---|---|
| `SessionStart` | Checks the harness. Speaks only if a piece is blocked, or if something changed since the approval: Claude is told to warn you, and you see a short message. |
| `PreToolUse` on `Skill` | Before Claude uses a skill (looked up among the user's, the project's and enabled plugins' skills): a blocked skill is denied, one that needs review asks you. It uses the judge's cached opinion; a skill not judged yet is judged in the background, once per version. |
| `PostToolUse` on `Write\|Edit\|MultiEdit\|Bash` | When Claude writes a skill or a harness file (settings, `.mcp.json`, `CLAUDE.md`, subagents…), or runs a command that copies, clones, unpacks or installs into a skills or plugins folder. |

A failing hook never breaks the session: it says nothing and lets the action go ahead.

The MCP server (`harness-guard mcp`, stdio) has three read-only tools: `check_harness`,
`check_skill`, `audit_skills`. Their answers tell the agent that quoted text is data, not
instructions.

## What it cannot see

- An attack written only in prose, or a URL built piece by piece: that is the judge's job, and it
  can miss too.
- What a skill or a server downloads later, and what an MCP server's tools say: seeing them means
  running the server.
- A skill whose only problem is its author. A ✅ means "nothing suspicious found", not "safe".

## Environment

| Variable | What it does |
|---|---|
| `HARNESS_GUARD_HOME` | Where approvals and the judge cache are kept (default `~/.harness-guard`). |
| `HARNESS_GUARD_JUDGE` | `off`, `api` or `claude`: turn the judge off or force how it is called. |
| `HARNESS_GUARD_MODEL` | The judge's model (default `claude-opus-5-5`). |
| `HARNESS_GUARD_CLAUDE_BIN` | The `claude` CLI to call (the tests point it at a fake one). |
| `HARNESS_GUARD_USER_HOME` | The home folder to read the harness from (the tests and examples use a fake one). |
| `ANTHROPIC_API_KEY` | When set, the judge uses the Anthropic SDK. |

## Commands

```bash
harness-guard                      # the harness of the current project
harness-guard approve              # approve it
harness-guard <folder>             # one skill
harness-guard approve <folder>     # approve one skill
harness-guard audit [--judge]      # every installed skill
harness-guard install [--dry-run]  # the Claude Code hooks and the MCP server
harness-guard uninstall            # take them out
harness-guard hook --print-config  # the hooks, to add them by hand
harness-guard mcp                  # the MCP server
npm test                           # unit tests
npm run examples                   # the examples against their expected verdicts
npm run bench -- <corpus> [--judge] --out res.tsv
```

### Tests

GitHub runs `npm test` and `npm run examples` on Node 18 and 22 on every pull request and every
push to main (`.github/workflows/checks.yml`), with the judge off.

`npm test` runs `tests/*.test.mjs` with Node's own test runner: no test library, no network, no
model. The judge is tested with a fake `claude` CLI (`tests/fixtures/fake-claude.mjs`), `install` with
another (`tests/fixtures/fake-claude-cli.mjs`) and a throwaway settings folder, and the harness with
a fake home folder.

| File | What it pins down |
|---|---|
| `tests/rules.test.mjs` | What blocks and what needs review, combinations, Markdown prose, binaries and compressed files, the false positives seen on real skills. |
| `tests/approve.test.mjs` | Approving a skill, hidden findings, and the diff that catches a rug-pull update. |
| `tests/judge.test.mjs` | Verified quotes, floors, clearing a warning, the cache, failures, approved versions. |
| `tests/hooks-mcp.test.mjs` | The PostToolUse and PreToolUse hooks, the MCP server (in-process and over stdio), exit codes. |
| `tests/harness.test.mjs` | Hooks, MCP servers, settings, plugins and commands; approval and changes; secret redaction; the SessionStart hook. |
| `tests/install.test.mjs` | `install` and `uninstall`: merged hooks, other settings kept, a second run changing nothing, dry runs, invalid JSON, no `claude` CLI, a new node path, the first backup kept. |
| `tests/examples.test.mjs` | Every example gives the verdict in `examples/expected.json`. |

`tests/helpers.mjs` builds skills in a temporary folder, the fake judge and the fake harness. A
change comes with tests in the file that can see it, and with this page brought up to date.

### Measuring

`bench/run.mjs` runs a labelled corpus (`manifest.json` with `id` and `label`, then
`<label>/<id>/`) and prints what was caught and what was flagged by mistake. `bench/split.py` gives
the numbers for the half the rules were tuned on (`bench/tune-ids.json`) and for the other half.

The corpus used so far: 70 safe skills from anthropics/skills, openai/skills, obra/superpowers and
vercel-labs/agent-skills, and 66 malicious ones from
[MalSkillBench](https://github.com/lxyeternal/MalSkillBench) (56 found in the wild, 10 synthetic).
Its list is in `bench/corpus-manifest.json`; the files are not included, because MalSkillBench is
for academic research only. On the half the rules were not tuned on:

| | Malicious blocked | Malicious flagged (⛔ or ⚠️) | Safe blocked | Safe flagged |
|---|---|---|---|---|
| Static, first version | 33 % | 42 % | 11.4 % | 14.3 % |
| Static, current rules | 55 % | 67 % | 5.7 % | 14.3 % |
| Static + judge (claude-opus-5-5) | 76 % | **97 %** | 5.7 % | **5.7 %** |

The 2 safe skills still blocked are blocked by the static rules (`curl | sh` from installers),
which the judge may not clear. On this corpus, the 3 skills the model refused to read were all
malicious.
