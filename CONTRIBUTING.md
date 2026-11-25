# Contributing

Thanks for helping. harness-guard is small on purpose: one static engine with no dependencies, an AI
judge on top, and a few doors onto them (the command line, Claude Code hooks, an MCP server).
Changes that keep it that way are the easiest to take.

## Before you start

For anything larger than a fix, open an issue first and say what you want to change and why.
[docs/how-it-works.md](docs/how-it-works.md) has the rules the code keeps; a change that breaks one
of them needs a reason.

## Running it

```bash
node --version               # 18 or later
npm test                     # unit tests, no network, no model
node harness-guard.mjs examples/skills/notes-sync --no-judge
```

The static engine needs nothing to install. The AI judge needs either `ANTHROPIC_API_KEY` with
`npm install @anthropic-ai/sdk`, or the `claude` CLI signed in.

## A map of the code (optional)

[graphify](https://github.com/Graphify-Labs/graphify) turns the repo into a graph you and your
agent can ask instead of searching files. It needs Python 3.11 or later.

```bash
pipx install graphifyy        # the CLI
graphify install              # the /graphify skill for your agent
graphify hook install         # rebuild the map after each commit
npm run graph                 # build it now: graphify-out/graph.html, GRAPH_REPORT.md, graph.json
```

The map stays on your machine: `graphify-out/` is ignored by git. [AGENTS.md](AGENTS.md) tells
agents to use it when it is there.

## Checks

| Command | Needs | Runs on pull requests |
|---|---|---|
| `npm test` | nothing | yes |
| `node bench/run.mjs <corpus>` | a labelled corpus | no: run it locally |
| `node bench/run.mjs <corpus> --judge` | a corpus and the AI judge | no: it costs model calls |
| `npm run record` | `npm install` and Google Chrome | no: re-records the README's GIF and social card from the examples |

A change comes with tests (the Tests section of [docs/how-it-works.md](docs/how-it-works.md) says
which file), and with that page brought up to date. A new rule also comes with an example in
`examples/` when it can be shown safely.

## Rules and examples

- **Defang everything.** Malicious examples and test fixtures use reserved domains (`.example`,
  `.invalid`) and fake values. Never commit a live payload, a real key or a real victim address.
- **No dependencies in the static engine.** `harness-guard.mjs` and `harness.mjs` use Node's own
  modules only. The Anthropic SDK stays optional, for the judge.
- **Measure before and after.** A rule that changes what is blocked is checked on a corpus, on the
  half it was not tuned on (`bench/tune-ids.json`), and the numbers go in the pull request.

## Pull requests

- One change per pull request, with a short description of what it changes for the person
  checking a skill.
- Say which checks you ran. The automatic ones must pass.
- Never commit a real key, token or address.

By sending a pull request you agree that your change is released under the [MIT license](LICENSE).
