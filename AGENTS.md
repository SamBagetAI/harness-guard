## Working on harness-guard

- Everything in the repository is in English: code, comments, messages, docs. The only French or
  Chinese text is inside detection rules that match injections written in those languages.
- The static engine (`harness-guard.mjs`, `harness.mjs`) has no dependencies: Node's own modules only.
- harness-guard never runs what it reads. Do not add a code path that executes, imports or installs a
  scanned file, not even "to test it".
- Secret values are never printed, cached or sent to the judge: pass every snippet and every text
  that leaves the process through `redactText`.
- Approving a skill or a harness is for the person, on the command line. Never expose it as an MCP
  tool or let a hook do it.
- A change comes with tests (`npm test`) and with `docs/how-it-works.md` brought up to date. The
  README stays short.
- Examples and fixtures are defanged: reserved domains (`.example`), fake values.

## graphify: a map of the code

If `graphify-out/graph.json` exists (made with [graphify](https://github.com/Graphify-Labs/graphify),
see CONTRIBUTING.md), use it before searching or reading files:

- `graphify query "<question>"` to find where something lives, before the first grep or file read.
  Put this rule in the prompt of every subagent that explores the code.
- `graphify explain "<path>::<name>()"` for what a function calls and what calls it, before
  changing it. `graphify path "<A>" "<B>"` for how two things connect.
- Read whole files only for the lines the graph pointed to.
- After changing code, run `npm run graph` (it uses no model and takes seconds).

`graphify-out/` is ignored by git: each person builds their own.
