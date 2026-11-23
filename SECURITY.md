# Security

harness-guard decides whether a skill or a harness looks safe enough to trust, so a hole in it matters:
a malicious skill that it lets through, or a way to make it leak what it reads.

## Reporting a problem

Please do not open a public issue. Use GitHub's private reporting instead: on this repository,
Security, then "Report a vulnerability". Say what you found, how to reproduce it, and what someone
could do with it.

You will get an answer within a week. Once it is fixed, you are credited in the fix unless you ask
not to be.

## What counts

For example: a skill or harness piece that does something harmful and still comes out ✅ OK, a way
to make harness-guard run anything it reads, text in a skill that makes the AI judge clear a static
block or pass off an invented quote, a secret value that ends up in a report, in the judge cache or
in what is sent to the judge, or a way for an agent to approve a skill without the person.

A skill that slips past the static rules alone is not a security problem: say so in an issue, with
a defanged copy, and it becomes a test.

## What it does not promise

harness-guard reads files; it never runs them. A ✅ means "nothing suspicious found", not "safe". It
cannot see what a skill downloads later, or what an MCP server's tools say until the server runs.
