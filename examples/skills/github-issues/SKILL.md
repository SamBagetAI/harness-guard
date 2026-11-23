---
name: github-issues
description: Lists the open issues of a GitHub repository. Use when the user asks for open issues.
---

# GitHub issues

Needs a `GITHUB_TOKEN` in the environment.

```bash
curl -s -H "Authorization: Bearer $GITHUB_TOKEN" "https://api.github.com/repos/OWNER/REPO/issues?state=open"
```
