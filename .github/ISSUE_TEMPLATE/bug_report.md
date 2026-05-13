---
name: Bug report
about: Report a defect in Plenith
title: "[bug] short summary"
labels: bug, triage
---

<!--
Thanks for filing. The more of this template you fill in, the faster we
can confirm + fix. Fields marked (required) are non-negotiable; please
don't open without them.

Security issues: STOP. Use SECURITY.md instead — public bug reports for
security issues put users at risk.
-->

## What happened (required)

A clear description of the unexpected behavior.

## What you expected to happen (required)

What you thought would happen, and where you got that expectation
(docs, prior behavior, intuition).

## Reproduction (required)

Minimal steps. Ideally a runnable command or a tiny config snippet.

```bash
# example
python run.py --config config.yaml
ssh -p 22000 jdoe@127.0.0.1
> ls -la
```

If a config is involved, paste the *minimal* config that triggers it
(with secrets redacted).

## Environment (required)

- Plenith version (tag or commit SHA): 
- Python version: `python --version`
- OS: Ubuntu 22.04 / Windows 11 / macOS 14 / …
- Docker version (if relevant): `docker --version`
- LLM endpoint: LM Studio / Ollama / cloud-X / not used

## Logs / output

```
paste the relevant logs here. State files, tracebacks, dashboard
output. Trim aggressively to the relevant lines.
```

## What you tried already

- [ ] Re-running with `--verbose` / debug logging
- [ ] Checking the troubleshooting section of relevant `docs/`
- [ ] Searching existing issues
- [ ] Other:

## Additional context

Anything else that might help — recent config changes, prior
incidents, related issues.
