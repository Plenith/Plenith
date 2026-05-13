<!--
Thank you for the PR. Please fill out the relevant sections below —
incomplete PRs are slower to review. If this is a tiny / typo fix you
may delete most of this template, but keep the "Test plan" and
"Checklist" sections.
-->

## Summary

One or two sentences. What problem does this PR solve and how?

## Why

The motivation — what does this enable, what does it fix, who asked
for it (link the issue). The diff shows *what*; this section is for
*why*.

Closes: #<issue-number>

## What changed

Bulleted list of the meaningful changes. Don't list every file; list
the user-visible / API-visible / behavioral changes.

- 
- 

## Test plan

How a reviewer should be confident this works:

- [ ] `pytest` passes locally
- [ ] New tests added for the new behavior (path: `tests/...`)
- [ ] Manual verification steps (if relevant):
  ```bash
  # commands the reviewer can run to see this in action
  ```

## Impact

Check all that apply — each one means this PR has additional review
expectations.

- [ ] Public API change (REST / plugin / connector / on-disk format)
- [ ] New runtime dependency added (`requirements.txt` edit)
- [ ] New configuration option added
- [ ] Performance-sensitive code on the hot path (see
  `tools/bench.py --compare`)
- [ ] Security-sensitive code (auth, secrets, audit chain, network
  isolation, retention)
- [ ] Touches data-handling — `docs/DPIA.md` /
  `docs/DATA_HANDLING.md` should be reviewed for accuracy
- [ ] None of the above — internal change only

## Checklist

- [ ] My code follows the project style (`pre-commit run --all-files`
  is green)
- [ ] I've added / updated tests
- [ ] I've added / updated relevant documentation in `docs/`
- [ ] For a user-visible change, I've added a `CHANGELOG.md` entry
  under `[Unreleased]`
- [ ] For an architectural change, I've added an ADR under
  `docs/adr/`
- [ ] My commits have descriptive messages
- [ ] I've read `CONTRIBUTING.md` and `MISSION.md`

## Anything else

Open questions, alternatives you considered, follow-ups you'd
like to do in a later PR.
