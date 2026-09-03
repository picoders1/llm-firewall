# Git history rewrite — commit identity mapping

On **2026-08-22** the `main` branch was rewritten with `git filter-branch` to strip a
`Co-Authored-By:` trailer from commit messages. The rewrite touched the **last 18 commits**
of a 48-commit history; the 30 commits before it, including the root commit `a0e2a8d`, are
unchanged.

This file exists because this project's central claim is that every figure cites a
**committed artefact**. The rewrite changed commit *identities*, so citations written before
it named SHAs that a fresh clone cannot resolve. That made the one claim the project makes
about itself the one claim that did not reproduce.

## What the rewrite did and did not change

Verified by comparing each pre-rewrite commit with its successor:

| Property | Result |
|---|---|
| Tree (repository state) | **Identical for all 18** — `git diff <old> <new>` is empty in every case |
| Parent lineage | Preserved, in order |
| Author, committer, dates | Byte-identical |
| Message subject | Byte-identical |
| Message body | **`Co-Authored-By:` trailer removed** — the only difference |

Because every tree is identical, a new SHA denotes **exactly the repository state its
predecessor denoted**. Updating a citation from an old SHA to its successor therefore
preserves the factual meaning of the evidence rather than restating it.

Reproduce the check for any row:

```bash
git diff <old> <new>          # empty — same tree
git cat-file commit <old> | diff - <(git cat-file commit <new>)   # trailer only
```

## Mapping

Pre-rewrite SHAs survive locally under `refs/original/refs/heads/main`, which
`filter-branch` wrote as a backup. **Those refs are not pushed and are absent from a clone**,
so the right-hand column is the one to use in any new citation.

| Pre-rewrite | Current (reachable) | Subject | Tree |
|---|---|---|---|
| `8e03e1b` | `95c1aec` | fix main CI concurrency for release validation | identical |
| `76d6fad` | `5d528c0` | point the CI readiness probe at the port compose actually publishes | identical |
| `3adc8eb` | `23274df` | fix first-occurrence alerting and operational runbook gaps | identical |
| `72f2be7` | `6f4a3f1` | fix upstream error metric accounting | identical |
| `b2af81c` | `dd8298b` | pre-register Run 3 fault injection and amend it with Phase 1 evidence | identical |
| `9cc191d` | `c795508` | add Run 3 fault-injection fixtures, isolated from production | identical |
| `3114fb9` | `c1cbf6e` | fix audit failure metric accounting and update ADR verification | identical |
| `8e3ad87` | `4c0993b` | add a sustained fault-mixing mode to the shadow driver | identical |
| `e016cf4` | `a391d3f` | record Phase 20 Run 3 alert validation and runbook walk evidence | identical |
| `8b3a583` | `032be99` | reconcile Run 3 evidence into the risk register, ADRs and readiness matrix | identical |
| `22f6833` | `41ffb1e` | fail readably when the audit database is unreachable | identical |
| `746209d` | `49ee744` | record R-112 resolved and close F6 | identical |
| `4ea30a8` | `88aa677` | record a console label that overstates a detector's capability | identical |
| `6c3d8f0` | `b0ab5cc` | surface an upstream error as an error whatever status it carries | identical |
| `9f97b3b` | `b38923b` | record R-114 | identical |
| `3f92003` | `86d6e66` | make policy_version identify a policy (R-115) | identical |
| `54239f0` | `8502eb9` | make the console render, and make it navigable | identical |
| `9e2e744` | `1b98818` | restructure the README and keep local tooling out of the repository | identical |

## Tag

`v1.0.0-rc1` is an annotated tag. It was re-pointed by the rewrite and **is reachable from
`main`**:

| | |
|---|---|
| Tag object | `8b6df6d` |
| Commit | `5d528c0` — *"point the CI readiness probe at the port compose actually publishes"* |
| Pre-rewrite commit | `76d6fad` (backup ref only) |

## Citations deliberately left at the pre-rewrite SHA

Three classes of reference name a SHA that an **external system** recorded. Rewriting those
would falsify the record rather than repair it, so they keep the original value and are
resolved through the table above:

| Reference | Why it is not rewritten |
|---|---|
| `docs/release-ci-evidence.md`, `docs/release-checklist.md` — GitHub Actions run `32501090591` and artefact `release-evidence-76d6fadc604…` | GitHub executed against, and named its artefact after, the pre-rewrite SHA. That is what the remote holds |
| `eval/results/shadow/**/report.md` | Frozen evidence artefacts. They record the baseline as it was identified at run time; editing them would rewrite a completed experiment's record (the same rule that governs frozen corpora) |

Both remain accurate statements about the past. The trees are identical, so the run and the
reports describe the state now reachable at the mapped SHA.
