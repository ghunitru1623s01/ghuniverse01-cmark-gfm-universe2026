# Scoring And Evidence Rules

## Inbox Priority

Priority is an intake heuristic, not CVSS, exploitability, or verified severity.

| Claimed severity | Weight |
| --- | ---: |
| critical | 4 |
| high | 3 |
| medium | 2 |
| low or unknown | 1 |

Add one each for a cited file path, reproduction steps/PoC, and line numbers.
Maximum score: 7. The helper requires all three fields to be JSON booleans;
missing keys, numeric booleans, and strings such as `"false"` are errors.

| Score | Suggested action |
| --- | --- |
| 5-7 | Triage Immediately |
| 3-4 | Triage Soon |
| 2 | Triage |
| 1 | Likely Low Quality -- Request Details |

A bare critical report scores 4, not 7. Scores are sorted descending, with
oldest `created_at` first for ties. Missing dates show unknown age and sort last
within their score. A saved assessment is skipped only if its source advisory
timestamp and selected source repository still match. `rank` uses an explicit
`--source-repo` or the mapping saved by `inbox`; legacy inboxes default to the
advisory repository. A different code target must be assessed again. Updating
source code without changing the advisory
does not invalidate this cache: re-triage to refresh patch status when needed.

For `rank --signals FILE`, the file is an object like:

```json
{
  "GHSA-xxxx-xxxx-xxxx": {
    "has_file_references": true,
    "has_poc": false,
    "has_line_numbers": true
  }
}
```

For `score --signals FILE`, provide the inner three-field object instead.
Presence measures specificity only. A nonexistent filename still needs
verification and may later lower the report's quality rating.

## Fast-Close Candidate

The original taskflow's reputation matrix is preserved as a recommendation:

| Reputation | No signals, no prior | No signals, prior similar | Any signal |
| --- | --- | --- | --- |
| high trust | Verify | Verify | Verify |
| normal / no history | Verify | Shortcut candidate | Verify |
| treat with skepticism | Shortcut candidate | Shortcut candidate | Verify |

The prior must be a different, similar advisory in the same reporting repository
about the same selected source repository, with a
reviewed CONFIRMED or UNCONFIRMED security verdict. A confirmed `code_finding`
with an INCONCLUSIVE `verdict` does not qualify. Inspect older verdicts' scope
and reassess before treating a code-only conclusion as a security verdict.
Substring similarity alone may be
spurious: inspect whether it actually concerns the same component or issue.
Duplicates do not independently trigger the shortcut. Version information and
code snippets influence the quality assessment but are not shortcut signals.

Unlike the original, this skill defaults to full verification even for
candidates. Only an explicitly requested shortcut policy permits skipping it.
A skipped report remains INCONCLUSIVE and asks for the missing evidence. The
candidate flag never means the advisory should be automatically closed.

## Reporter History

Only human-reviewed bundles in the same advisory repository contribute. Reporter login
is case-normalized; unidentified reporters use null and contribute no shared
history. Re-running a GHSA replaces its local assessment rather than counting
another report. Changing any reviewed assessment/report/reply invalidates the
review digest, removing it from reviewed history until re-reviewed. Changing a
bundle's selected source repository also prevents reuse of the old review.
The confirmed fraction uses the security `verdict`, never `code_finding`.

- High trust: confirmed fraction >= 0.60 and Low-quality fraction <= 0.20.
- Treat with skepticism: confirmed fraction <= 0.20 or Low-quality fraction >= 0.50.
- Normal: other nonempty histories. No history: no reviewed records.

These are the original thresholds, without statistical calibration or a minimum
sample size. A single reviewed result can change a label. Always show the sample
size and do not treat a local history label as a GitHub-wide reputation score.
Review hashes detect edits; they are not cryptographic proof of reviewer identity.

## Duplicate Detection

`compare` reads the cached inbox from `inbox`. Fingerprints use nonempty CWE IDs,
ecosystem/package names, exact version-range strings, source file paths, and
normalized summaries. Version strings are not evaluated as semver intervals.

- Strong: same package plus a shared CWE, file, or version string.
- Moderate: same package alone, or a shared CWE and file.
- Weak: any other structural overlap, including an identical normalized summary.
- None: insufficient shared metadata, not proof of distinct vulnerabilities.

Only strong edges join clusters, transitively. All pairs are examined for
clustering and counted by strength, but only the first 1,000 matching pairs in
input order retain detailed evidence. `total_matches`, `match_counts`,
`omitted_matches`, and `matches_truncated` describe that limit in both `compare`
and `rank` output. Always disclose omitted evidence; a retained sample is not
an exhaustive duplicate review. A transitive cluster
may contain different bugs, so review pairwise evidence. Semantic comparison is
the model's separate, labelled judgment from actual descriptions and code paths.
An advisory inbox can contain reports for different codebases; do not assume
that a shared reporting repository or a batch source selection proves identity.
Never infer a duplicate from who the reporter is.