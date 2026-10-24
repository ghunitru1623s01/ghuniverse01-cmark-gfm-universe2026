# PVR Triage for GitHub Copilot

A Copilot skill for maintainers assessing GitHub Private Vulnerability Reports
(PVRs). Investigate individual advisories, rank an inbox, identify potential
duplicates, and draft responses. GitHub access is read-only: maintainers make
decisions, execute advisory state changes, and send replies.

## Requirements

- GitHub Copilot with skill support, Python 3.10+, and GitHub CLI (`gh`) on PATH.
  The Python helper uses only the standard library and existing `gh` authentication.
- GitHub.com access to the private advisory and source repository independently.
  GitHub Enterprise Server is not supported; no local source clone is required.
- A Copilot session approved for restricted data. Advisory text, source excerpts,
  and tool results can enter model context and session logs.

Repository permissions, organization SSO, and Codespaces token restrictions still
apply. `GH_TOKEN` or `GITHUB_TOKEN` may override a saved `gh` login; never print
tokens to troubleshoot access.

## Install

From the bundled `PVRTools/` directory, with a current Copilot CLI:

```bash
copilot skill add ./skills/pvr-triage
```

Alternatively, copy the complete `pvr-triage` directory to `~/.copilot/skills/`
for personal use or `.github/skills/` in a target repository for project use.
Keep `scripts`, `references`, and `assets` together, and review an existing
installation before replacing it. A generic `skills/` directory alone is not
a Copilot discovery location.

Reload and verify the installation inside an interactive Copilot session:

```text
/skills reload
/skills list
```

If your CLI lacks `copilot skill add`, use the directory layout above and restart
the session. See the [official installation guide](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills).

## Usage

```text
/pvr-triage triage owner/repo GHSA-xxxx-xxxx-xxxx
/pvr-triage batch owner/repo
/pvr-triage respond owner/repo GHSA-xxxx-xxxx-xxxx accept
/pvr-triage respond-batch owner/repo
```

Replace `owner/repo` with the repository receiving reports and the GHSA
placeholder with an accessible advisory ID. An individual advisory URL can
replace those arguments; a repository's security page is not an advisory.

`triage` investigates one report. `batch` ranks the inbox before you select
reports for deeper investigation. `respond` and `respond-batch` prepare proposed
decisions and reply drafts, not automatic acceptance, rejection, or publication.

### Assessment results

Copilot checks affected code at a pinned revision, current patch status,
severity, policy compliance, and duplicate evidence. New assessments separate:

- `verdict`: whether the reported **security vulnerability** is supported.
- `code_finding`: whether the underlying **code behavior** is supported.

Both use `CONFIRMED` (supported), `UNCONFIRMED` (refuted), or `INCONCLUSIVE`
(unresolved). Confirmed code behavior alone does not establish security impact.
Static evidence can suffice; executing a proof of concept is not mandatory.
Missing evidence is not grounds for automatic rejection.

When evidence establishes a non-security issue, the UNCONFIRMED security verdict
explicitly says it is not a security vulnerability in the reported scenario.
The code finding may still be CONFIRMED. Recommend a public issue for a
non-security bug or feature request only after a maintainer checks disclosure
is safe; unresolved security claims stay private and INCONCLUSIVE.

Legacy bundles without `code_finding` remain supported without migration or
relabeling. Reassess older verdicts when needed rather than infer a security
verdict from a code-finding status. See the [full workflow](./SKILL.md) and
[response guidance](./references/responses.md).

### Triage report categories

`triage.md` starts with advisory metadata, repository identities, and examined
revisions, then uses these [report sections](./assets/report-template.md):

| Category | What it covers |
| --- | --- |
| Source Selection | Why the source repository was chosen and any identity or access gaps. |
| Verdict | Separate security and code-finding outcomes, confidence, and limitations. |
| Code Verification | Pinned source evidence, the attack path, preconditions, and existing checks. |
| Validation Results | Approved validation results and limitations; omitted when no supervised validation ran. |
| Severity And CVSS 3.1 | Actual impact, severity rationale, and verified scoring or an explicit scoring limitation. |
| Duplicate And Prior Reports | Related reports, match evidence, differences, and any new information. |
| Patch Status | `still_vulnerable`, `patched`, or `could_not_determine` at the recorded HEAD. |
| Security Policy Compliance | Policy scope, supported versions, requirements, and conflicts; omitted when no policy is accessible. |
| Report Quality And History | Evidence quality and reviewed local reporter history, with small-sample caveats. |
| Recommendations | Specific maintainer actions, open questions, and the reply draft location. |

### Source repository discovery

Reports may be collected in a different repository from the affected code.
Copilot verifies the source using advisory evidence, package identity,
maintained documentation, and pinned source checks before saving a snapshot.
It records the selection and asks only when the evidence cannot establish a
unique source. An explicit `--source-repo` takes precedence:

```text
/pvr-triage triage example-org/reports GHSA-xxxx-xxxx-xxxx --source-repo example-org/project
```

Here, `example-org/reports` receives advisories and `example-org/project`
contains the code. `--repo` scopes advisory APIs, local reports, and reporter
history; `--source-repo` scopes code and revision reads. Both identities and
selection evidence are saved with the assessment. Changing the source requires
refetching and reassessment; an old review cannot be reused.

Discovery uses read-only GitHub.com APIs, not arbitrary linked services or
report-supplied commands. See the [discovery procedure](./references/source-discovery.md)
for verification rules and legacy source metadata handling.

## Local data and safeguards

Data defaults to `~/.local/state/pvr-triage`, or
`$XDG_STATE_HOME/pvr-triage` when set. Override it with `PVR_REPORT_DIR` or
`--data-dir`. Keep private report data outside public checkouts.

For a non-default output root, put `--data-dir /private/report-root` in the skill
invocation itself. The skill must resolve that root once and pass it to every
helper command; it must not replace an environment override with the default.
An explicit helper `--data-dir` takes precedence over `PVR_REPORT_DIR`.

Each `<data-root>/owner/repo/GHSA-xxxx-xxxx-xxxx/` bundle contains the advisory,
repository context, and policies, plus `assessment.json`, `triage.md`, and
`response.md`. Inbox ranking also produces repository-level `inbox.json`,
`ranked.json`, and a Copilot-written `batch_queue.md`.

The inbox reader follows GitHub's `Link`-header cursors, stopping only when no
next page remains. It refuses incomplete results beyond 50 pages or 5,000
advisories. Policy reads use the remote default branch and GitHub's precedence:
`.github/SECURITY.md`, root `SECURITY.md`, then `docs/SECURITY.md`, with the
owner's default community policy used only when none of those is found.
The inherited `OWNER/.github` repository is checked in the same order:
`.github/SECURITY.md`, root `SECURITY.md`, then `docs/SECURITY.md`.

Duplicate comparison examines all pairs for complete structural clusters, but
retains at most 1,000 detailed matches to bound memory growth. Both `compare`
and `rank` disclose total matches, counts by strength, and omitted matches.
Do not treat retained pair evidence as exhaustive.

During triage, `draft-assessment.json`, `draft-triage.md`, and `draft-response.md`
are temporary inputs. `record` removes them from the bundle only after all three
canonical outputs are saved; failures retain them for correction and retry.
Inputs with other names or outside the bundle are not automatically removed.

Before replacing a report bundle, `record` stages all three outputs and backs up
existing files. A failed replacement rolls back the files already replaced,
preserving the prior bundle and its review status. If a filesystem error also
prevents rollback, the command reports the affected files and retains recovery
backups at the reported path; restore those before reusing the bundle.

Generated bundles are provisional. Only a maintainer's interactive `review`
command creates `review.json`; only reviewed bundles affect reporter reputation,
and edits invalidate that review. Preserve human edits and obtain approval
before replacing reviewed or human-edited bundles. Review hashes check integrity,
not identity or authorization.

The helper creates files with mode 0600 and new report directories with mode
0700; these permissions are not encryption. Use read-only GitHub credentials for
analysis. The skill does not provide a sandbox or authorize automatic execution
of untrusted code; see [supervised validation](./references/validation.md).

## Python helper

For direct helper use, run from the `PVRTools/` directory or use an absolute script path:

```bash
python skills/pvr-triage/scripts/pvr.py --help
python skills/pvr-triage/scripts/pvr.py --repo example-org/reports \
  --source-repo example-org/project fetch GHSA-xxxx-xxxx-xxxx
```

Global options precede the command. Direct Python calls do not discover sources:
without `--source-repo`, code reads default to `--repo`. Supply the selected
source on every later source read and `fetch` refresh.

Use `COMMAND --help` for arguments, [scoring rules](./references/scoring.md)
for ranking and duplicate logic, and [SKILL.md](./SKILL.md) for the workflow.
The helper has no GitHub write commands, and Copilot must not simulate
interactive maintainer review.

GitHub subprocess output is decoded as UTF-8 regardless of the host locale.
Saved-assessment similarity checks treat null optional vulnerability/component
metadata as missing text, without rewriting the stored assessment.