# PVR Triage for GitHub Copilot

A Copilot skill for maintainers assessing GitHub Private Vulnerability Reports
(PVRs). Investigate individual advisories, rank an inbox, identify potential
duplicates, and draft responses. GitHub access is read-only: maintainers make
decisions, execute advisory state changes, and send replies.

## Requirements

- GitHub Copilot with skill support, Python 3.10+, and GitHub CLI (`gh`) on PATH.
- GitHub.com access to the private advisory and source repository independently.
  GitHub Enterprise Server is not supported; no local source clone is required.
- A Copilot session approved for restricted data. Advisory text, source excerpts,
  and tool results can enter model context and session logs.

## Install

The supplied skills are already in `.github/skills/`, a discovery location for
Copilot CLI and VS Code. No copying is needed. If explicit CLI registration is
needed, run from the repository root:

```bash
copilot skill add ./.github/skills
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
```
We will only be using the singular advisory triage command for this workshop, though experimental support for batch, respond, and comparison commands are available.

```text
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

Copilot finds and verifies the code repository automatically, asking if the source is unclear.
Use `--source-repo owner/code-repo` to override it; see [discovery details](./references/source-discovery.md).

## Local data and safeguards

- For the supplied workshop data, add `--data-dir ./workshop-results/advanced`
  to your invocation from the repository root. See the
  [participant instructions](../../../README.md#5-try-the-advanced-skill).
- Open the returned `triage.md`, `assessment.json`, and `response.md` paths.
  Results are grouped under the output root by repository and advisory ID.
- For real private reports, use storage outside the checkout. Without an
  override, reports default to `~/.local/state/pvr-triage` (or
  `$XDG_STATE_HOME/pvr-triage` when set). The saved inbox can include other
  private reports; do not commit or publish it.
- Results and reply drafts are provisional. Preserve human edits on reruns;
  a maintainer must review decisions and send replies. Do not execute
  report-provided code as part of triage.

See the [full workflow](./SKILL.md) and [response guidance](./references/responses.md)
for details.