# Maintainer Responses

The helper and skill do not change GitHub data. `respond` and `respond-batch`
prepare a reviewed handoff instead of reproducing the original write-back
agent. There is intentionally no helper `accept`, `reject`, or `comment` command.

## Recommended Disposition

For incoming reports still in `triage`, give a provisional maintainer recommendation:

| Security verdict | Recommendation |
| --- | --- |
| CONFIRMED | Recommend accepting for security handling if in scope and not already handled. |
| UNCONFIRMED | Recommend rejecting the reported security scenario, citing disconfirming evidence at the affected revision. |
| INCONCLUSIVE | Request the specific missing evidence; defer acceptance or rejection. |

Use the security verdict, not `code_finding`: an incorrect code explanation can
still reveal a real vulnerability. Handle duplicates under the existing report;
retain historical validity when already fixed; distinguish policy-based routing
for out-of-scope findings from technical validity. None alone makes a finding false.
For established non-security expected behavior with no bug or feature request,
explain or link documentation rather than suggesting a public issue.

## Before Preparing A State Change

1. Confirm the advisory repository, GHSA, and action with the maintainer.
   An assessment request is not approval to accept or reject a report.
2. Read the saved assessment, triage report, and response draft. Resolve missing
   evidence and preserve human edits. A candidate or low-quality rating alone
   does not justify rejection. For inconclusive reports, recommend a request
   for specific missing information without changing state. Use the security
   `verdict`, not `code_finding`, when preparing the decision. If an older verdict
   referred only to code behavior, reassess rather than silently reinterpreting it.
3. Keep `--repo` set to the advisory repository. Read `source_repo` from the
   saved assessment and verify it matches `context.json`; for legacy bundles
   without that metadata, source defaults to the advisory repository. Do not
   reinterpret an old assessment using a different source. Read the saved
   `source_selection` evidence when available; response preparation uses the
   assessed source rather than silently running discovery again. If new facts
   undermine that selection, return to triage instead of reusing its verdict.
   Run the helper's
   `status GHSA`. Require live state `triage` for an incoming
   PVR accept/reject handoff and compare `updated_at` with `source_updated_at`.
   If the report changed, re-assess it before preparing the command. Use
   `--source-repo` with the saved code repository for `resolve --ref HEAD` and
   any source reads. Refresh patch claims if that SHA differs from `head_sha`.
4. Present the specific decision, evidence, response text, and exact effect.
   A maintainer may mark the local bundle reviewed by running the following
   in their own interactive terminal after inspecting all three files:
   ```bash
   python "$PVR_HELPER" --data-dir "$DATA_DIR" --repo "$REPO" review "$GHSA"
   ```
   The command requires an exact typed confirmation and refuses noninteractive
   input. Do not run it for the maintainer, pipe approval into it, or edit
   `review.json` to simulate approval. Local review is not GitHub acceptance.
5. Supply the appropriate command below, with the validated literal **advisory
   repository**, never the code repository, and GHSA substituted. The maintainer
   executes it themselves. Do not call the
   command using a tool, even if a broad shell permission has been granted.

Accept a triage report into a draft advisory:

```bash
gh api --hostname github.com --method PATCH \
  /repos/OWNER/REPO/security-advisories/GHSA-ID -f state=draft
```

Reject a triage report by closing it:

```bash
gh api --hostname github.com --method PATCH \
  /repos/OWNER/REPO/security-advisories/GHSA-ID -f state=closed
```

Accepting does not establish an agreed severity, publish an advisory, create a patch, or notify the reporter
with the draft response. Never use `gh issue comment` for a GHSA. This skill does
not automate advisory comments: the maintainer posts the reviewed draft in the
advisory's discussion UI at
`https://github.com/OWNER/REPO/security/advisories/GHSA-ID`.

After the maintainer reports completion, use `status` to verify the actual
state. Refresh the cached advisory with `fetch` when appropriate so subsequent
`pending` output reflects it, retaining the saved `--source-repo` selection.
Never label a reply sent merely because state
changed. There is no misleading `response_sent` marker in this port.

## Bulk Handoffs

Run `pending` for the specified advisory repository only. Its entries include
each assessment's source repository and reflect cached
triage state and may be stale. Recheck live status and review each selected
bundle independently; code HEAD may belong to a different source for each
entry. Show a table of GHSA, source repository, verdict, reviewed/stale status,
proposed action, and reply path. Skip already-transitioned advisories, unknown
states, stale evidence, and unreviewed decisions. Do not generate an executable
loop applying a uniform action to every pending report.

## Response Drafts

Use direct, respectful plain text, normally fewer than 200 words, without
Markdown headings. Replace bracketed portions only with supported facts:

Choose wording from the security verdict, not the code-finding status. Acknowledge
a verified code defect without implying that its claimed security impact is
confirmed. Distinguish source verification from runtime reproduction.

When evidence establishes a non-security issue, say so explicitly rather than
calling it a valid vulnerability or asking for another PoC by default. Recommend
the public issue tracker only for non-security bugs or feature requests after
a maintainer confirms disclosure is safe. Never copy private report details into
a public issue or post one automatically. Do not redirect unresolved security
claims to public issues: missing evidence remains INCONCLUSIVE.

**Confirmed:** "Thank you for reporting this. Our initial review found
[attacker-controlled path] in [affected revision/path] crosses [security boundary]
and causes [supported impact] under [necessary preconditions].
[Verified current patch status, if known.] [An authorized next step, or a request
to clarify a remaining detail.]"

**Unconfirmed / non-security:** "Thank you for the report. At [revision],
[path/lines] shows [specific behavior]. This is not a security vulnerability in
the reported scenario because [specific evidence ruling out the security
violation]. [When appropriate and cleared for disclosure: Please submit this
non-security bug or feature request as a public issue in the project's issue
tracker instead.]"

**Inconclusive / shortcut:** "Our source review [supports specific code behavior /
remains incomplete]. We cannot establish [the reported security scenario] because
[specific missing precondition, impact evidence, or access limitation]. Please
provide [the exact information or controls needed to resolve that gap]."

Do not call a reporter untrustworthy, accuse them of using AI, quote their
reputation score, disclose another private report, or promise a fix or credit
arrangement the maintainer has not approved.