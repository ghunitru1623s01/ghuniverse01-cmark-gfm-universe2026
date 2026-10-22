# PVR Triage Analysis: GHSA-v5gw-mw7f-84px

Provisional AI assessment. Maintainer review required.

**Advisory repository:** Kludex/starlette  
**Source repository:** Kludex/starlette  
**Advisory:** https://github.com/Kludex/starlette/security/advisories/GHSA-v5gw-mw7f-84px  
**State:** published; historical assessment explicitly authorized by the user  
**Advisory updated:** 2025-08-26T10:32:10Z  
**Claimed severity/type:** Low; CWE-22 path traversal  
**Affected revision:** 0.26.1, `8965f8849977b5752e415722a83aa00049f80ff3`  
**Current revision:** `dc20b216f065af3a487722141da9a29dcac388d1`

## Source Selection

Automatic selection of Kludex/starlette: GitHub identifies the non-fork Starlette framework, its maintained README links to this source, and the affected manifest declares package `starlette`. The historical manifest uses `encode/starlette` URLs, consistent with the advisory's older link. The selected repository contains the exact cited `StaticFiles.lookup_path` behavior at release 0.26.1. Selection is supported independently of the vulnerability verdict.

## Verdict

**Security verdict: CONFIRMED. Code finding: CONFIRMED.**

High confidence from static evidence. A remote unauthenticated requester can escape a public static mount and read an otherwise nonpublic, process-readable sibling file whose resolved path shares the static directory's string prefix. This crosses the intended static-root confidentiality boundary. It is not unrestricted filesystem access: matching-prefix files must exist, permissions must permit reading, and the request must reach ASGI without upstream dot-segment removal. No runtime reproduction was performed; the quality shortcut was not used.

## Code Verification

All citations below belong to Kludex/starlette at the pinned revisions.

At affected SHA `8965f8849977b5752e415722a83aa00049f80ff3`:

- [`starlette/routing.py:386-406`](https://github.com/Kludex/starlette/blob/8965f8849977b5752e415722a83aa00049f80ff3/starlette/routing.py#L386-L406) forwards the mount remainder, retaining `../`.
- [`starlette/staticfiles.py:92-146`](https://github.com/Kludex/starlette/blob/8965f8849977b5752e415722a83aa00049f80ff3/starlette/staticfiles.py#L92-L146) normalizes that remainder, permits GET/HEAD, and serves regular files or HTML indexes. Leading parent components survive normalization.
- [`starlette/staticfiles.py:162-179`](https://github.com/Kludex/starlette/blob/8965f8849977b5752e415722a83aa00049f80ff3/starlette/staticfiles.py#L162-L179) resolves paths but checks string-based `commonprefix`. For root `/srv/static`, `/srv/static1.txt` passes despite being outside the root.
- [`starlette/staticfiles.py:182-197`](https://github.com/Kludex/starlette/blob/8965f8849977b5752e415722a83aa00049f80ff3/starlette/staticfiles.py#L182-L197) constructs FileResponse; [`starlette/responses.py:332-362`](https://github.com/Kludex/starlette/blob/8965f8849977b5752e415722a83aa00049f80ff3/starlette/responses.py#L332-L362) opens the selected file and transmits bytes. GET/HEAD restrictions and filesystem permissions do not enforce static-root containment.

## Severity And CVSS 3.1

Low is reasonable for the constrained confidentiality-only scenario; actual sensitivity depends on exposed files. No integrity or availability impact is demonstrated. The advisory records **CVSS 3.0**, vector `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`, score 3.7. A candidate CVSS 3.1 vector uses the same metrics, reflecting the required filesystem layout. No independently calculated CVSS 3.1 numeric score is asserted.

## Duplicate And Prior Reports

No similar local assessments; the accessible triage inbox contains zero reports, so structural comparison yields no matches and no semantic duplicate can be identified. Published/closed reports and inaccessible reports were not exhaustively checked. Absence of matches does not establish novelty.

## Patch Status

**patched** for this specific bug at recorded HEAD. Release 0.27.0, SHA `0c4b68ac4e179a788e38bac28f299dcad0f36e99`, uses [`commonpath` at staticfiles.py:172](https://github.com/Kludex/starlette/blob/0c4b68ac4e179a788e38bac28f299dcad0f36e99/starlette/staticfiles.py#L162-L179); its [regression test](https://github.com/Kludex/starlette/blob/0c4b68ac4e179a788e38bac28f299dcad0f36e99/tests/test_staticfiles.py#L520-L550) checks both reported sibling patterns. Tests were read, not run. [HEAD staticfiles.py:160-179](https://github.com/Kludex/starlette/blob/dc20b216f065af3a487722141da9a29dcac388d1/starlette/staticfiles.py#L160-L179) retains component-aware containment.

The structured affected range `>=0.13.5` lacks an upper bound, conflicting with patched version 0.27.0 and inspected fixed source. Release 0.26.1 is confirmed affected; the full lower-bound history was not examined.

## Security Policy Compliance

Fetched inherited policy `Kludex/.github:SECURITY.md` asks for the Security-tab reporting channel and a minimal reproducible example. This advisory provides source lines and reproduction details; no supported-version restrictions or relevant exclusions are stated. Reporting/source policies are the same. Current policy is not evidence of the policy in force in 2023.

## Report Quality And History

**High:** file, lines, PoC, structured version information, and example code are present. Correct root cause and patch are corroborated; the affected-range upper bound needs correction. Reporter login is unidentified: structured credit names a coordinator only. Reviewed reporter sample size is zero; no reputation inference is justified.

## Recommendations

Maintainer should review this historical assessment, correct the range to exclude fixed versions after checking release history, and advise affected deployments to use a supported fixed release and assess potential file exposure. No accept/reject action applies to the published advisory. Reply draft: `response.md` beside this report. No GitHub state change or reporter reply has been sent.
