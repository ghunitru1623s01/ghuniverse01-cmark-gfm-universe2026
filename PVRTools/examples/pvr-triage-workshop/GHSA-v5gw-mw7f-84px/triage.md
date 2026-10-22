**Verdict:** CONFIRMED — static evidence supports a feasible directory-containment bypass that exposes files outside the configured static root.

**Code finding:** CONFIRMED — `lookup_path()` checks a character prefix rather than filesystem-path containment, allowing similarly named sibling paths.

**Claim:** An attacker can request `/static/../static1.txt` or `/static/../static_disallow/` to read otherwise nonpublic files beside the configured `static` directory.

**Revision:** `Kludex/starlette`, release `0.26.1`, commit `8965f8849977b5752e415722a83aa00049f80ff3`. This predates the advisory’s listed patched release, `0.27.0`; its structured affected range (`>=0.13.5`) lacks an upper bound.

**Evidence:**
- [`routing.py:386–406`](https://github.com/Kludex/starlette/blob/8965f8849977b5752e415722a83aa00049f80ff3/starlette/routing.py#L386-L406): Mount routing forwards the remaining request path without rejecting `..`.
- [`staticfiles.py:106–111`](https://github.com/Kludex/starlette/blob/8965f8849977b5752e415722a83aa00049f80ff3/starlette/staticfiles.py#L106-L111): Normalization preserves leading parent traversal in the mount-relative path.
- [`staticfiles.py:162–179`](https://github.com/Kludex/starlette/blob/8965f8849977b5752e415722a83aa00049f80ff3/starlette/staticfiles.py#L162-L179): Resolving `static/../static1.txt` escapes the root, but `commonprefix()` still matches the entire root string. Neither realpath resolution nor default symlink handling prevents this.
- [`staticfiles.py:117–146`](https://github.com/Kludex/starlette/blob/8965f8849977b5752e415722a83aa00049f80ff3/starlette/staticfiles.py#L117-L146): Accepted regular files are served; with `html=True`, sibling-directory `index.html` files can also be served. Methods are restricted to GET/HEAD, and permission failures are rejected.

**Impact and limitations:** Confidentiality loss requires a reachable static mount, traversal reaching the application without upstream normalization or rejection, and a readable sibling file/directory whose resolved path shares the static root’s character prefix. No authentication is required unless imposed externally. This is not unrestricted filesystem access, directory listing, or a demonstrated write capability. Deployment-specific exposure is unknown; the PoC was not executed.

**Next action:** Verify the `0.27.0` containment fix and regression coverage for both sibling-file and sibling-directory traversal before closing the report.

Provisional assessment; human review required. No GitHub data was changed.
