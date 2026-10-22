Thank you for documenting this issue. Our source review confirms that Starlette 0.26.1 uses a string-prefix check in StaticFiles.lookup_path, allowing a request containing parent-directory components to select process-readable files outside the configured static root when their paths share its prefix. This can disclose nonpublic sibling files when the request reaches the application without upstream path normalization.

Release 0.27.0 uses a component-aware commonpath check, and the current source retains that protection. This assessment is based on static inspection, not runtime reproduction.

The published advisory's structured affected range is currently ">=0.13.5", which also includes the stated patched release. Please clarify the intended upper bound so that the affected-version metadata excludes fixed versions.
