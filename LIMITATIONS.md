# Limitations

- **A model is not a finding.** Nothing here was run against Echo. The
  labels describe the model, built from the saved diffs, the GHSA and NVD
  text and the Go standard library.
- **The commit mixes advisories.** b838391 and fc41009 are merges that also
  fix scheme detection, JSONP, MethodOverride, redirects and IP extraction.
  Only the file-selection hunk of `middleware/static.go` is modelled. That
  hunk also carries GHSA-3pmx-cf9f-34xr (dot and empty segments), which the
  model reports apart from this CVE. The `echo_fs.go` / `StaticDirectoryHandler`
  changes (diff:441-534) are **not** modelled.
- **Reconstructed code.** The router (route patterns, wildcard param taken
  from the router form without unescaping, the `c.Path()` of an unmatched
  request), the name computation between hunks (`path.Clean` on a rooted
  path, after the comment at diff:1240-1241), directory and index handling, HTML5 mode,
  `Skipper`, `Root` and the error handler (`ERROR_500`) are reconstructed or
  left out. Only the post-fix statuses of the diff's tests check them.
- **Not verified: guard ordering in the global mount.** The model follows
  the fix's own docstring (diff:1206-1208, v5diff:1299-1301): global Static
  runs before group middleware. In the GHSA PoC layout it therefore serves
  the literal `/admin/secret.txt` (`ORDER_BYPASS`), while the GHSA PoC
  reports `401`. NVD calls the source internally inconsistent on this
  point. The model does not settle it.
- **Documented residual.** With `EnablePathUnescaping`, encoded slashes are
  still decoded after the fix (`a02`, `a04`, 13 sweep rows). The CHANGELOG
  (diff:44) and the docstring (diff:1184-1185) document this. It is not
  presented as a finding.
- **Filesystem.** A fixed in-memory set of five files. No OS filesystem is
  used, there are no symlinks, and Windows separators are not modelled
  (CVE-2026-25766, named in the GHSA, is a different issue).
- **Input domain:** origin-form targets of at most 512 characters made of
  `A-Za-z0-9-._~/%`. Anything else is `BAD_INPUT`. Queries are not modelled.
- **Sweep:** `results/sweep.csv` is a fixed grid, not a proof.
- Nothing is attributed beyond the commits, GHSA and CVE listed in
  SOURCES.md.
