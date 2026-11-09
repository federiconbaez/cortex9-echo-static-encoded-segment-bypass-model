# Sources

Local copies under `security-research-45/sources/cve2026/` (not in this
repo), fetched read-only; the NVD response carries the timestamp
2026-11-09T10:27:34 (UTC). Each SHA-256 below was checked against
`sources/cve2026/SHA256SUMS` before use.

| Source | URL | Commit | Used for | SHA-256 of copy |
|---|---|---|---|---|
| v4 fix diff `CVE-2026-118650_echo_b838391e2ead.diff` (20 files, +1307/-62, "Merge commit from fork") | https://github.com/labstack/echo/commit/b838391e2eade87ae7e5a09d7bb5087bec271ec1 | b838391e2eade87ae7e5a09d7bb5087bec271ec1 (2026-09-27T22:25:02Z, v4.16.0) | `middleware/static.go` diff:1163-1286 (cited: 1184-1185, 1206-1208, 1216-1238, 1246-1252, 1261-1286); tests diff:1296-1404 (cited: 1301-1306, 1314-1323, 1328-1337, 1355-1359, 1367-1375, 1380-1392); CHANGELOG diff:18, 44 | 8595ff8ca1f379ccae0a5fd2ffc936b45049fbeee90fe8339cb8e9aa222e1340 |
| v5 fix diff `CVE-2026-118650_echo_fc410094b2f3.diff` (22 files, +1333/-84) | https://github.com/labstack/echo/commit/fc410094b2f3415cf2bf5204082137b205bfd5af | fc410094b2f3415cf2bf5204082137b205bfd5af (2026-09-27T22:25:02Z, v5.4.0) | same logic in v5 `middleware/static.go`: v5diff:1299-1301, 1309-1331, 1339-1345, 1357-1379 | c282d94eec787a7dd2dc7c5417343c6d2306d89280aaf4ce6262d682521c66cc |
| GHSA record `ghsa_rec/CVE-2026-118650.json` | https://github.com/advisories/GHSA-375p-5qhx-8wq4 (repo advisory: https://github.com/labstack/echo/security/advisories/GHSA-375p-5qhx-8wq4) | references both commits | affected/fixed versions (v4 < 4.16.0, v5 < 5.4.0), CWE-177 and CWE-863, root cause, PoC layout | 0a6cfb2a2453676c4416609a8999e491e5f363223ab3d202e4e113919e28bc62 |
| NVD record `nvd/CVE-2026-118650.json` (Undergoing Analysis, published 2026-10-28) | https://nvd.nist.gov/vuln/detail/CVE-2026-118650 | references both commits | description, including the note that the source is internally inconsistent about the guard in the global-mount layout | 5460d5c7778a2b8f26a15b724b99645898f93ebc903ded0a671b6789e205fbe3 |

Other advisories named in the diffs (GHSA-3pmx-cf9f-34xr and those for
scheme, JSONP, MethodOverride, redirects and IP extraction) are cited only as
they appear in the diff text. Their own records were not downloaded.

Go standard library behaviour (`net/url` `ParseRequestURI`, `PathUnescape`;
`path.Clean`) is used as shipped with the Go toolchain named in `go.mod`.

No source contained instructions addressed to a tool or agent.
