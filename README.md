# cortex9-echo-static-encoded-segment-bypass-model

Offline model of **CVE-2026-118650** (GHSA-375p-5qhx-8wq4): Echo's
`middleware.Static` resolves the file from the decoded `URL.Path` while the
router matches the still-encoded path, so `/admin%2Fsecret.txt` skips an
`/admin` route guard and still reaches `admin/secret.txt` under the static
root. Before (`pre`) and after (`post`) the fix in labstack/echo
[b838391](https://github.com/labstack/echo/commit/b838391e2eade87ae7e5a09d7bb5087bec271ec1)
(v4.16.0) and
[fc41009](https://github.com/labstack/echo/commit/fc410094b2f3415cf2bf5204082137b205bfd5af)
(v5.4.0). Educational, deterministic, Go standard library only. No Echo code
is imported or run, no socket is opened.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## Scope

Both commits are merges that fix several advisories at once (scheme,
JSONP, MethodOverride, redirects, IP extraction). This model only covers the
file-selection hunk of `middleware/static.go`. That hunk fixes two
advisories, and the model keeps them apart:

- **GHSA-375p-5qhx-8wq4 (this CVE):** resolve the file from `RawPath` when
  it is set, the form the router matched (diff:1216-1224, v5diff:1309-1317).
- **GHSA-3pmx-cf9f-34xr (related, same hunk):** do not serve paths with
  `.`, `..` or empty segments, before and after unescaping
  (diff:1225-1238, 1246-1252, 1261-1286).

`diff:N` is line N of the v4 diff, `v5diff:N` of the v5 diff
([SOURCES.md](SOURCES.md)).

## What is modelled

- The request-target is parsed with `url.ParseRequestURI`, which sets
  `Path` and `RawPath` the way `net/http` does.
- Router form: `RawPath` if set, else `Path` (diff:1218-1219, 1278-1279).
- Three layouts: `global` (`e.Use(Static)` and an `/admin` group with
  `GET /*`, diff:1328-1337); `route` (Static as middleware of `GET /*`,
  diff:1380-1392); `global-exact` (the GHSA PoC: `/admin` group with
  `GET /secret.txt`). In global layouts Static runs before route and group
  middleware (diff:1206-1208, v5diff:1299-1301).
- Static root: the union of the diff's test filesystems (diff:1301-1306,
  1355-1359).

Labels: `MISMATCH` (a file under `admin/` is served for a router form
outside `/admin`), `ORDER_BYPASS` (served although the router matched the
guarded route), `SERVED`, `DENIED_403`, `NOT_FOUND_404`, `ERROR_500`,
`BAD_INPUT`.

## What it shows (differential evidence)

| Case | pre | post |
|---|---|---|
| `g01` global, `/admin%2Fsecret.txt` | `MISMATCH`: looks up `admin/secret.txt` from `URL.Path` (diff:1216) | 404: looks up `admin%2Fsecret.txt` from `RawPath` (diff:1222-1224) |
| `g03` global, `/%61dmin/secret.txt` | `MISMATCH` | 404 |
| `g06` global, `/public/../admin/secret.txt` (GHSA-3pmx) | `MISMATCH` | 404, unclean (diff:1227, 1248-1249) |
| `r03` route, `/admin%2Fsecret.txt` | 404: the wildcard param is already the router form | 404 |
| `a02` route, `/admin%2Fsecret.txt`, `EnablePathUnescaping` | `MISMATCH` | `MISMATCH`: documented, not fixed (diff:44, 1184-1185) |
| `x01` GHSA PoC layout, literal `/admin/secret.txt` | `ORDER_BYPASS` | `ORDER_BYPASS` (diff:1206-1208) |

All 19 post-fix statuses of the diff's own tests (diff:1314-1323,
1367-1375) are reproduced. Fixed sweep (`results/sweep.csv`, 784 targets ×
3 layouts × unescaping on/off): 90 `MISMATCH` before the fix (37 with
unescaping off), 13 after. All 13 need `EnablePathUnescaping` and an encoded
`%2F` or letter, with no dot or empty segment. No post-fix result serves an
`admin/` file that pre did not.

**Unverified, not a finding:** in the PoC layout, the model serves the
*literal* path too, because global Static runs before the group guard (as
the fix's own docstring says). The GHSA PoC reports `401` for that request,
and NVD says the source is internally inconsistent on this point. The model
does not settle it. See [LIMITATIONS.md](LIMITATIONS.md).

## Run

```sh
sh scripts/build.sh test                                # gofmt, vet, tests
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
python3 scripts/derive_expected.py sweep | diff - results/sweep.csv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
./build/staticmodel case pre '/admin%2Fsecret.txt' global 0
```

`fixtures/expected.tsv` and the sweep are derived independently in Python
(`scripts/derive_expected.py`). It re-implements the URL parsing, segment
checks and router lookup without reading the Go model, and the Go tests
compare against it.

License: Apache-2.0.
