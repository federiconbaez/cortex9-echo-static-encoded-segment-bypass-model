# cortex9-echo-static-encoded-segment-bypass-model

Modelo offline de **CVE-2026-118650** (GHSA-375p-5qhx-8wq4). El
`middleware.Static` de Echo resuelve el archivo desde el `URL.Path`
decodificado, mientras que el router compara la ruta todavía codificada. Así,
`/admin%2Fsecret.txt` esquiva el guard de la ruta `/admin` y aun así llega a
`admin/secret.txt` dentro de la raíz estática. Se modela antes (`pre`) y
después (`post`) del fix en labstack/echo
[b838391](https://github.com/labstack/echo/commit/b838391e2eade87ae7e5a09d7bb5087bec271ec1)
(v4.16.0) y
[fc41009](https://github.com/labstack/echo/commit/fc410094b2f3415cf2bf5204082137b205bfd5af)
(v5.4.0). Es educativo y determinista, y usa solo la biblioteca estándar de
Go. No se ejecuta código de Echo y no se abre ningún socket.

## Alcance

Los dos commits son merges que corrigen varios advisories a la vez. El
modelo solo cubre el hunk de selección de archivo de `middleware/static.go`,
que corrige dos advisories, y los separa:

- **GHSA-375p-5qhx-8wq4 (este CVE):** resolver desde `RawPath` si existe
  (diff:1216-1224, v5diff:1309-1317).
- **GHSA-3pmx-cf9f-34xr (relacionado, mismo hunk):** no servir rutas con
  segmentos `.`, `..` o vacíos, antes y después de decodificar
  (diff:1225-1238, 1246-1252, 1261-1286).

## Qué muestra

| Caso | pre | post |
|---|---|---|
| `g01` global, `/admin%2Fsecret.txt` | `MISMATCH`: busca `admin/secret.txt` desde `URL.Path` (diff:1216) | 404: busca `admin%2Fsecret.txt` desde `RawPath` (diff:1222-1224) |
| `g06` global, `/public/../admin/secret.txt` (GHSA-3pmx) | `MISMATCH` | 404, unclean (diff:1227, 1248-1249) |
| `r03` route, `/admin%2Fsecret.txt` | 404 | 404 |
| `a02` route con `EnablePathUnescaping` | `MISMATCH` | `MISMATCH`: documentado y sin corregir (diff:44, 1184-1185) |
| `x01` layout de la PoC, ruta literal | `ORDER_BYPASS` | `ORDER_BYPASS` (diff:1206-1208) |

Se reproducen los 19 estados post-fix de los tests del propio diff. En el
barrido (`results/sweep.csv`, 4704 filas) hay 90 `MISMATCH` antes del fix y
13 después. Los 13 requieren `EnablePathUnescaping` y un `%2F` o una letra
codificada, sin segmentos de punto ni vacíos.

**No verificado, no es un hallazgo:** en el layout de la PoC, el modelo
también sirve la ruta *literal*, porque el Static global corre antes del
guard del grupo (lo dice el propio docstring del fix). La PoC del GHSA
reporta `401` para esa petición, y NVD señala que la fuente es
inconsistente en ese punto. Ver [LIMITATIONS.md](LIMITATIONS.md).

## Uso

```sh
sh scripts/build.sh test
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
python3 scripts/derive_expected.py sweep | diff - results/sweep.csv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
./build/staticmodel case post '/admin%2Fsecret.txt' global 0
```

Ejercicios en [PRACTICE.md](PRACTICE.md); límites en
[LIMITATIONS.md](LIMITATIONS.md); fuentes en [SOURCES.md](SOURCES.md).
Licencia: Apache-2.0.
