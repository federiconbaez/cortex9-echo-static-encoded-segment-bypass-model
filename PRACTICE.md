# Guía práctica (8 niveles)

Ejercicios **offline y locales**. Úsalos solo con este modelo o en tus
propios laboratorios: máquinas de HTB que te corresponda atacar, o una app
Echo que levantes tú en `localhost`. Nunca contra sistemas de terceros. Cada
respuesta está comprobada en `tests/model_test.go` (`TestPracticeLevels`).

Comandos: `sh scripts/build.sh test`. Después de `sh scripts/build.sh
results /tmp/r`, puedes usar `./build/staticmodel case pre|post <ruta>
global|global-exact|route 0|1`.

**Básico**

1. **Servir un archivo público.** `/public/index.html` con mount global.
   (nivel 1: `SERVED`)
2. **La forma del router.** `/admin%2Fsecret.txt`: ¿qué ruta compara el
   router y qué route elige? (nivel 2: `/admin%2Fsecret.txt`, `none`)

**Intermedio**

3. **El desajuste.** Misma ruta en `pre`: ¿desde qué campo busca Static el
   archivo? (nivel 3: `URL.Path`, diff:1216, `MISMATCH`)
4. **El fix.** Misma ruta en `post`. (nivel 4: 404, porque busca desde
   `RawPath`, diff:1221-1224)
5. **El mount por ruta.** La misma ruta con `route` en `pre`. ¿Por qué ya
   era 404? (nivel 5: el parámetro `*` ya viene en la forma del router)

**Avanzado**

6. **El advisory vecino.** `/public/../admin/secret.txt` en `post`. ¿Qué
   advisory lo cubre y qué líneas? (nivel 6: `!unclean`, GHSA-3pmx,
   diff:1227 y 1248-1249)
7. **El residuo documentado.** `/admin%2Fsecret.txt`, `route`, con
   `EnablePathUnescaping` en `post`. (nivel 7: `MISMATCH`. Está documentado
   en diff:44 y 1184-1185, no es un hallazgo)
8. **El orden de los middleware.** `/admin/secret.txt` con `global-exact`.
   ¿Por qué el modelo lo sirve si la PoC dice 401? (nivel 8: `ORDER_BYPASS`;
   **no verificado**, ver LIMITATIONS.md)

Más allá, en tu laboratorio local, levanta la app mínima de la PoC del GHSA
solo en `localhost` con v4.15.4 o v5.3.1 y con la versión corregida, y
compara con las filas `g01`, `x01` y `x02`. Anota lo que difiera en
LIMITATIONS.md antes de sacar conclusiones. Para practicar con el modelo,
añade un caso a `fixtures/cases.tsv`, regenera `fixtures/expected.tsv` con
`scripts/derive_expected.py` y comprueba que el modelo en Go coincide.
