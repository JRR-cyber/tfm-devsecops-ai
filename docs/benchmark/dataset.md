# Dataset experimental (Paso 1.3)

Este documento describe cómo se construye el conjunto de vulnerabilidades sobre el que se evalúa el pipeline en la Fase 5: qué fuentes se usan, qué criterios de selección se aplican y cuántos casos supera cada uno.

**Resultado.** El dataset tiene dos conjuntos complementarios, ambos construidos sobre hallazgos de CodeQL con traza de taint completa:

- **Remediación** ([`benchmarks/dataset.csv`](../../benchmarks/dataset.csv)): 33 vulnerabilidades confirmadas (30 de SecBench.js y 3 de Juice Shop), para medir la tasa de éxito de la remediación (RSR).
- **Triaje** ([`benchmarks/triage/labels.csv`](../../benchmarks/triage/labels.csv), §5.1): 47 grupos etiquetados como verdadero positivo, falso positivo o indeterminado (17 TP de Juice Shop —14 de ellos nuevos—, 16 FP y 4 indeterminados de Juice Shop; 6 FP y 4 indeterminados de SecBench.js), para medir la tasa de falsos positivos (FPR) y la aportación de la traza. Toda etiqueta se respalda con evidencia ejecutable.

## 1. Decisión de fuentes

La hoja de ruta v1 proponía como dataset complementario Big-Vul o PrimeVul, y el OWASP Benchmark en la Fase 5. Ninguno sirve para este proyecto:

| Fuente | Lenguaje | Motivo del descarte |
|---|---|---|
| Big-Vul | C/C++ | Lenguaje distinto al del pipeline (JavaScript/TypeScript). Son funciones sueltas, sin build ni tests. |
| PrimeVul (Ding et al., ICSE 2025) | C/C++ | Igual que Big-Vul. |
| OWASP Benchmark | Java | Lenguaje distinto al del pipeline. |

El bucle de reparación de la Fase 4 necesita, para cada vulnerabilidad, código que se pueda re-escanear y un oráculo ejecutable que diga si el parche es válido. Los datasets de funciones de C/C++ no cumplen ninguna de las dos condiciones.

Se usan dos fuentes JavaScript/TypeScript que se complementan:

| Fuente | Qué aporta | Clases de vulnerabilidad |
|---|---|---|
| **OWASP Juice Shop v20.2.0** (`src/app/juice-shop/`) | Una aplicación web realista, con correcciones de referencia para sus retos de código (`data/static/codefixes/`). | SQLi, NoSQLi, XSS, open redirect, control de acceso, exposición de información… |
| **SecBench.js** (Bhuiyan et al., ICSE 2023) | CVEs reales de paquetes npm, cada uno con un **exploit y un oráculo ejecutables** que confirman si una versión es explotable. | Inyección de código, inyección de comandos, path traversal, prototype pollution, ReDoS |

Las clases no se solapan: Juice Shop cubre las vulnerabilidades típicas de aplicación web y SecBench.js las de librería de servidor.

## 2. Criterios de selección

Los mismos criterios de detección (C7, C8) se aplican a las dos fuentes. Los criterios C1–C6 son propios de SecBench.js.

| Criterio | Tipo | Definición |
|---|---|---|
| C1 | estático | El caso tiene un identificador CVE (trazabilidad con un advisory público). |
| C2 | estático | Existe una corrección de referencia: commit de corrección o versión corregida publicada. |
| C3 | estático | El *sink* está en el código del propio paquete (no en una dependencia) y el caso usa un solo paquete. |
| — | muestreo | Muestra estratificada: hasta 25 casos por clase, un caso por paquete, semilla `20260930`. |
| C4 | dinámico | Consistencia: el paquete del caso es uno de los que OSV asocia al CVE (siguiendo los alias GHSA). |
| C5 | dinámico | El exploit funciona contra la versión vulnerable. |
| C6 | dinámico | El exploit **falla** contra la versión corregida, es decir, el oráculo distingue código vulnerable de código corregido. |
| — | unicidad | Un caso por CVE. |
| C3b | estático | *Sink* abordable: el *sink* se localiza en un archivo fuente legible del paquete (ni minificado ni generado). Es el requisito de la hoja de ruta de que el caso "afecte a un único archivo abordable por el LLM". |
| C7 | escaneo | Detección: Semgrep o CodeQL reportan un hallazgo junto al *sink* (±10 líneas en SecBench.js, ±3 líneas de las marcas `vuln-line` en Juice Shop), con una regla etiquetada con una CWE de la clase. |
| C8 | escaneo | **Traza completa**: alguno de esos hallazgos trae una traza de taint (`codeFlows`) de dos o más pasos, es decir, con fuente y *sink* distintos. |

**Por qué C8.** El triaje híbrido de la Fase 3 inyecta la traza fuente → propagación → *sink* en el prompt del LLM. Un hallazgo sin traza no aporta al LLM nada más que la línea del *sink*, así que no permite evaluar la arquitectura. En la práctica, C8 equivale a "CodeQL da la traza": Semgrep OSS no publica trazas sin sesión en su plataforma comercial ([`pipeline.md`, sección 4](../architecture/pipeline.md)).

**Por qué C7 exige la CWE.** Contar cualquier hallazgo cercano al *sink* sobreestima la detección. Por ejemplo, en `serve-here.js` y `tinyserver2` Semgrep dispara una regla de "servidor HTTP sin TLS" en la misma línea que el path traversal, sin haberlo detectado.

C7 y C8 se calculan sobre el SARIF unificado del pipeline de CI (`unified/findings.sarif`), es decir, con las mismas herramientas y versiones que verá el agente.

## 3. Juice Shop

Inventario: [`benchmarks/juice-shop/inventory.csv`](../../benchmarks/juice-shop/inventory.csv). Detección: [`benchmarks/juice-shop/detection.csv`](../../benchmarks/juice-shop/detection.csv).

La unidad de medida es la **vulnerabilidad**, no el reto. Varios retos comparten un mismo fragmento vulnerable; por ejemplo, `routes/login.ts` agrupa tres retos pero es una única inyección SQL. Contar retos inflaría la N de la Fase 5.

| Paso | Resultado |
|---|---:|
| Retos con corrección de referencia | 35 |
| Vulnerabilidades distintas (fragmentos marcados con `vuln-code-snippet`) | 23 |
| Candidatas (defecto de código en JS/TS) | 13 |
| C7 (detectadas) | 4 |
| **C8 (con traza)** | **3** |

Excluidas del inventario: rutas del cliente (2), diseño de preguntas de seguridad (1), prompt injection de LLM (2), secreto en IaC (1), imagen Docker (1), Solidity (3). El secreto en Terraform (JS-19) y la imagen Docker vulnerable (JS-20) quedan fuera del conjunto de *remediación*, pero se usan como ground truth para TruffleHog y Trivy.

Las tres con traza son las inyecciones SQL de `login.ts` y `search.ts` y la NoSQL de `updateProductReviews.ts`. El *directory listing* de `server.ts` (JS-08) lo detecta Semgrep, pero sin traza. Las otras nueve candidatas (XSS en plantillas de Angular, control de acceso, mass assignment, política de contraseñas…) son defectos de lógica o de configuración que ninguna regla de los dos escáneres modela.

## 4. SecBench.js

SecBench.js no tiene licencia, así que sus exploits **no se copian** a este repositorio: el arnés los descarga de un commit fijo (`5d362353550a8baa42bba34edd26e5fb86d41b60`). Solo se versiona el código de los paquetes npm afectados, que tienen su propia licencia y la conservan.

Archivos:
- [`catalog.csv`](../../benchmarks/secbench-js/catalog.csv): C1–C3.
- [`candidates.csv`](../../benchmarks/secbench-js/candidates.csv): la muestra.
- [`verification.csv`](../../benchmarks/secbench-js/verification.csv): C4–C6.
- [`excluded.csv`](../../benchmarks/secbench-js/excluded.csv): unicidad y C3b.
- [`detection.csv`](../../benchmarks/secbench-js/detection.csv): C7–C8.
- [`manifest.json`](../../benchmarks/secbench-js/manifest.json): los casos versionados, con CVE, CWE, paquete, versiones, *sink*, comando del exploit y resultado de C7/C8.

### Embudo

| Clase | Total | C1 | C1–C2 | C1–C3 | Muestra | C4–C6 | Unicidad + C3b | C7 | **C8** |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| code-injection | 40 | 20 | 11 | 9 | 9 | 8 | 7 | 5 | **2** |
| command-injection | 101 | 90 | 42 | 42 | 25 | 15 | 14 | 13 | **12** |
| path-traversal | 170 | 81 | 12 | 12 | 12 | 5 | 5 | 3 | **3** |
| prototype-pollution | 192 | 158 | 103 | 97 | 25 | 20 | 17 | 10 | **7** |
| redos | 97 | 59 | 51 | 48 | 25 | 18 | 15 | 8 | **6** |
| **Total** | **600** | **408** | **219** | **208** | **96** | **66** | **58** | **39** | **30** |

En code-injection y path-traversal la muestra agota los casos elegibles (9 y 12 paquetes), así que esas clases no pueden crecer más.

### Ampliación de la muestra

La primera versión del dataset usaba 10 casos por clase (49 candidatos, 37 verificados). Al exigir C8, solo quedaban 20 vulnerabilidades en total, por debajo de las 30 necesarias para la comparación global de la Fase 5. La muestra se amplió a 25 por clase con la misma semilla.

El script de selección baraja cada clase completa antes de recortarla, así que la muestra ampliada **contiene a la original**: no se ha vuelto a sortear ni se ha elegido qué casos añadir. Los exploits de los 49 casos originales no se repitieron (`secbench_verify.py --reuse`).

### Por qué se descartan casos en C4–C6

Los 30 candidatos descartados documentan problemas de calidad del propio SecBench.js, lo que es relevante para discutir la validez del benchmark:

| Motivo | N | Casos |
|---|---:|---|
| Caso mal etiquetado: el CVE corresponde a otro paquete (OSV) | 11 | `alfred-workflow-nodejs`, `command-exists`, `diskstats`, `samsung-remote`, `scp`, `strider-git`, `vboxmanage.js`, `connie`, `millisecond`, `ms`, `prompts` |
| La versión corregida declarada sigue siendo explotable | 6 | `hostr`, `deepref`, `react-native`, `jspdf`, `ws`, `lodash` (su "versión corregida", 4.17.5, es anterior a la vulnerable, 4.17.15) |
| Sin versión corregida publicada (C6 no verificable) | 4 | `im-resize`, `macfromip`, `js-data`, `html-parse-stringify2` |
| La "versión corregida" es la misma que la vulnerable | 3 | `json-ptr` (code-injection), `gm`, `mcstatic` |
| El exploit agota el tiempo de espera (servidor HTTP) | 3 | `node-simple-router`, `stattic`, `node-srv` (solo en la versión corregida) |
| El exploit no funciona ni en la versión vulnerable | 2 | `glance`, `multi-ini` |
| La versión corregida no se puede instalar | 1 | `servey` |

### Unicidad y C3b

| Caso | Motivo |
|---|---|
| `command-injection/hot-formula-parser` | Mismo CVE (CVE-2020-6836) que el caso de code-injection del mismo paquete |
| `code-injection/hot-formula-parser` | El *sink* está en un parser generado por jison (líneas de 5.243 caracteres) |
| `prototype-pollution/jointjs` | El *sink* está en `dist/joint.min.js` (minificado). Además, el paquete ocupa 88 MB |
| `redos/html-parse-stringify` | El *sink* está en un bundle de `dist/` (líneas de 2.088 caracteres) |
| `prototype-pollution/sds` | Metadato del *sink* mal formado (`js:34`) |
| `prototype-pollution/set-or-get`, `redos/semver-regex` | El *sink* apunta a archivos internos de Jest (`build/utils.js`, `jasmineAsyncInstall.js`), no del paquete |
| `redos/three` | `three.js:6333` no existe en el paquete publicado (26 MB) |

Los casos excluidos no se versionan. Algunas rutas del *sink* son solo el nombre del archivo (`marked.js` en lugar de `lib/marked.js`); se resuelven por nombre cuando no hay ambigüedad.

## 5. Dataset final

[`benchmarks/dataset.csv`](../../benchmarks/dataset.csv): una fila por vulnerabilidad, con fuente, clase, CWE, CVE, archivo y línea del *sink*.

| Fuente | Clase | N |
|---|---|---:|
| SecBench.js | command-injection | 12 |
| SecBench.js | prototype-pollution | 7 |
| SecBench.js | redos | 6 |
| SecBench.js | path-traversal | 3 |
| SecBench.js | code-injection | 2 |
| Juice Shop | sql-injection | 2 |
| Juice Shop | nosql-injection | 1 |
| **Total** | 7 clases | **33** |

El objetivo de la hoja de ruta era de 30 a 50 vulnerabilidades.

### Conjunto de triaje (TP/FP, para la FPR)

El conjunto de remediación anterior solo contiene vulnerabilidades confirmadas, así que no permite medir la tasa de falsos positivos (FPR, Paso 5.2) ni comparar la decisión del agente con y sin traza (Paso 5.3), que es el núcleo de la pregunta de investigación. Para eso se añade un **conjunto de triaje** con hallazgos etiquetados como verdadero positivo (TP), falso positivo (FP) o indeterminado (UNCERTAIN). Vive en [`benchmarks/triage/labels.csv`](../../benchmarks/triage/labels.csv); los criterios, en [`triage-labels.md`](triage-labels.md); el registro de decisiones, en [`decisions.md`](decisions.md).

**Principio: toda etiqueta se apoya en una ejecución, no en la lectura del código** (decisión D2). El script [`scripts/benchmarks/triage_evidence.py`](../../scripts/benchmarks/triage_evidence.py) vuelve a ejecutar la evidencia de cada etiqueta y comprueba que da el resultado que la etiqueta exige; si alguna deja de hacerlo, la etiqueta no es válida.

| Evidencia | Significa |
|---|---|
| **OFF** | exploit tomado de un test oficial de OWASP (la verdad de base la aporta el benchmark) → TP |
| **POC** | exploit propio, versionado, que funciona contra el código tal cual → TP |
| **ABL** | el exploit falla contra el código y pasa a funcionar al desactivar la guarda citada (ablación) → FP |
| **GATE** | guarda evidente citada + un check reproducible de que la entrada maliciosa se rechaza (D7) → FP |
| **UNCERTAIN** | no se puede construir ninguna de las dos pruebas, o el efecto no es observable |

Los exploits de Juice Shop se lanzan por HTTP contra la imagen de contenedor del pipeline (con todos los retos activos); los de SecBench.js, en el arnés Docker contra la versión instalada desde npm (ver [`triage-labels.md`](triage-labels.md), sección 5).

**Alcance (D8).** El triaje se limita a hallazgos de **CodeQL con traza de taint de dos o más pasos** (el mismo criterio C8), porque es lo que permite evaluar la aportación de la traza. Quedan fuera Semgrep, Trivy y TruffleHog, y las alertas de CodeQL sin dataflow (`js/missing-rate-limiting`, `js/sensitive-get-query`…); el embudo concreto (234 hallazgos sin etiquetar → 16 en alcance) está en [`decisions.md`](decisions.md), D8.

**Estado (unidad = vulnerabilidad / `vuln_group`).** Completo:

| Fuente | TP | FP | UNCERTAIN | Total |
|---|---:|---:|---:|---:|
| Juice Shop | 17 | 16 | 4 | 37 |
| SecBench.js (versiones corregidas) | 0 | 6 | 4 | 10 |
| **Total (grupos)** | **17** | **22** | **8** | **47** |

El CSV tiene **53 filas**: varios resultados de CodeQL comparten `vuln_group` —misma fuente, regla y arreglo— y cuentan una vez en la métrica; por filas el desglose es 20 TP / 25 FP / 8 UNCERTAIN.

- Los **FP de Juice Shop** son guardas reales fuera de la traza: el allowlist de `.md/.pdf`, el middleware `serve-index` sobre los directorios servidos, la validación de claves de los endpoints `vulnCode*`, la verificación de firma antes de `put`, el saneado de extensión de las subidas de imagen, etc.
- Los **FP de SecBench.js** son las versiones corregidas de los casos vulnerables, que CodeQL sigue marcando pero cuyo arreglo neutraliza el exploit (ablación).
- Los **UNCERTAIN** reúnen debilidades de calidad sin exploit en tiempo de ejecución (MD5 de contraseñas, `Math.random`, ReDoS polinómico), código que no encaja en el modelo exploit/ablación (hoek, hosted-git-info, la detección de retos de `verify.ts`) y arreglos incompletos retenidos por posible divulgación (`connection-tester`, `dns-sync`; D3). Se informan aparte, con un análisis de sensibilidad (contándolos como TP y como FP).

**Relación con el conjunto de remediación.** Los 17 TP de Juice Shop del triaje incluyen los 3 que ya están en `benchmarks/dataset.csv` (inyecciones de `login`, `search` y `updateProductReviews`) y **14 nuevos** (open redirect, LFR, null-byte, NoSQL de reviews y likes, SSRF, inyección de logs, confusión de tipos, fuga de campos sensibles, JWT forjado…). Incorporar esos 14 al conjunto de remediación ([`triage-labels.md`](triage-labels.md), sección 8) es un paso **deliberado**: cambia la N de la Fase 5 y exige fijar la corrección de referencia de cada uno (el *codefix* cuando existe, o la validación por re-escaneo + exploit en la Fase 4). Se decide por separado y todavía no se ha aplicado.

## 6. Reproducción

Requisitos: Python 3.11+, Docker, Node/npm y el repositorio de SecBench.js en local (para el catálogo).

```bash
# 1. Catálogo con los criterios estáticos C1–C3
git clone https://github.com/cristianstaicu/SecBench.js /tmp/secbench
git -C /tmp/secbench checkout 5d362353550a8baa42bba34edd26e5fb86d41b60
python scripts/benchmarks/secbench_catalog.py /tmp/secbench benchmarks/secbench-js/catalog.csv

# 2. Muestra estratificada (25 por clase, semilla fija)
python scripts/benchmarks/secbench_select.py benchmarks/secbench-js/catalog.csv benchmarks/secbench-js/candidates.csv 25

# 3. Criterios C4–C6 (OSV + exploits en Docker)
docker build -t tfm/secbench-harness benchmarks/secbench-js/harness
python scripts/benchmarks/secbench_verify.py benchmarks/secbench-js/candidates.csv benchmarks/secbench-js/verification.csv

# 4. Unicidad, C3b y código fuente de los casos
python scripts/benchmarks/secbench_materialize.py benchmarks/secbench-js/verification.csv benchmarks/secbench-js/cases

# 5. C7–C8 sobre el SARIF unificado del pipeline (artefacto "unified-findings" de GitHub Actions)
python scripts/benchmarks/secbench_detect.py benchmarks/secbench-js/cases benchmarks/secbench-js/detection.csv \
  "semgrep=findings.sarif#semgrep" "codeql=findings.sarif#codeql"
python scripts/benchmarks/juiceshop_detect.py benchmarks/juice-shop/inventory.csv benchmarks/juice-shop/detection.csv \
  "semgrep=findings.sarif#semgrep" "codeql=findings.sarif#codeql"

# 6. Manifiesto y dataset final
python scripts/benchmarks/build_manifest.py
```

En Windows, el repositorio de SecBench.js no se puede extraer directamente, porque contiene una ruta que termina en punto (`incubator/ioredis_4.0.0.`). Se puede extraer solo lo necesario con `git -c core.protectNTFS=false archive HEAD code-injection command-injection path-traversal prototype-pollution redos`.

Notas del entorno:
- La imagen del arnés usa `node:16-bookworm`: SecBench.js se validó con Node 16, y la base `bullseye` de los Dockerfiles originales ya no tiene soporte (su repositorio de seguridad devuelve 404).
- No se usan los Dockerfiles por caso que trae SecBench.js: se generaron automáticamente y algunos clonan el repositorio equivocado (p. ej., `ms_0.7.0` clona `caolan/forms`).

## 7. Limitaciones

- **Clases desequilibradas.** Command-injection aporta 12 casos y code-injection solo 2. El análisis por categoría de la Fase 5 es exploratorio. Para la comparación global entre estrategias de prompting se usan los 33 casos con medidas repetidas.
- **Sesgo de selección hacia lo que CodeQL modela.** C8 deja dentro solo las vulnerabilidades que CodeQL sabe seguir. En las librerías, eso significa consultas que tratan los parámetros de las funciones exportadas como fuente (`js/shell-command-constructed-from-input`, `js/prototype-pollution-utility`, `js/unsafe-code-construction`…). Los resultados de la Fase 5 describen el rendimiento del sistema **sobre vulnerabilidades con traza**, no sobre cualquier vulnerabilidad. Es coherente con la pregunta de investigación (el valor de la traza), pero debe decirse así en la memoria.
- **Juice Shop aporta solo 3 casos al conjunto de remediación.** Son las vulnerabilidades más documentadas públicamente (inyecciones SQL de un benchmark conocido desde 2014), justo las que más riesgo de memorización tienen. La prueba de control de memorización (Paso 5.3) tendrá poco poder sobre esos 3. Lo mitiga el conjunto de triaje (§5.1): aporta 14 TP más de Juice Shop —varios sin *codefix* ni *writeup* público— y 22 FP, 6 de ellos de versiones corregidas de paquetes npm poco conocidos de SecBench.js, menos memorizables.
- **Regresión funcional en SecBench.js.** Los paquetes de npm no suelen incluir sus tests, así que el oráculo de seguridad (el exploit) no comprueba que el parche mantenga la funcionalidad. Hay que resolverlo antes de la Fase 4. Opciones: tests del repositorio original en la etiqueta de la versión, o pruebas diferenciales contra la versión corregida.
- **Path traversal** queda con 3 casos, porque la clase tiene muy pocos casos con corrección de referencia (12 de 170).
- **Muestreo.** Una muestra estratificada no es representativa de la distribución original de SecBench.js, dominada por prototype pollution. Es una decisión deliberada para cubrir todas las clases.
