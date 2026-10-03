# Dataset experimental (Paso 1.3)

Este documento describe cómo se construye el conjunto de vulnerabilidades sobre el que se evalúa el pipeline en la Fase 5, qué fuentes se usan, qué criterios de selección se aplican y en qué punto está cada uno.

## 1. Decisión de fuentes

La hoja de ruta proponía como dataset complementario Big-Vul o PrimeVul, y el OWASP Benchmark en la Fase 5. Ninguno sirve para este proyecto:

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

## 2. Juice Shop: inventario

Inventario completo: [`benchmarks/juice-shop/inventory.csv`](../../benchmarks/juice-shop/inventory.csv).

La unidad de medida es la **vulnerabilidad**, no el reto. Varios retos comparten un mismo fragmento vulnerable; por ejemplo, `routes/login.ts` agrupa tres retos pero es una única inyección SQL. Contar retos inflaría la N de la Fase 5.

| Paso | Resultado |
|---|---|
| Retos con corrección de referencia | 35 |
| Vulnerabilidades distintas (fragmentos marcados con `vuln-code-snippet`) | 23 |
| Candidatas (defecto de código en JS/TS) | **13** |
| Excluidas | 10: rutas del cliente (2), diseño de preguntas de seguridad (1), prompt injection de LLM (2), secreto en IaC (1), imagen Docker (1), Solidity (3) |

El secreto en Terraform (JS-19) y la imagen Docker vulnerable (JS-20) quedan fuera del conjunto de *remediación*, pero se usan como ground truth para TruffleHog y Trivy.

## 3. SecBench.js: embudo de selección

SecBench.js no tiene licencia, así que sus exploits **no se copian** a este repositorio: el arnés los descarga de un commit fijo (`5d362353550a8baa42bba34edd26e5fb86d41b60`). Solo se versiona el código de los paquetes npm afectados, que tienen su propia licencia y la conservan.

### Criterios

| Criterio | Tipo | Definición |
|---|---|---|
| C1 | estático | El caso tiene un identificador CVE (trazabilidad con un advisory público). |
| C2 | estático | Existe una corrección de referencia: commit de corrección o versión corregida publicada. |
| C3 | estático | El *sink* está en el código del propio paquete (no en una dependencia) y el caso usa un solo paquete. |
| — | muestreo | Muestra estratificada: hasta 10 casos por clase, un caso por paquete, semilla `20260930`. |
| C4 | dinámico | Consistencia: el paquete del caso es uno de los que OSV asocia al CVE (siguiendo los alias GHSA). |
| C5 | dinámico | El exploit funciona contra la versión vulnerable. |
| C6 | dinámico | El exploit **falla** contra la versión corregida, es decir, el oráculo distingue código vulnerable de código corregido. |
| C7 | dinámico | Algún escáner del pipeline reporta el hallazgo a ±10 líneas del *sink*, con una regla etiquetada con una CWE de la clase. |

### Resultados

| Clase | Total | C1 | C1–C2 | C1–C3 | Muestra | C4–C6 (verificados) | C7 Semgrep |
|---|---:|---:|---:|---:|---:|---:|---:|
| code-injection | 40 | 20 | 11 | 9 | 9 | 8 | 5 |
| command-injection | 101 | 90 | 42 | 42 | 10 | 7 | 4 |
| path-traversal | 170 | 81 | 12 | 12 | 10 | 5 | 1 |
| prototype-pollution | 192 | 158 | 103 | 97 | 10 | 9 | 3 |
| redos | 97 | 59 | 51 | 48 | 10 | 8 | 1 |
| **Total** | **600** | **408** | **219** | **208** | **49** | **37** | **14** |

C7 está **pendiente de CodeQL** (Paso 2.5), así que la columna de Semgrep es un límite inferior de la detección.

### Por qué se descartan casos en C4–C6

Los 12 candidatos descartados documentan problemas de calidad del propio SecBench.js, lo que es relevante para discutir la validez del benchmark:

| Motivo | Casos |
|---|---|
| Caso mal etiquetado: el CVE corresponde a otro paquete (detectado con OSV) | `redos/ms_0.7.0` (CVE de `forms`), `command-injection/strider-git_1.0.3` (CVE de `im-metadata`) |
| La "versión corregida" de los metadatos es la misma que la vulnerable | `json-ptr`, `gm`, `mcstatic` |
| La versión corregida declarada sigue siendo explotable | `hostr`, `deepref`, `react-native` |
| Sin versión corregida publicada (C6 no verificable) | `macfromip` |
| El exploit agota el tiempo de espera (servidor HTTP) | `node-simple-router`, `node-srv` (solo en la versión corregida), `stattic` |

### Por qué se endurece C7 con la CWE

Contar cualquier hallazgo cercano al *sink* sobreestima la detección. Por ejemplo, en `serve-here.js` y `tinyserver2` Semgrep dispara una regla de "servidor HTTP sin TLS" en la misma línea que el path traversal, sin haberlo detectado. Con el criterio por CWE, la detección de Semgrep baja de 17 a 14 casos.

### Anomalías de los metadatos del *sink*

- Algunas rutas del *sink* son solo el nombre del archivo (`marked.js` en lugar de `lib/marked.js`). Se resuelven por nombre cuando no hay ambigüedad.
- `prototype-pollution/sds_3.2.0` tiene un *sink* mal formado (`js:34:13`) que no identifica un archivo. Se mantiene en el conjunto porque su oráculo es válido, pero no puede evaluarse con C7 por localización.
- 4 paquetes (`dset`, `ajv`, `hot-formula-parser`, `ua-parser-js`) publican código en `dist/`, que el `.gitignore` de la raíz ignoraba. En `dset` el *sink* solo existe ahí (`dist/dset.js`). `benchmarks/secbench-js/cases/.gitignore` anula esa regla para que el código de los paquetes se versione completo.

## 4. Tamaño resultante

| Subconjunto | Candidatos | Detectados por Semgrep | Pendiente |
|---|---:|---:|---|
| Juice Shop | 13 | — | Detección con Semgrep y CodeQL (Paso 2.5) |
| SecBench.js | 37 | 14 | Detección con CodeQL (Paso 2.5) |
| **Total** | **50** | | |

El objetivo de la Fase 5 son 30–50 vulnerabilidades. El conjunto final serán los candidatos que cumplan C7 con Semgrep o CodeQL.

## 5. Reproducción

Requisitos: Python 3.11+, Docker, Node/npm y el repositorio de SecBench.js en local (para el catálogo).

```bash
# 1. Catálogo con los criterios estáticos C1–C3
git clone https://github.com/cristianstaicu/SecBench.js /tmp/secbench
git -C /tmp/secbench checkout 5d362353550a8baa42bba34edd26e5fb86d41b60
python scripts/benchmarks/secbench_catalog.py /tmp/secbench benchmarks/secbench-js/catalog.csv

# 2. Muestra estratificada (semilla fija)
python scripts/benchmarks/secbench_select.py benchmarks/secbench-js/catalog.csv benchmarks/secbench-js/candidates.csv

# 3. Criterios C4–C6 (OSV + exploits en Docker)
docker build -t tfm/secbench-harness benchmarks/secbench-js/harness
python scripts/benchmarks/secbench_verify.py benchmarks/secbench-js/candidates.csv benchmarks/secbench-js/verification.csv

# 4. Código fuente de los casos verificados
python scripts/benchmarks/secbench_materialize.py benchmarks/secbench-js/verification.csv benchmarks/secbench-js/cases

# 5. C7: cruzar los SARIF de los escáneres con los sinks
python scripts/benchmarks/secbench_detect.py benchmarks/secbench-js/cases benchmarks/secbench-js/detection-semgrep.csv semgrep=semgrep.sarif
```

En Windows, el repositorio de SecBench.js no se puede extraer directamente, porque contiene una ruta que termina en punto (`incubator/ioredis_4.0.0.`). Se puede extraer solo lo necesario con `git -c core.protectNTFS=false archive HEAD code-injection command-injection path-traversal prototype-pollution redos`.

Notas del entorno:
- La imagen del arnés usa `node:16-bookworm`: SecBench.js se validó con Node 16, y la base `bullseye` de los Dockerfiles originales ya no tiene soporte (su repositorio de seguridad devuelve 404).
- No se usan los Dockerfiles por caso que trae SecBench.js: se generaron automáticamente y algunos clonan el repositorio equivocado (p. ej., `ms_0.7.0` clona `caolan/forms`).

## 6. Limitaciones

- **Regresión funcional en SecBench.js**: los paquetes de npm no suelen incluir sus tests, así que el oráculo de seguridad (el exploit) no comprueba que el parche mantenga la funcionalidad. Hay que resolverlo antes de la Fase 4. Opciones: tests del repositorio original en la etiqueta de la versión, o pruebas diferenciales contra la versión corregida.
- **Muestreo**: una muestra estratificada de 10 casos por clase no es representativa de la distribución original de SecBench.js, que está dominada por prototype pollution. Es una decisión deliberada para cubrir todas las clases en el análisis por categoría de la Fase 5.
- **Path traversal** queda con solo 5 casos verificados, porque la clase tiene pocos casos con corrección de referencia (12 de 170).
