# Benchmarks

Datos del conjunto experimental. La metodología completa está en [`docs/benchmark/dataset.md`](../docs/benchmark/dataset.md).

| Ruta | Contenido |
|---|---|
| `juice-shop/inventory.csv` | Vulnerabilidades de Juice Shop (una fila por fragmento vulnerable), con su CWE y el estado candidata/excluida. El código está en `src/app/juice-shop/`. |
| `secbench-js/catalog.csv` | Los 600 casos de SecBench.js con los criterios estáticos C1–C3. |
| `secbench-js/candidates.csv` | Muestra estratificada (semilla fija) sobre los casos elegibles. |
| `secbench-js/verification.csv` | Criterios dinámicos C4–C6 por candidato (OSV y exploits). |
| `secbench-js/detection-semgrep.csv` | Criterio C7 con Semgrep (pendiente de CodeQL). |
| `secbench-js/cases/<clase>/<caso>/` | Código fuente del paquete vulnerable (`src/`, tal y como se publicó en npm) y el manifiesto `case.json`: CVE, CWE, *sink*, versión corregida y oráculo. |
| `secbench-js/harness/` | Imagen Docker que ejecuta los exploits de SecBench.js (descargados de un commit fijo). |

El código de `secbench-js/cases/*/*/src/` es de terceros y **vulnerable a propósito**: no se corrige salvo para ejercitar la remediación, y está excluido de los hooks de pre-commit.
