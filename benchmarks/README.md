# Benchmarks

Datos del conjunto experimental. La metodología completa está en [`docs/benchmark/dataset.md`](../docs/benchmark/dataset.md).

| Ruta | Contenido |
|---|---|
| `dataset.csv` | **Dataset final** de la Fase 5: las vulnerabilidades de las dos fuentes que cumplen todos los criterios (C8: traza de CodeQL). |
| `remediation-targets.csv` | Hallazgo objetivo (fingerprint) preregistrado para cada caso de `dataset.csv`, con su CVSS y si pasa el filtro ≥ 7. Lo genera `scripts/benchmarks/remediation_targets.py` a partir del SARIF unificado; regla de selección en `scripts/ai_agent/README.md`, sección 4.10. |
| `nvd-cvss.csv` | CVSS v3/v2 de NVD del CVE de cada caso de SecBench.js junto a la severidad por regla de CodeQL (D11). Lo genera `scripts/benchmarks/nvd_cvss.py`; lleva la fecha de consulta. |
| `juice-shop/inventory.csv` | Vulnerabilidades de Juice Shop (una fila por fragmento vulnerable), con su CWE y el estado candidata/excluida. El código está en `src/app/juice-shop/`. |
| `juice-shop/detection.csv` | Criterios C7–C8 de las candidatas de Juice Shop. |
| `secbench-js/catalog.csv` | Los 600 casos de SecBench.js con los criterios estáticos C1–C3. |
| `secbench-js/candidates.csv` | Muestra estratificada (semilla fija) sobre los casos elegibles. |
| `secbench-js/verification.csv` | Criterios dinámicos C4–C6 por candidato (OSV y exploits). |
| `secbench-js/excluded.csv` | Casos verificados que no se versionan: CVE duplicado o *sink* no abordable (C3b). |
| `secbench-js/detection.csv` | Criterios C7–C8 (Semgrep y CodeQL) por caso. |
| `secbench-js/manifest.json` | Resumen de los casos versionados: CVE, CWE, paquete, versiones, *sink*, comando del exploit y C7/C8. |
| `secbench-js/cases/<clase>/<caso>/` | Código fuente del paquete vulnerable (`src/`, tal y como se publicó en npm) y su `case.json`. |
| `secbench-js/harness/` | Imagen Docker que ejecuta los exploits de SecBench.js (descargados de un commit fijo). |

El código de `secbench-js/cases/*/*/src/` es de terceros y **vulnerable a propósito**: no se corrige salvo para ejercitar la remediación, y está excluido de los hooks de pre-commit.
