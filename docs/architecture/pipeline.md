# Pipeline Shift-Left (Fase 2)

Workflow: [`.github/workflows/devsecops-pipeline.yml`](../../.github/workflows/devsecops-pipeline.yml). Se ejecuta en cada `push` a `main`, en cada PR hacia `main` y manualmente (`workflow_dispatch`).

## 1. Estructura

```
semgrep ─────┐
codeql ──────┤
trivy-fs ────┼──► unify ──► unified/findings.sarif  (entrada del agente, Fase 3)
trivy-image ─┤
trufflehog ──┘
```

| Job | Pilar | Herramienta | Qué analiza | Salida |
|---|---|---|---|---|
| `semgrep` | SAST | Semgrep OSS 1.178.0, `--config auto --dataflow-traces` | Todo el repositorio | SARIF |
| `codeql` | Dataflow/taint | CodeQL, suite `security-extended`, `javascript-typescript` | Todo el repositorio | SARIF (también se sube a *code scanning*) |
| `trivy-fs` | SCA | Trivy 0.74.0, `fs --scanners vuln` | Lockfiles (`package-lock.json` de Juice Shop) | JSON + SARIF |
| `trivy-image` | Contenedor | Trivy 0.74.0, `image` | Imagen construida con el `Dockerfile` de Juice Shop | JSON + SARIF |
| `trufflehog` | Secretos | TruffleHog 3.97.5, `filesystem --no-verification` | Árbol de trabajo (sin `.git/`) | JSONL → SARIF |
| `unify` | — | [`scripts/pipeline/unify_results.py`](../../scripts/pipeline/unify_results.py) | Las salidas anteriores | SARIF unificado + resumen en la página del *run* |

Los cinco escáneres corren en paralelo. `unify` se ejecuta aunque alguno falle y deja constancia de los que faltan (`properties.tfm.missingJobs`), para que un fallo de un escáner no se confunda con "cero hallazgos".

Trivy se ejecuta dos veces a propósito: el JSON conserva los vectores CVSS que necesita la priorización por riesgo (Paso 3.3), y el SARIF (generado con `trivy convert` a partir del mismo JSON) alimenta el artefacto unificado.

## 2. Artefacto unificado

Un único log SARIF 2.1.0 con **un `run` por job**. Se respetan los resultados de cada herramienta tal cual, con dos añadidos:

- `automationDetails.id` = `<job>/` (`semgrep/`, `codeql/`, `trivy-fs/`, `trivy-image/`, `trufflehog/`). Distingue las dos ejecuciones de Trivy.
- `partialFingerprints["tfmContextHash/v1"]` en **todos** los resultados.

### Huella para emparejar hallazgos antes y después del parche

La Fase 4 tiene que distinguir los hallazgos que el parche introduce de los que ya existían. No puede hacerse por número de línea: el parche desplaza líneas y los hallazgos preexistentes parecerían nuevos. Las huellas nativas no sirven como clave común, porque cada herramienta las rellena de forma distinta (CodeQL sí calcula `primaryLocationLineHash`, Trivy no rellena `partialFingerprints`).

`tfmContextHash/v1` = `sha256(job, regla, archivo, texto normalizado de las líneas señaladas)` + `:<n>`, donde `n` numera las apariciones con la misma clave (el mismo esquema que `primaryLocationLineHash` de GitHub). El texto se normaliza colapsando espacios, así que la huella no cambia si se insertan o se borran líneas en otra parte del archivo, ni si se reindenta. Sí cambia si se modifica la propia línea señalada; en ese caso el hallazgo original desaparece y, si sigue habiendo uno, cuenta como nuevo. Es el comportamiento buscado.

Para los hallazgos sin línea de código en el repositorio (paquetes dentro de la imagen del contenedor), la huella usa el mensaje del hallazgo, que incluye paquete, versión instalada y CVE.

## 3. Decisiones de seguridad del propio pipeline

### Secretos y PRs desde forks

GitHub Actions no expone los secretos del repositorio a los workflows disparados por PRs desde forks. **Ningún job de esta fase usa secretos**, así que el pipeline de escaneo se comporta igual en un PR propio que en uno de un fork.

El agente de la Fase 3 sí necesita `GROQ_API_KEY` y permisos de escritura. Se ejecutará solo en `push` a `main` y en `workflow_dispatch`, nunca en `pull_request_target`. Ese evento da secretos y token con escritura a código que viene del fork, y es la vía clásica de compromiso de un repositorio.

### Cadena de suministro

- Las acciones se fijan por **SHA de commit**, no por etiqueta. Una etiqueta se puede mover, y es así como se comprometieron `tj-actions/changed-files` y otras acciones en 2025.
- Las imágenes de los escáneres (Semgrep, Trivy, TruffleHog) se fijan por **digest**.
- Se usan versiones con al menos una semana publicadas. Las versiones maliciosas suelen detectarse en los primeros días.
- `permissions: contents: read` por defecto. Solo `codeql` recibe `security-events: write`, para subir resultados a *code scanning*.
- `persist-credentials: false` en todos los checkouts, para que el token no quede en `.git/config` al alcance de los escáneres.

### TruffleHog sin verificación

TruffleHog puede "verificar" cada secreto probándolo contra la API del proveedor. Aquí está desactivado (`--no-verification`), porque enviaría las credenciales del benchmark a servicios de terceros. Además, el secreto en claro (`Raw`, `RawV2`) se elimina con `jq` antes de que el resultado salga del runner: el artefacto solo contiene la versión censurada.

## 4. Validación de las trazas de taint (Paso 2.5)

Pendiente de la primera ejecución en CI: qué herramienta produce `codeFlows` y con qué granularidad. El resumen de `unify` cuenta, por herramienta, los hallazgos con `codeFlows` y la mediana de pasos por traza.

## 5. Desviaciones respecto a Juice Shop original

- El script `sbom` del frontend apuntaba a `dist/frontend/stats.json`, pero Angular 22 genera `browser-stats.json`. El fallo rompía `npm install` (vía `postinstall`) y el `docker build` del job `trivy-image`. Se corrige el nombre del archivo. Es un cambio de herramientas de compilación y no toca código vulnerable.
