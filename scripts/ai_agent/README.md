# Agente de IA (Fases 3–4)

Agente híbrido del pipeline: lee el SARIF unificado que produce CI
(`scripts/pipeline/unify_results.py` → `unified/findings.sarif`), triaje cada
hallazgo apoyándose en la traza de taint de CodeQL y, para los de severidad alta,
propone un parche y abre un PR para revisión humana (postura asistiva).

Diseño fijo del roadmap (no sustituir sin pedirlo): un solo modelo en Groq
(ver "Decisión de modelo" abajo), los experimentos comparan *estrategias de
prompting* (zero-shot / few-shot / CoT); auto-remediación solo para CVSS ≥ 7.0;
emparejamiento pre/post parche por `partialFingerprints`, nunca por línea; el
agente no corre en `pull_request_target`.

## Decisión de modelo

**Modelo único fijado: `openai/gpt-oss-120b` en Groq.** El roadmap fijaba
*Llama 3.3 70B en Groq*, pero **Groq retiró ese modelo el 16-08-2026** (y toda la
familia Llama de chat; en el *free tier* solo quedan `gpt-oss-*`, `qwen3`, Whisper
y los clasificadores Prompt Guard, que no sirven para generación). Ante el
conflicto entre las dos decisiones fijas (proveedor = Groq, modelo = Llama 3.3
70B), se conserva **Groq** y se cambia al modelo abierto más capaz de su catálogo
actual, `openai/gpt-oss-120b`.

No afecta a la pregunta de investigación: el experimento es *within-subject*
(con/sin traza y zero/few/CoT con el **modelo fijo**), así que lo que se mide es la
diferencia entre condiciones dentro del mismo modelo; el modelo es la constante
controlada, no la variable. La única consecuencia es de **validez externa** (los
resultados aplican a este modelo), que se declara en Amenazas a la validez. Se
mantiene un modelo open-weights, coherente con la premisa de "modelo asequible y
reproducible" del plan.

## Estado por paso

| Paso | Descripción | Estado |
|---|---|---|
| 3.1 | Cliente Groq (clave `GROQ_API_KEY`) | **hecho** — `groq_client.py` |
| 3.2 | Parser del SARIF unificado (fichero, línea, regla, snippet, `codeFlows`, fingerprint, severidad) | **hecho** — `sarif_parser.py` |
| 3.3 | Filtro CVSS ≥ 7.0 + mapeo documentado de severidad Semgrep | **hecho** — `severity.py` |
| 3.4 | Traza de taint como contexto estructurado; decisión FP a partir de la traza | **hecho** — `trace_context.py`, `triage.py` |
| 3.5 | RAG ligero (imports y funciones relacionadas del fichero vulnerable) | **hecho** — `context_rag.py` |
| 3.6 | Prompts zero-shot / few-shot / CoT; parche como diff | **hecho** — `strategies.py`, `remediate.py` |
| 3.7 | Rama `fix/ai-remediation-...` + PR | **hecho** — `remediation_pr.py`, `triage_engine.py` |

Fase 4 (verificación post-parche y bucle reflexivo):

| Paso | Descripción | Estado |
|---|---|---|
| 4.1 | Aislamiento: el parche se aplica y commitea en un `git worktree` aparte | **hecho** — `worktree.py` |
| 4.2 | Rescan local con CodeQL CLI (misma versión/queries que CI) sobre el worktree | **hecho** — `rescan.py`; equivalencia con CI medida en los 31 alcances del dataset |
| 4.3 | Emparejamiento pre/post por `tfmContextHash/v1`: FIXED / NOT_FIXED / NEW / PERSISTING | pendiente |
| 4.4 | Hallazgos reubicados (fingerprint cambiado por el parche) → RELOCATED, no NEW | pendiente |
| 4.5 | Registro JSONL por intento (reanudable; tokens y tiempo) | pendiente |
| 4.6 | Decisión del oráculo funcional (`dataset.md` §7) | pendiente |
| 4.7–4.10 | Bucle reflexivo (3 intentos), oráculo funcional, etiquetado/escalado de PRs, ensayo de punta a punta | pendiente |

## Aislamiento con worktrees (4.1)

Aplicar el parche cambiando de rama en el checkout del usuario (como hacía la
primera versión de 3.7) es frágil: reescribe su árbol de trabajo, falla si hay
cambios locales y una rama basada en `main` puede no contener ni el propio código
del agente (pasó al abrir el PR demo #7). Un `git worktree` es un segundo
directorio de trabajo ligado al mismo repositorio, con su propia rama: la rama
`fix/ai-remediation-…` vive ahí y el checkout del usuario no se toca.

- **Ubicación:** fuera del repo (`<repo>/../tfm-worktrees/`, configurable con
  `TFM_WORKTREE_ROOT`), para que los escáneres de CI, pre-commit o una base de datos
  CodeQL del checkout principal no los vean, y para mantener rutas cortas en Windows.
- **Barrera de seguridad:** el módulo solo crea y borra ramas `fix/ai-remediation-*`;
  el agente no puede usarlo para escribir en `main`.
- **Ciclo de vida:** el directorio del worktree se borra siempre al terminar; la rama
  se conserva solo si el parche se aplicó y se commiteó (es lo que apunta el PR). Si
  el parche no aplica, se borran rama y worktree. `reset()` devuelve el worktree a
  `base` para un intento nuevo del bucle reflexivo (4.7).
- **Diffs multi-fichero:** se rechazan explícitamente (el prompt pide un solo
  fichero; antes se habrían mezclado bajo una ruta).

## Rescan local con CodeQL (4.2)

Tras aplicar el parche hay que comprobar si la vulnerabilidad desaparece y si
aparecen otras. Hacerlo en CI cuesta ~2 min por intento y deja ramas en GitHub;
con un bucle de hasta 3 intentos × 33 casos no es viable, así que el rescan corre
**en local reproduciendo el análisis de CI**:

| Aspecto | CI (`devsecops-pipeline.yml`) | Rescan local (`rescan.py`) |
|---|---|---|
| Versión CodeQL | 2.27.4 (la que registra el SARIF; el *default* de la action v4.38.1 es 2.27.0, pero el runner tenía en caché una más nueva) | 2.27.4 fijada; se niega a correr con otra salvo `--allow-version-mismatch` (solo desarrollo) |
| Suite | `security-extended` | `javascript-security-extended.qls` (la misma) |
| Lenguaje / build | `javascript-typescript`, `build-mode: none` | igual |
| Alcance | todo el repo | solo el **proyecto** del hallazgo (Juice Shop o un caso SecBench.js) |
| Fingerprint | `unify_results.add_fingerprints` | la misma función, **importada** (no copiada ni modificada) |
| Ficheros escaneados | checkout limpio (solo ficheros versionados) | worktree limpio; **se niega** si el alcance tiene ficheros no versionados o ignorados |

**Por qué exigir un árbol limpio** (hallazgo de la primera ejecución): el checkout
de desarrollo de Juice Shop contiene `node_modules/`, `build/`, `frontend/dist/` y
`.angular/` (miles de ficheros JS generados y minificados que CI nunca ve). CodeQL
los extraía, el escaneo pasaba de 10 minutos sin terminar y habría reportado
hallazgos inexistentes en CI. Un worktree (4.1) solo contiene ficheros versionados,
así que el rescan se hace siempre sobre él (`--allow-untracked` existe solo para
desarrollo).

**Por qué escanear solo el proyecto:** reconstruir la base de datos de todo el repo
en cada intento es lento, y los flujos de datos no cruzan proyectos. Las URIs del
SARIF se reescriben a rutas relativas al repo, así que los fingerprints son
comparables con los de CI. Equivalencia **comprobada, no supuesta**:

- *Post-procesado* (reescritura de URIs + fingerprint), offline sobre el SARIF
  crudo de CI del run 43605673798: 345/345 fingerprints idénticos al artefacto
  unificado (91/91 en Juice Shop, 12/12 en un caso SecBench), URIs de los
  `codeFlows` también relativas al repo.
- *Escaneo real* en un worktree limpio de `84ce0be` frente al CI del mismo commit
  (run 43605673798), Windows 11, 12 hilos:

  | Alcance | Local | CI | Emparejados | Tiempo |
  |---|---:|---:|---:|---:|
  | Repo completo | 345 | 345 | **345** (exacto) | 250 s |
  | Juice Shop (solo el proyecto) | 94 | 91 | **91** + 3 solo-local | 98 s |
  | SecBench `clamscan_1.2.0` (solo el caso) | 12 | 12 | **12** (exacto) | 50 s |

  El repo completo coincide al 100 % con CI, así que la plataforma (Windows frente
  a Linux) no introduce diferencias. Los 3 extra de Juice Shop
  (`js/clear-text-logging` en `lib/antiCheat.ts:76,105,217`, flujos entre ficheros
  desde propiedades llamadas `changePasswordBenderChallenge` / `leakedApiKeyChallenge`)
  se deben al **alcance**: con solo el proyecto, CodeQL resuelve algunos flujos entre
  ficheros de forma distinta.

**Decisión: escanear solo el proyecto.** La comparación que decide el veredicto es
pre frente a post, ambos locales y con la misma configuración: un hallazgo extra
aparece en los dos lados (PERSISTING) y no cambia ningún veredicto. El hallazgo
objetivo se localiza igual (los 91 de CI están en el escaneo local). A cambio, la
rejilla de la Fase 5 (33 casos × 3 estrategias × ≤ 3 intentos = hasta 297 rescans)
baja de ~20 h (repo completo, 250 s) a ~3,7 h (~40 s por caso SecBench, ~98 s Juice
Shop).

**Equivalencia medida en todo el dataset** (`benchmarks/dataset.csv`: 30 casos
SecBench.js + Juice Shop = 31 alcances), escaneo por proyecto frente a CI:

| | Alcances | Hallazgos CI | Recuperados en local | Solo-local |
|---|---:|---:|---:|---:|
| SecBench.js | 30 | 162 | **162** (100 %) | 1 (`json-ptr_1.1.0`: `js/unsafe-code-construction` en `src/index.js:229`) |
| Juice Shop | 1 | 91 | **91** (100 %) | 3 (`js/clear-text-logging`, ver arriba) |
| **Total** | **31** | **253** | **253 (100 %)** | **4 (1,6 %)** |

29 de los 30 casos SecBench son idénticos a CI; tiempo medio ~40 s por caso. Ningún
hallazgo de CI se pierde con el escaneo por proyecto: la diferencia es solo en el
sentido de *más* hallazgos (4), que aparecen tanto antes como después del parche y
se declaran en Amenazas a la validez.

Instalación del bundle (CLI + packs de queries precompilados, lo mismo que usa la
action), en Git Bash:

```bash
mkdir -p ~/tools && cd ~/tools
curl -LO https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.4/codeql-bundle-win64.tar.gz
curl -LO https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.4/codeql-bundle-win64.tar.gz.checksum.txt
sha256sum -c codeql-bundle-win64.tar.gz.checksum.txt      # debe decir: OK
tar -xzf codeql-bundle-win64.tar.gz                        # crea ~/tools/codeql/
~/tools/codeql/codeql version --format=terse              # 2.27.4
export CODEQL_CLI=~/tools/codeql/codeql.exe                # o añadir ~/tools/codeql al PATH
```

Uso:

```bash
# --source-root debe ser un worktree limpio (p. ej. ../tfm-worktrees/<caso>)
python scripts/ai_agent/rescan.py --source-root ../tfm-worktrees/<caso> --scope src/app/juice-shop \
    --out ../tfm-worktrees/_rescan/juice-shop --compare unified/findings.sarif
```

El tiempo de `database create` + `analyze` se devuelve en el resultado (métrica de
*overhead* de la Fase 5).

## Módulos

- **`sarif_parser.py`** — convierte el SARIF unificado en objetos `Finding`
  tipados. Es el único punto que normaliza la severidad entre herramientas (ver
  abajo). No filtra ni triaje: solo parsea.
  ```bash
  python scripts/ai_agent/sarif_parser.py unified/findings.sarif --repo-root . [--json]
  ```
- **`severity.py`** — asigna a cada `Finding` una puntuación comparable con CVSS
  (0–10) y aplica el filtro ≥ 7.0 (Paso 3.3). Es *política*, no un hecho del
  SARIF, por eso vive aparte del parser. Ver "Mapeo de severidad" abajo.
  ```bash
  python scripts/ai_agent/severity.py unified/findings.sarif
  ```
- **`trace_context.py`** — renderiza un `Finding` y su traza de taint como texto
  estructurado para el prompt (Paso 3.4). La traza es un bloque **separable**:
  `render_context(..., with_trace=False)` da la condición ciega de la Fase 5.3.
  `render_context` tiene también `with_rag` para añadir el bloque de 3.5.
- **`context_rag.py`** — RAG ligero (Paso 3.5): extrae estáticamente (sin
  embeddings) los imports, la **función que envuelve el *sink*** y las funciones
  hermanas que llama, para que el modelo vea mitigaciones que están *fuera* de la
  traza (p. ej. la guarda de `keyServer.ts:13`). Bloque separable, como la traza.
- **`strategies.py`** — las tres estrategias de prompting (Paso 3.6) como
  transformaciones del prompt, agnósticas a la tarea: `zero-shot` (directo),
  `few-shot` (antepone ejemplos), `cot` (pide razonar paso a paso). La estrategia
  no toca el contexto del hallazgo (traza/RAG): esas son las constantes.
- **`remediate.py`** — genera el parche como **diff unificado** (Paso 3.6) para un
  TP de CVSS ≥ 7. Mismo contexto estructurado que el triaje (+ RAG por defecto,
  no se parchea lo que no se ve) y las mismas estrategias. Generar el diff es el
  entregable; aplicarlo y el bucle reflexivo son Fase 4.
  ```bash
  GROQ_API_KEY=... python scripts/ai_agent/remediate.py unified/findings.sarif --fingerprint <fp> --repo-root . --strategy cot --run
  ```
- **`remediation_pr.py`** — mecánica de 3.7: aplica el parche **por contenido**
  (los diffs del modelo no llevan números de línea, así que se localiza el bloque
  `-` literal y se sustituye por el `+`), crea la rama `fix/ai-remediation-…`,
  commitea y prepara el PR. Dry-run por defecto (aplica en memoria, no toca el
  repo); `--commit` crea rama+commit local (en un worktree aislado, 4.1); `--open`
  además hace push y abre el PR.
- **`rescan.py`** — rescan local post-parche con CodeQL CLI (Paso 4.2), con la
  misma versión y suite que CI y el SARIF con forma de artefacto unificado. Ver
  "Rescan local con CodeQL" arriba.
- **`worktree.py`** — worktrees aislados para aplicar y verificar parches (Paso
  4.1). Ver "Aislamiento con worktrees" arriba.
  ```bash
  python scripts/ai_agent/worktree.py list
  python scripts/ai_agent/worktree.py remove fix/ai-remediation-<regla>-<fp8> [--delete-branch]
  ```
- **`triage_engine.py`** — orquestador (capstone de la Fase 3): encadena
  parse → filtro (CVSS≥7 ∩ traza) → triaje → (si TP) parche → PR. Sin argumentos
  lista los candidatos; con `--fingerprint … --run` ejecuta un hallazgo de punta a
  punta.
  ```bash
  python scripts/ai_agent/triage_engine.py unified/findings.sarif --repo-root .   # lista candidatos
  ```
- **`evaluate.py`** — probe de desarrollo (NO el experimento de Fase 5): corre el
  triaje sobre el conjunto etiquetado en varios modos (`notrace` / `trace` /
  `trace+rag`) y mide el acuerdo con `labels.csv`. Para cazar bugs y ver el efecto
  de la traza y el RAG, no para reportar resultados.
- **`triage.py`** — decisión de triaje con el LLM (Paso 3.4): construye el prompt,
  llama a Groq y parsea el veredicto **TP / FP / UNCERTAIN** (mismo vocabulario que
  `benchmarks/triage/labels.csv`, para evaluarlo en la Fase 5).
  ```bash
  # offline: solo imprime el prompt (con o sin traza)
  python scripts/ai_agent/triage.py unified/findings.sarif --fingerprint <fp> --repo-root . [--no-trace]
  # en vivo: decisión real (necesita GROQ_API_KEY)
  GROQ_API_KEY=... python scripts/ai_agent/triage.py unified/findings.sarif --fingerprint <fp> --repo-root . --run
  ```
- **`groq_client.py`** — cliente mínimo (solo biblioteca estándar) del endpoint
  compatible con OpenAI de Groq. Modelo fijo, clave desde el entorno.
  ```bash
  GROQ_API_KEY=... python scripts/ai_agent/groq_client.py --selftest
  ```

## Dónde está la severidad en el SARIF unificado (hallazgo de 3.2, relevante para 3.3)

`unify_results.py` conserva cada run de scanner **intacto** (solo añade
`automationDetails.id` y el fingerprint). Por tanto la severidad **no se pierde**,
pero cada herramienta la guarda en un sitio distinto, y `sarif_parser.py` la
normaliza en el campo `security_severity` (CVSS 0–10) de cada `Finding`:

| Herramienta | Severidad numérica | Dónde | `level` | Traza (`codeFlows`) |
|---|---|---|---|---|
| CodeQL | ✅ `security-severity` 0–10 | `tool.extensions[].rules` | `rule.defaultConfiguration.level` | ✅ (única fuente) |
| Trivy (fs/image) | ✅ `security-severity` (CVSS) | `tool.driver.rules` | `result.level` | ❌ |
| Semgrep | ❌ (solo nivel) | — | `defaultConfiguration.level` | ❌ |
| TruffleHog | ❌ (secreto → crítico) | — | `error` | ❌ |

**Consecuencia para 3.3:** el filtro CVSS ≥ 7.0 obtiene el número directamente del
SARIF unificado para CodeQL y Trivy; para **Semgrep** hay que aplicar el *mapeo
documentado Semgrep→CVSS* (ya previsto en el roadmap), porque Semgrep no emite un
número. **No hace falta modificar `unify_results.py`.**

Medido sobre el `unified/findings.sarif` de CI (commit de referencia): 1056
hallazgos — codeql 345 (231 con traza ≥2 pasos, los 345 con CVSS), semgrep 448
(0 con CVSS, pendientes de mapeo), trivy-fs 125, trivy-image 124, trufflehog 14.
Solo CodeQL aporta traza, lo que fija que la decisión FP basada en traza (3.4) es
exclusiva de CodeQL (decisión D8 del dataset).

## Mapeo de severidad (3.3)

El roadmap solo auto-remedia hallazgos con **CVSS ≥ 7.0**; el resto se reportan.
Para aplicar un único umbral a herramientas que expresan la severidad de forma
distinta, `severity.py` reduce cada hallazgo a un número en la escala CVSS 0–10:

| Herramienta | Fuente del número | Mapeo |
|---|---|---|
| CodeQL | `security-severity` (ya es CVSS) | se usa tal cual |
| Trivy (fs/image) | `security-severity` (ya es CVSS) | se usa tal cual |
| Semgrep | no da número, solo nivel | `error`→8.0 (High), `warning`→5.0 (Medium), `note`→2.0 (Low) |
| TruffleHog | secreto embebido (CWE-798) | constante 9.0 (Critical) |

**Decisión (mapeo Semgrep→CVSS).** Se usa la *escala cualitativa de severidad de
CVSS v3.1* (None 0.0 · Low 0.1–3.9 · Medium 4.0–6.9 · High 7.0–8.9 · Critical
9.0–10.0) y se asigna a cada nivel de Semgrep el valor representativo de su banda.
El nivel SARIF de Semgrep viene de su severidad interna (ERROR/WARNING/INFO):
`ERROR` es el nivel que Semgrep reserva a las reglas de seguridad "que deben
corregirse", así que se trata como **High** y es el **único** nivel que cruza el
umbral de ≥ 7. No se usa la confianza (`LOW CONFIDENCE`, `precision`) para
modular el número: se deja el criterio reproducible y defendible (nivel → banda),
y la confianza queda como contexto para el LLM en 3.4, no como parte del filtro.
El campo `Score.source` deja trazado de dónde salió cada número
(`tool` / `semgrep-level-map` / `trufflehog-constant`), para auditoría.

**Alcance del filtro vs. alcance de la auto-remediación.** `severity.py` clasifica
*todos* los hallazgos por severidad; es solo la capa de severidad. **Qué se
auto-remedia** se decide al componer con 3.4: el candidato real a remediación es
`CVSS ≥ 7` **∩ con traza** (es decir, CodeQL), porque es lo único sobre lo que la
decisión FP por traza y el parche por diff pueden actuar. Los demás altos
—Semgrep (patrón sin traza), Trivy (CVE de dependencia) y TruffleHog (secreto, se
rota, no se parchea)— se reportan/escalan, no se auto-remedian.

**Distribución medida** (artefacto `unified-findings` de CI, run 40745100452 sobre
`main`): de 1094 hallazgos, **394 cruzan CVSS ≥ 7**, pero solo **91 son CodeQL con
traza** (el conjunto candidato a remediación). Desglose de los ≥ 7: CodeQL 197
(91 con traza), Trivy-fs 79, Trivy-image 60, Semgrep 44 (todos del nivel `error`),
TruffleHog 14.

## Decisión de triaje y traza separable (3.4)

`triage.py` pide al LLM decidir si un hallazgo es **TP / FP / UNCERTAIN** —el mismo
vocabulario que `benchmarks/triage/labels.csv`, para evaluarlo contra esa verdad
de base en la Fase 5 (el join es por `fingerprint`, no por ruta)—. El prompt lleva
el contexto estructurado del hallazgo (regla, CWE, ubicación, código marcado) y, si
procede, la **traza de taint** (`trace_context.py`): la lista fuente → … → *sink*
con la línea de código de cada paso.

**Traza separable (control de la Fase 5.3).** `render_context(..., with_trace=…)`
construye el mismo contexto con o sin el bloque de traza. El system prompt es
**idéntico** en ambas condiciones, así que la única variable que cambia entre
"con traza" y "ciego" es la presencia del flujo fuente → *sink*. Solo CodeQL tiene
traza (D8), así que la condición "con traza" solo existe para hallazgos de CodeQL.

**Robustez.** La temperatura es 0 (determinista). El veredicto se pide como un
único objeto JSON; `parse_verdict` lo extrae aunque el modelo añada prosa, y cae a
`UNCERTAIN` si no hay nada parseable. La respuesta cruda se conserva (`raw`) para
auditoría. La decisión en vivo (`decide` / `--run`) necesita `GROQ_API_KEY`; el
renderizado del prompt y el parseo funcionan sin clave y están probados.
