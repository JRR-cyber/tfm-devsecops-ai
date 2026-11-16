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

**Comprobación con la página oficial de modelos de Groq (16-11-2026).** Llama 3.3
70B y Llama 3.1 8B siguen listados, pero con precio y límites "Contact Sales": solo
están disponibles con contrato Enterprise, no en el plan gratuito ni en el plan de
pago *Developer*. Pagar no los recupera, así que la elección se mantiene.
`gpt-oss-120b` en el plan Developer: $0,15 / $0,60 por millón de tokens de
entrada/salida, 250K tokens/min y 1K peticiones/min.

**Plan de pago.** Para el ensayo del 4.10 y la Fase 5 se usará el plan Developer
con un **tope de gasto de $10/mes** (límite de la consola de Groq, que bloquea la
API al alcanzarlo). Estimación pesimista de la rejilla completa: ~$2,50, o ~$6 si
los tokens de razonamiento triplicaran la salida. El ensayo del 4.10 medirá el
coste real por llamada antes de la Fase 5. A 16-11-2026 la contratación está
**pendiente**: Groq tiene las altas al plan Developer "temporalmente no
disponibles por alta demanda". Los pasos 4.7–4.9 no la necesitan (se prueban con un
LLM simulado y pocas llamadas reales); hay que resolverla antes del 4.10.

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

Checkpoint de la Fase 3: alcance completo, recortando profundidad dentro de cada fase ([D10](../../docs/benchmark/decisions.md)).

Fase 4 (verificación post-parche y bucle reflexivo):

| Paso | Descripción | Estado |
|---|---|---|
| 4.1 | Aislamiento: el parche se aplica y commitea en un `git worktree` aparte | **hecho** — `worktree.py` |
| 4.2 | Rescan local con CodeQL CLI (misma versión/queries que CI) sobre el worktree | **hecho** — `rescan.py`; equivalencia con CI medida en los 31 alcances del dataset |
| 4.3 | Emparejamiento pre/post por `tfmContextHash/v1`: FIXED / NOT_FIXED / NEW / PERSISTING | **hecho** — `regression.py` |
| 4.4 | Hallazgos reubicados (fingerprint cambiado por el parche) → RELOCATED, no NEW | **hecho** — `regression.py` |
| 4.5 | Registro JSONL por intento (reanudable; tokens y tiempo) | **hecho** — `results.py` |
| 4.6 | Decisión del oráculo funcional (`dataset.md` §7) | **hecho** — [D9](../../docs/benchmark/decisions.md): seguridad doble (CodeQL + exploit sobre el parche) y funcional por niveles (tests de API en Juice Shop, suite del paquete T1, diferencial T2) |
| 4.7 | Bucle reflexivo: hasta 3 intentos, con el motivo del rechazo como feedback | **hecho** — `repair_loop.py` |
| 4.8 | Implementación de los oráculos de D9 (preregistro + ejecutores) | pendiente |
| 4.9 | Etiquetado y escalado de PRs | pendiente |
| 4.10 | Ensayo de punta a punta sobre los 33 casos | pendiente |

## Aislamiento con worktrees (4.1)

Aplicar el parche cambiando de rama en el checkout del usuario (como hacía la
primera versión de 3.7) es frágil: reescribe su árbol de trabajo, falla si hay
cambios locales y una rama basada en `main` puede no contener ni el propio código
del agente (pasó al abrir el PR demo #7). Un `git worktree` es un segundo
directorio de trabajo ligado al mismo repositorio, con su propia rama: la rama
`fix/ai-remediation-…` vive ahí y el checkout del usuario no se toca.

- **Ubicación:** fuera del repo (`<repo>/../tfm-worktrees/`, configurable con
  `TFM_WORKTREE_ROOT`), para que los escáneres de CI, pre-commit o una base de datos
  CodeQL del checkout principal no los vean. Cada worktree se llama
  `wt-<hash de la rama>` (longitud fija): Windows limita las rutas a 260 caracteres
  y el fichero más profundo de Juice Shop ocupa 181, así que un nombre derivado de
  una rama larga desbordaba el límite (pasó con `js/insecure-randomness`). Si
  `git worktree add` falla, se borran la rama y el directorio a medio crear.
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

## Comparación pre/post por fingerprint (4.3)

`regression.py` compara el rescan del proyecto **antes** (base sin parche) y
**después** (worktree parcheado), emparejando por `tfmContextHash/v1`, nunca por
línea: un parche desplaza líneas y un emparejamiento por línea daría por
"arreglado y nuevo" todo lo que hay debajo de la edición.

| Resultado | Criterio |
|---|---|
| objetivo **FIXED** | su digest desaparece **y** no aparece un NEW de la misma regla en el mismo fichero |
| objetivo **NOT_FIXED** | su digest sigue, o aparece reubicado (ver abajo) |
| **NEW** | hallazgo en post sin pareja en pre → posible regresión de seguridad |
| **PERSISTING** | presente en ambos (incluye los 4 extra de alcance de 4.2) |
| **DISAPPEARED** | otro hallazgo que desaparece (arreglo colateral o texto editado; 4.4 lo refina) |

Decisiones:

- **Multiconjunto de digests.** El fingerprint es `digest:ocurrencia`; el índice de
  ocurrencia cambia si aparece o desaparece un hallazgo idéntico, así que se compara
  por `label_key` (el digest) contando repeticiones.
- **Guarda contra el falso éxito.** El digest hashea el *texto* de la línea marcada.
  Un parche cosmético en la línea vulnerable (cambiar comillas, renombrar una
  variable) cambia el digest aunque la vulnerabilidad siga ahí. Sin la segunda
  condición eso contaría como FIXED; con ella sale **NOT_FIXED (relocated)**.
- **Baseline cacheada** por commit base y alcance (`_rescan/baseline/<sha>/<alcance>`):
  se escanea una vez y se reutiliza en todos los intentos y estrategias.
- `verify_patch` hace todo el ciclo en un worktree desechable (se borran
  worktree y rama): verificar solo mide; conservar el arreglo y abrir el PR es
  `remediation_pr.prepare_pr`.

Validación real (SQLi de `routes/login.ts:34`, fingerprint `c292aea5…`, base
`84ce0be`, CodeQL 2.27.4):

| Parche | Objetivo | NEW | PERSISTING | Rescan |
|---|---|---:|---:|---|
| Real (el del PR demo #7: consulta parametrizada) | **FIXED** | 0 | 93 | baseline 92 s + post 87 s |
| Cosmético (solo cambia `''` por `""` en la línea vulnerable) | **NOT_FIXED (relocated)** | 1 (`js/sql-injection` en la misma línea, digest nuevo) | 93 | post 85 s (baseline cacheada) |

- El parche real no introduce regresiones. La alerta #97
  (`js/insufficient-password-hash` en `lib/insecurity.ts:41`), que el check de GitHub
  del PR #7 marcó como "nueva" porque el parche movió un paso de su flujo, sale
  **PERSISTING**: su fingerprint no cambia. Es el ejemplo de por qué se empareja por
  fingerprint y no con la heurística de "código cambiado".
- El parche cosmético demuestra la guarda en un caso real: una comparación ingenua
  por digest lo habría contado como FIXED + 1 NEW.

### Hallazgos reubicados (4.4)

El problema de la reubicación tiene dos caras. La del **objetivo** (falso FIXED) ya
la cubre la guarda de 4.3. La otra es el **resto** de hallazgos: si el parche toca
de paso otra línea marcada, ese hallazgo aparece como DISAPPEARED + NEW, y el NEW
parece una regresión que no existe (falso NEW). El bucle reflexivo rechazaría o
escalaría un parche bueno, y la Fase 5 inflaría la tasa de regresión.

Regla: tras emparejar por fingerprint, cada hallazgo desaparecido se empareja con
un NEW de la **misma regla en el mismo fichero** → **RELOCATED** (sale de NEW y de
DISAPPEARED). Decisiones:

- La identidad sigue siendo el fingerprint; la línea solo **desempata** cuando hay
  varios candidatos de la misma regla en el fichero (el más cercano). Nunca decide
  por sí sola que dos hallazgos son el mismo.
- El objetivo empareja **primero**. Si el objetivo se arregló y a la vez otro
  hallazgo de la misma regla del mismo fichero se reubicó, el objetivo puede
  "quedarse" con ese NEW y salir NOT_FIXED. Es deliberado: el error posible va en
  la dirección conservadora (falso NOT_FIXED, que el bucle reintenta o escala),
  nunca hacia un falso FIXED.
- El objetivo reubicado del parche cosmético ya no cuenta como NEW (no es una
  regresión, es el objetivo sin arreglar).

Validación real (CodeQL 2.27.4, base `84ce0be`):

| Parche | Objetivo | NEW | RELOCATED |
|---|---|---:|---:|
| Cosmético SQLi (reclasificado sin re-escanear) | NOT_FIXED (relocated) | 0 (antes 1) | 1 (el propio objetivo) |
| `lib/insecurity.ts`, 2 hunks: arregla `js/insecure-randomness` (l. 53, `Math.random` → `crypto.randomBytes`) y retoca cosméticamente `js/user-controlled-bypass` (l. 55) | **FIXED** | **0** | 1 (l. 55, digest `1af3e17b` → `7db83792`) |

Sin 4.4, el segundo caso habría salido "FIXED + 1 NEW": una regresión inexistente.

## Registro de resultados reanudable (4.5)

El bucle reflexivo (4.7) y la rejilla de la Fase 5 hacen cientos de llamadas al LLM
y rescans sobre una API con límites de uso. Un run puede cortarse en cualquier
momento (back-off de 429 agotado, caída, Ctrl+C), así que `results.py` escribe
**una línea JSON por intento en cuanto termina**, y al relanzar se saltan los
intentos ya registrados en vez de volver a pagarlos.

| Grupo | Campos |
|---|---|
| Clave (reanudar; nunca duplicada) | `kind` (triage/remediation), `fingerprint`, `strategy`, `with_trace`, `with_rag`, `attempt` |
| Resultado | triaje: `verdict`, `confidence`, `rationale`; remediación: `status` (FIXED / NOT_FIXED / APPLY_FAILED / NO_DIFF), `relocated`, `regression`, `new`, `moved`, `persisting`, `disappeared`, `diff` |
| Coste (*overhead*) | `prompt_tokens`, `completion_tokens`, `llm_seconds`, `rescan_seconds` |
| Procedencia | `model_served` (lo que la API dice que sirvió: detecta cambios silenciosos de modelo), `model_requested`, `codeql_version`, `agent_commit`, `base_sha`, `timestamp`, `raw` (respuesta cruda del modelo) |

Decisiones:

- **Se guarda la respuesta cruda.** La API no es lo bastante determinista para
  regenerarla, y el modelo puede retirarse (ya pasó con Llama 3.3 70B): el log es
  la única evidencia reproducible del experimento.
- **Escritura robusta:** cada línea se escribe con un solo `write` + `flush` +
  `fsync`. Una línea cortada por una caída (sin salto de línea final) se detecta al
  abrir, se elimina y se cuenta (`repaired`).
- `triage.decide` y `remediate.remediate` devuelven ahora el uso de la llamada
  (`usage`: tokens, segundos, modelo servido) junto al veredicto/parche;
  `groq_client.timed_complete` lo mide.
- El resumen estima el coste con el precio de lista de `gpt-oss-120b` en Groq
  ($0,15 / $0,60 por millón de tokens de entrada/salida, consultado 14-11-2026).

Validación offline: uso de tokens capturado; registro realista construido con los
rescans reales de la SQLi (FIXED, 0 NEW, 93 PERSISTING); duplicados rechazados;
línea parcial reparada; y **reanudación**: un run de 6 intentos que "cae" en la
llamada 4 deja 3 registrados, y al relanzarlo hace exactamente las 3 llamadas que
faltan.

```bash
python scripts/ai_agent/results.py summary results/run.jsonl
```

## Bucle reflexivo (4.7)

`repair_loop.py` da al agente hasta **3 intentos** por vulnerabilidad (fijado por
el roadmap) para producir un parche aceptable:

```
intento k:  remediate (con los intentos 1..k-1 rechazados como feedback)
            → verify_patch (worktree de la base, rescan CodeQL, 4.1–4.4, + oráculos de D9 en 4.8)
            → ¿aceptado?  sí → fin (ACCEPTED);  no → feedback → intento k+1
tras 3 rechazos → ESCALATED (se escala a un humano; etiqueta del PR en 4.9)
```

**Criterio de aceptación.** Un intento se acepta solo si se cumplen las cuatro:

1. El diff se aplica.
2. El objetivo queda **FIXED** (4.3: su fingerprint desaparece y no está reubicado).
3. El parche **no introduce ningún NEW** (una regresión de seguridad).
4. Todos los oráculos adicionales pasan. `verify_patch` ya acepta una lista de
   `checks` que se ejecutan sobre el worktree parcheado; los implementa el 4.8.

**Feedback.** El motivo del rechazo se escribe para que el modelo pueda actuar:

| Resultado del intento | Feedback al modelo |
|---|---|
| NO_DIFF | No devolvió ningún diff; debe devolver un único bloque ```diff |
| APPLY_FAILED | No se pudo aplicar (motivo); las líneas de contexto y `-` deben copiarse literalmente del fichero original |
| NOT_FIXED | CodeQL sigue reportando la regla en `fichero:línea`; el dato contaminado sigue llegando al *sink* |
| NOT_FIXED (reubicado) | La edición cambió la línea marcada, pero el flujo sigue llegando al *sink* (nueva línea) |
| FIXED con NEW | El objetivo desaparece, pero aparecen hallazgos nuevos (regla, `fichero:línea` y mensaje de CodeQL) |
| Oráculo fallido (4.8) | `Check '<nombre>' failed: <motivo>` |

Decisiones:

- **Cada intento se aplica al fichero original**, sobre el mismo commit base,
  nunca encima de un intento anterior. Así cada verificación es independiente y
  comparable, y el prompt se lo dice al modelo.
- **El intento 1 usa exactamente el prompt de la Fase 3.** A partir del 2 se
  añaden *todos* los intentos rechazados (diff + motivo), no solo el último, para
  que el modelo no vuelva a un arreglo que ya falló. La estrategia, la traza y el
  RAG de la condición no cambian entre intentos.
- **Registro (4.5):** cada intento se guarda con su número, `accepted`,
  `feedback`, `max_attempts` y los `checks` (esquema 2). Al relanzar, el historial
  se reconstruye desde el log y se sigue en el intento siguiente. El resumen
  (`results.py summary`) da la **convergencia**: bucles ACCEPTED / ESCALATED /
  INCOMPLETE (interrumpidos) y en qué intento se aceptaron (métrica de la Fase 5).
- **Un fallo de infraestructura** (CodeQL que falla, red) lanza una excepción y
  **no se registra**: no dice nada del modelo, así que al reanudar se repite el
  intento.
- **Dónde van los logs.** Los de desarrollo y ensayo (incluido el 4.10), en
  `results/dev/`, que git ignora (`.gitignore` ya excluye `results/`). Los de la
  Fase 5 se commitearán como datos de la tesis, porque son la evidencia de los
  resultados; su ruta versionada se fija al preparar la Fase 5.

Validación:

- **Offline** (LLM y verificador simulados, log real), 22 comprobaciones:
  aceptación en el intento 1 con un prompt idéntico al de la Fase 3; NO_DIFF →
  APPLY_FAILED → NOT_FIXED termina en ESCALATED con el historial creciendo en cada
  prompt; un NEW rechaza un FIXED; feedback de reubicado y de oráculo fallido;
  caída en la llamada del intento 2 y reanudación (solo se hacen las llamadas que
  faltan y el historial sale del log); un error de infraestructura no se registra;
  un bucle terminado no repite llamadas; resumen de convergencia.
- **Real** (CodeQL 2.27.4 y worktrees reales, LLM con guion para no gastar API),
  sobre la SQLi de `login.ts:34`:

  | Intento | Parche | Resultado | Rescan |
  |---|---|---|---|
  | 1 | Cosmético (`''` → `""` en la línea vulnerable) | NOT_FIXED reubicado → rechazado; el feedback indica la línea y que el flujo sigue llegando al *sink* | base 111 s + post 94 s |
  | 2 | El arreglo real del PR #7 (consulta parametrizada) | FIXED, 0 NEW, 93 PERSISTING → **ACCEPTED** | post 88 s (base en caché) |

  5,2 minutos en total; no quedó ningún worktree ni rama temporal.
- **En vivo** (gpt-oss-120b, plan gratuito, zero-shot con traza y RAG, misma SQLi;
  16-11-2026): **ACCEPTED en el intento 1**. Consulta parametrizada con
  `replacements` de Sequelize, FIXED, 0 NEW, 93 PERSISTING. Coste: 1.923 tokens de
  entrada y 365 de salida (~$0,0005 a precio de lista), 1,1 s de LLM y 89 s de
  rescan. Es un solo caso (n = 1), pero queda muy por debajo del supuesto
  pesimista del presupuesto (8K + 2K tokens por llamada de remediación).
  Observación: el modelo sustituyó el comentario marcador de Juice Shop
  (`// vuln-code-snippet vuln-line …`) por `// fixed: …`. En una rama de artefacto
  no importa, pero es un cambio fuera del arreglo estricto. Si se repite, el 4.8
  debe decidir si los oráculos lo toleran.

```bash
python scripts/ai_agent/repair_loop.py unified/findings.sarif --fingerprint <fp> --repo-root . \
    [--strategy cot] [--no-trace] [--no-rag] [--log results/dev/repair.jsonl]
python scripts/ai_agent/results.py summary results/dev/repair.jsonl
```

## Uso de `regression.py`

```bash
python scripts/ai_agent/regression.py verify unified/findings.sarif --fingerprint <fp> \
    --patch-file fix.diff --repo-root .
python scripts/ai_agent/regression.py compare --pre pre.sarif --post post.sarif --target <fp>
```

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
  entregable; aplicarlo y el bucle reflexivo son Fase 4 (`history` lleva los
  intentos rechazados, 4.7).
  ```bash
  GROQ_API_KEY=... python scripts/ai_agent/remediate.py unified/findings.sarif --fingerprint <fp> --repo-root . --strategy cot --run
  ```
- **`remediation_pr.py`** — mecánica de 3.7: aplica el parche **por contenido**
  (los diffs del modelo no llevan números de línea, así que se localiza el bloque
  `-` literal y se sustituye por el `+`), crea la rama `fix/ai-remediation-…`,
  commitea y prepara el PR. Dry-run por defecto (aplica en memoria, no toca el
  repo); `--commit` crea rama+commit local (en un worktree aislado, 4.1); `--open`
  además hace push y abre el PR.
- **`regression.py`** — comparación pre/post por fingerprint (Paso 4.3):
  FIXED / NOT_FIXED / NEW / PERSISTING / DISAPPEARED, y `verify_patch` (worktree →
  baseline → parche → rescan → comparación). Ver "Comparación pre/post" arriba.
- **`results.py`** — registro JSONL reanudable de cada intento (Paso 4.5): clave,
  resultado, tokens, tiempos y procedencia. Ver "Registro de resultados" arriba.
- **`repair_loop.py`** — bucle reflexivo (Paso 4.7): parche → verificación →
  feedback → nuevo parche, hasta 3 intentos; ACCEPTED o ESCALATED. Ver "Bucle
  reflexivo" arriba.
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
