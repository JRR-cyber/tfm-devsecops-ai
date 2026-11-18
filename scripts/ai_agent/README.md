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
LLM simulado y pocas llamadas reales).

**Plan gratuito por tandas (17-11-2026).** Con el plan Developer aún bloqueado, el
4.10 se ejecuta en el plan gratuito, que para `gpt-oss-120b` permite 30
peticiones/min, 1.000 peticiones/día, 8K tokens/min y 200K tokens/día. La demo
real midió ~5.900 tokens por caso completo (triaje + 2 intentos), así que los 33
casos caben en 1–2 días de cuota. El límite por minuto no estorba, porque cada
intento ya espera ~95 s al rescan de CodeQL. Cuando se agota la cuota diaria, el
cliente lanza `GroqQuotaExhausted` sin reintentar, con el tiempo de espera que
indica Groq (cabecera `Retry-After` o "try again in …" del mensaje). El lote se
detiene y se relanza después con el mismo comando: el log (4.5) evita repetir lo
ya hecho. Un 429 corto (por minuto) se sigue esperando dentro del cliente. No se
cambia de proveedor: aunque otros sirven el mismo modelo, mezclar proveedores
dentro de un experimento rompería el diseño within-subject. Si la Fase 5 no cupiera
en el plan gratuito, el cambio se aplicaría a todo el experimento y se registraría
como decisión nueva.

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
| 4.8 | Implementación de los oráculos de D9 (preregistro + ejecutores) | **hecho** — `oracle_juiceshop.py`, `oracle_secbench.py`: Juice Shop (3), exploit SecBench (30), T1 (17), T2 (13) |
| 4.9 | Etiquetado y escalado de PRs | **hecho** — `publish.py`; `triage_engine.py` encadena triaje → bucle → publicación |
| 4.10 | Ensayo de punta a punta sobre los 33 casos | **en curso** — `run_dataset.py` y objetivos preregistrados listos; falta la ejecución real |

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

## Oráculos de verificación de D9 (4.8)

El 4.8 implementa los oráculos que decidió [D9](../../docs/benchmark/decisions.md).
Se conectan al bucle (4.7) como `checks` de `verify_patch`: se ejecutan sobre el
worktree parcheado, después del rescan, y un oráculo que falla rechaza el intento
y su motivo llega al modelo como feedback. `repair_loop.py` los activa por
defecto (`--no-oracles` deja solo CodeQL). Un oráculo que no aplica a un hallazgo
devuelve `None`; un fallo de infraestructura (Docker, red, registro desfasado)
lanza una excepción y no se registra.

| Oráculo | Casos | Qué comprueba | Módulo |
|---|---|---|---|
| `juice-shop-functional` | 3 Juice Shop | Los tests *funcionales* de la API de la ruta siguen pasando | `oracle_juiceshop.py` |
| `juice-shop-exploit` | 3 Juice Shop | Los tests *de ataque* de la ruta dejan de pasar (seguridad dinámica) | `oracle_juiceshop.py` |
| `secbench-exploit` | 30 SecBench | El exploit oficial de SecBench.js deja de funcionar contra el paquete parcheado | `oracle_secbench.py` |
| `secbench-t1-suite` | 17 SecBench | La suite de tests del propio paquete sigue pasando | `oracle_secbench.py` |
| `secbench-t2-differential` | 13 SecBench | Mismo comportamiento que la versión original con entradas benignas preregistradas | `oracle_secbench.py` |

### Preregistro

Fijado antes de que exista ningún parche de la Fase 5 y versionado en
`benchmarks/oracles/`:

- **`juice-shop-api.json`**: los 41 tests de las tres rutas, clasificados como
  `functional` (26) o `vuln` (15), con la justificación de los casos dudosos (p. ej.
  los cuatro tests "SQL Injection fails…" afirman un error SQLITE, es decir, que la
  entrada llega al parser: son de vulnerabilidad). Los 41 pasan sobre la base.
- **`secbench-functional.json`**: para cada caso, el nivel (T1/T2), de dónde salen
  los tests (tarball o repositorio en el commit de la etiqueta de la versión) y el
  comando curado, o el driver T2, con su validación. Lo valida
  `scripts/benchmarks/secbench_oracle_register.py`.
- **`t2/`**: los 13 drivers diferenciales con sus entradas benignas.

### Juice Shop

Los tests de API se ejecutan dentro del worktree parcheado con el runner nativo de
Node (reporter JUnit, porque nombra cada test). El worktree no tiene
`node_modules` ni artefactos de build, así que se **enlazan** (junctions de
Windows) los de tu checkout: `node_modules`, `build` y `frontend/dist`. Los dos
últimos solo satisfacen las precondiciones de arranque de Juice Shop (que los
ficheros existan): los tests importan `server.ts` y ejecutan las rutas TypeScript
del worktree con tsx, es decir, el código parcheado.

**Seguridad de los enlaces.** `git worktree remove --force` borra el contenido no
versionado; si entrara en un enlace, vaciaría tus carpetas reales. Por eso los
enlaces se quitan siempre al acabar el oráculo y, además, `worktree.remove` los
quita antes de llamar a git (por si el proceso muere a mitad). Comprobado:
borrando el worktree con los enlaces todavía dentro, `node_modules` (848
entradas), `build` (448) y `frontend/dist` (764) quedan intactos.

Dos detalles encontrados al validarlo: el reporter JUnit de Node escapa dos veces
las comillas de los nombres (`&amp;quot;`), y un test preregistrado que no
aparece en el informe se trata como error del oráculo, no como fallo del parche.

### SecBench.js: exploit

`run_case.sh` acepta `PATCHED_SRC`: instala la versión vulnerable publicada y
sobrescribe `node_modules/<paquete>` con el `src/` parcheado del worktree.
`src/` es exactamente el tarball de npm de esa versión (`npm pack`), así que lo
único que cambia es el parche. Validación: sobre la base el exploit funciona; con
el código de la versión corregida oficial (`fixed/`) deja de funcionar
(`set-value`, `dns-sync`).

**Limitación:** el oráculo prueba **el** exploit oficial, no cualquier ataque. El
arreglo oficial de `dns-sync` es incompleto (etiquetado UNCERTAIN en el triaje,
D3) y aun así supera este exploit.

### SecBench.js: T1 (suite del propio paquete)

`run_suite.sh` ejecuta la suite sobre el `src/` montado (base o parcheado) en el
harness de Node 16. Si el tarball no trae los tests, se toman del repositorio
original en el commit de la etiqueta de la versión (caché fuera del repo, sin
`.git`). Las dependencias se guardan en un volumen de Docker por caso, de modo que
cada ejecución tarda 2–17 s.

**Criterios de un comando T1.** Se excluyen los linters (`xo`, `standard`,
`eslint`, `jshint`) y los umbrales de cobertura (`--100`, `-t 100`), porque no
son regresiones funcionales. También se excluyen los tests que ya fallan sobre la
base (2 de *tree-shaking* en underscore, 1 de hoek, 2 ficheros de tough-cookie).

**Falsos "pasa" detectados por el sondeo:** `madlib-object-utils` sale con 0 si
falta grunt; el mocha 1.x de `dns-sync`, `forwarded` y `fresh` sale con 0 en
Node 16 sin ejecutar nada (se fija mocha 5.2); `hosted-git-info` sale con 0 sin
tests en el tarball; `tough-cookie` igual.

**Control de sensibilidad.** Que la suite pase sobre la base no basta: tiene que
llegar al código vulnerable. El registro ejecuta además la suite sobre un
**mutante** con `throw` insertado justo antes de la línea del sink, y exige que
falle. Si el `throw` rompe la sintaxis (sink dentro de una expresión multilínea),
se inserta al inicio del fichero y la sensibilidad queda como `module-load`, más
débil (jsonpointer, libnested, forwarded).

| Resultado | Casos |
|---|---|
| **T1 válido (17)** | underscore (203 tests), bestzip (77), connection-tester, dns-sync, dset (12), hoek (194), json-ptr (195), jsonpointer, libnested (30), madlib-object-utils (8), set-value (26), color-string, forwarded (4), fresh (22), hosted-git-info (3.246), is-email, tough-cookie |
| **Rechazado por sensibilidad → T2 (5)** | apex-publish-static-files, diskusage-ng, macaddress, whereis, m-server: pasan sobre la base pero siguen pasando con el `throw` en el sink |
| **Sin suite utilizable → T2 (8)** | pixl-class, portprocesses, serve-here.js (sin tests); giting, tinyserver2 (repositorio inaccesible); async-git (sin etiqueta de la versión); react-dev-utils, thi.ng-egf (monorepos) |

D9 estimaba "hasta 25" casos T1; tras exigir que la suite llegue al sink quedan
17. Riesgo declarado: los tests de `connection-tester` y `dns-sync` usan la red
(TCP a hosts públicos, DNS); un fallo ahí debe contrastarse con la conectividad.

**El ejemplo de D9, medido.** Un parche saboteador para `set-value` (`return
target;` como primera línea de `set()`) **engaña al exploit** ("the exploit no
longer succeeds") y **T1 lo detecta** (23 de 26 tests fallan). Sin oráculo
funcional, contaría como arreglo.

### SecBench.js: T2 (diferencial)

Para los 13 casos sin suite válida, un **driver** preregistrado
(`benchmarks/oracles/t2/<caso>.js`) llama al mismo punto de entrada que ataca el
exploit, pero con **entradas benignas** fijadas antes de cualquier parche, y
devuelve lo observable. `run_diff.sh` instala la versión vulnerable dos veces
(original, y con el `src/` parcheado encima) y `diff_runner.js` ejecuta cada
entrada contra cada instalación **en un proceso nuevo** (sin estado compartido) y
compara. Una diferencia en cualquier entrada es una regresión funcional.

Qué se observa, según la clase:

| Clase | Observación |
|---|---|
| command-injection (10) | `child_process` interceptado: los comandos se registran como **argv**, no como texto, para que formas equivalentes coincidan (`exec("git reset 'x'")` = `execFile("git", ["reset", "x"])`); las tuberías se separan en segmentos y `echo X \| cmd` se registra como `cmd` con X por stdin (= `execFileSync(cmd, args, {input: X})`). Las salidas falsas de los comandos son plausibles (`df`, `lsof`, `ifconfig`…) para que el código llegue a procesarlas. Se compara también el valor devuelto |
| path-traversal (3) | El servidor real se arranca sobre un sitio de prueba fijo y se compara la respuesta (estado, tipo, cuerpo) a rutas legítimas, a un listado de directorio y a un fichero inexistente |
| code-injection (pixl-class) | El comportamiento de las clases que crea `create()`: constructor heredado, métodos, estáticos, mixins |

Decisiones de diseño de los drivers (documentadas en cada uno): `macaddress`
simula `darwin` para llegar a `lib/unix.js` (en Linux carga `lib/linux.js`; por eso
su suite T1 no llegaba al sink); `whereis` no prueba el caso "no encontrado",
que solo llega a ramas exclusivas de Windows que un arreglo puede eliminar con
razón; `tinyserver2` no prueba un fichero inexistente, porque el original responde
200 con cuerpo vacío y un arreglo puede pasar a 404 con razón.

**Validación** (misma regla que T1): sobre la base, original y copia dan las
mismas observaciones en todas las entradas (también comprueba que el driver es
determinista); con el `throw` antes del sink, alguna entrada cambia. Los 13
drivers la superan (`thi.ng-egf` con sensibilidad `module-load`: su sink está
dentro de una expresión flecha). Además se revisó que lo observado tiene sentido,
no solo que coincide.

### ¿Aceptan los oráculos los arreglos correctos?

Contraprueba: se aplicó como "parche" la versión corregida oficial de los 10 casos
que la tienen vendorizada (`fixed/`), con los tres oráculos:

| Resultado | Casos |
|---|---|
| Exploit: **acepta los 10** | — |
| Funcional: acepta | underscore, connection-tester, dns-sync, madlib-object-utils, hosted-git-info |
| Funcional: rechaza por un **defecto real del arreglo oficial** | **giting** 0.0.8: aplica `encodeURIComponent` a la rama, así que `feature/login` pasa a `feature%2Flogin` y las ramas con `/` dejan de funcionar |
| Funcional: rechaza por **cambios ajenos** de la nueva versión | set-value 4.0.1 (versión mayor, cambia la API), hoek 5.0.3 (cambian `escape*` y errores de base64), jsonpointer 5.0.0 (el tarball ya no trae `test.js`), serve-here.js 1.2.0 (nueva dependencia `commander` que la 1.1.0 no instala) |

Ningún rechazo es un error del oráculo. Los cuatro por cambios ajenos son el
motivo por el que D9 descartó comparar contra la versión corregida: los parches del
agente son de un solo fichero y no arrastran esos cambios.

**Prueba de punta a punta con oráculos** (CodeQL, worktrees y LLM con guion, SQLi
de `login.ts`): el parche cosmético se rechaza por CodeQL (reubicado) **y** por el
oráculo dinámico (5/5 ataques siguen funcionando); el arreglo del PR #7 da FIXED,
13/13 funcionales y 0/5 ataques → ACCEPTED en el intento 2.

```bash
python scripts/ai_agent/oracle_juiceshop.py --tree . --target src/app/juice-shop/routes/login.ts
python scripts/ai_agent/oracle_secbench.py exploit --tree . --case prototype-pollution/set-value_3.0.0
python scripts/ai_agent/oracle_secbench.py suite --case prototype-pollution/set-value_3.0.0
python scripts/ai_agent/oracle_secbench.py diff --case command-injection/async-git_1.13.1
python scripts/benchmarks/secbench_oracle_register.py [caso ...]   # revalidar el preregistro (T1 y T2)
```

## Etiquetado y escalado (4.9)

`publish.py` convierte el resultado del bucle en lo que recibe la persona que
revisa. **Solo se abre un PR para un parche verificado**, el intento que el bucle
aceptó. Un caso escalado no tiene parche verificado, así que no se sube código: se
abre un *issue* con cada intento, su diff y el motivo del rechazo.

| Resultado del bucle | Se publica como | Etiquetas |
|---|---|---|
| ACCEPTED con evidencia completa | PR | `ai-fixed` |
| ACCEPTED con salvedades | PR, con sección "Por qué revisar con especial atención" | `ai-fixed` + `ai-needs-review` |
| ESCALATED tras 3 intentos | issue | `ai-escalated` |

Todo PR sigue necesitando aprobación humana (postura asistiva): las etiquetas solo
dicen cuánto cubre ya la verificación automática.

**Salvedades** (reglas fijas; cada una añade `ai-needs-review` y se explica en el
PR):

- Ningún oráculo funcional o de exploit cubre el hallazgo. Es el caso de los
  candidatos fuera de los 33 del dataset, que solo verifica CodeQL.
- El oráculo funcional es el más débil: diferencial (T2), o una suite T1 con
  sensibilidad `module-load`.
- El parche también cambió otros hallazgos (DISAPPEARED, o RELOCATED aparte del
  objetivo): efectos más allá del arreglo.

El PR incluye la tabla de verificación (CodeQL y cada oráculo con su resultado),
los intentos anteriores si los hubo (con el motivo de cada rechazo) y el parche.

`triage_engine.py` encadena ya todo: triaje → (si TP) bucle reflexivo con CodeQL y
oráculos → publicación. Por defecto es dry-run (muestra el PR o el issue que
crearía); `--commit` crea la rama local; `--open` publica (push + PR, o issue). El
triaje también se guarda en el registro, y al relanzar no se vuelve a pagar.

Validación offline (12 comprobaciones): evidencia completa → solo `ai-fixed`;
historial de intentos en el PR; candidato sin oráculos → `ai-needs-review` con 2
salvedades; T2 y T1 `module-load` → salvedad; T1 con sensibilidad en la línea
del sink → sin salvedad; efectos colaterales; escalado → issue sin diff; dry-run
del PR con el parche real del PR #7 (se aplica y muestra las etiquetas).

**Demo real de punta a punta (17-11-2026,
[PR #10](https://github.com/JRR-cyber/tfm-devsecops-ai/pull/10), borrador, no se
fusiona).** gpt-oss-120b (plan gratuito, zero-shot con traza y RAG) sobre la SQLi
de búsqueda (JS-02, `search.ts:23`):

| | Intento 1 | Intento 2 |
|---|---|---|
| Parche | Consulta parametrizada **con** `type: QueryTypes.SELECT` | Consulta parametrizada, sin `type` |
| CodeQL | FIXED, 0 NEW | FIXED, 0 NEW |
| Ataques (9) | 0 funcionan | 0 funcionan |
| Funcionales (6) | **6 fallan** | 6 pasan |
| Resultado | rechazado | **ACCEPTED** → PR `ai-fixed` |

El primer parche eliminaba la vulnerabilidad y CodeQL y el exploit lo daban por
bueno, pero `QueryTypes.SELECT` cambia lo que devuelve `sequelize.query` (filas
en lugar de `[filas, metadatos]`), y el `.then(([products]) => …)` siguiente se
quedaba con la primera fila: **la búsqueda de productos quedaba rota**. Es el
caso que motivó D9, esta vez producido por el modelo real; el bucle lo corrigió
con el feedback de los tests. Etiqueta `ai-fixed` sin salvedades (hay oráculo
funcional y de ataque; el hallazgo vecino de la línea 22 no cambió). Coste del caso
completo (triaje y 2 intentos): 4.700 + 1.227 tokens (~$0,0014); 4 s de LLM y
188 s de rescan: el cuello de botella es CodeQL, no la API.

Fallo encontrado por la demo: el cuerpo del PR (con emojis) se enviaba a `gh` con
la codificación de la consola de Windows (cp1252) y la creación del PR falló
**después** del push. Ahora el texto va en UTF-8, se comprueba el push y, si falla
la creación del PR, el informe lo dice (la rama queda subida) en vez de terminar
con una traza.

```bash
python scripts/ai_agent/publish.py labels [--apply]      # crea/actualiza las 3 etiquetas en GitHub
python scripts/ai_agent/triage_engine.py unified/findings.sarif --repo-root . \
    --fingerprint <fp> --run [--strategy cot] [--commit] [--open]
```

## Ensayo de punta a punta (4.10)

`run_dataset.py` pasa los 33 casos del dataset por el agente completo bajo una
condición (estrategia × traza × RAG): triaje → si TP, bucle reflexivo con CodeQL y
los oráculos de D9 → decisión de publicación. La publicación es siempre **dry-run**:
el texto del PR o del issue va al informe y no se sube nada, porque el dataset es el
benchmark (las demos usan `triage_engine.py --open --draft` sobre un hallazgo). El
mismo script servirá para la rejilla de la Fase 5, condición a condición.

**Objetivo preregistrado por caso.** `dataset.csv` identifica cada caso por su
*sink* (fichero + línea), pero el bucle juzga FIXED sobre **un** fingerprint, y cerca
del *sink* CodeQL suele dar más de un hallazgo con traza (11 de 33 casos: dos reglas
en la misma línea o el mismo flujo marcado en varias líneas). La correspondencia
caso → hallazgo se fija antes de cualquier parche en
[`benchmarks/remediation-targets.csv`](../../benchmarks/remediation-targets.csv)
(`scripts/benchmarks/remediation_targets.py`), con una regla determinista: CodeQL
con traza en la ventana de ±10 líneas de C7, regla aceptada por C7 para el caso, el
más cercano al *sink* y, en caso de empate, por regla y fingerprint. Regenerado con
el SARIF de CI de `84ce0be` y el de `1e6ca25`, sale idéntico: los fingerprints no
dependen de la línea. En SecBench, los demás hallazgos de la ventana siguen en el
código, pero el exploit comprueba la vulnerabilidad completa.

**Hallazgo: solo 12 de los 33 casos pasan el filtro CVSS ≥ 7.** CodeQL puntúa por
*regla*, no por vulnerabilidad: `js/shell-command-*` vale 6.3 y
`js/prototype-polluting-assignment` y `js/unsafe-code-construction` valen 6.1. Pasan
los 3 de Juice Shop (8.8), los 3 de path traversal y los 6 de ReDoS (7.5). Las 12
inyecciones de comandos, las 7 contaminaciones de prototipo y las 2 inyecciones de
código quedan por debajo. Comparado con el CVSS v3 de NVD de cada CVE
([`nvd-cvss.csv`](../../benchmarks/nvd-cvss.csv)), CodeQL y NVD solo coinciden en el
lado del umbral en 6 de 29 casos, con errores en las dos direcciones. Decisión
([D11](../../docs/benchmark/decisions.md)): la RSR se mide sobre los 33 y se desglosa
por los dos subconjuntos. El umbral sigue siendo la política de producción de
`triage_engine.py`. `run_dataset.py` repara todos los casos por defecto, y `--policy`
aplica el filtro: los casos por debajo solo pasan por el triaje.

**Por tandas en el plan gratuito.** El prompt más grande del dataset ronda los 2K
tokens de entrada, muy por debajo del límite de 8K por minuto. Una pasada completa
con aceptación en el intento 1 son ~100K tokens, y con reintentos se esperan
150–250K: 1–2 días de cuota. Si se agota, el lote escribe el informe hasta donde
llegó, dice cuándo relanzar y sale con el código 75. Al relanzar el mismo comando no
se repite nada. Antes de gastar tokens, la comprobación previa verifica la clave,
CodeQL, Docker, la imagen del harness, el build de Juice Shop y que los 33
fingerprints estén en el SARIF.

```bash
# Git Bash, desde la raíz; GROQ_API_KEY y CODEQL_CLI exportadas, Docker arrancado
gh run download <run de main> -n unified-findings -D ci
python scripts/ai_agent/run_dataset.py ci/findings.sarif                 # todos, zero-shot, traza + RAG
python scripts/ai_agent/run_dataset.py ci/findings.sarif --only JS-02    # un caso
python scripts/ai_agent/run_dataset.py ci/findings.sarif --report-only   # informe desde el log
python scripts/ai_agent/results.py summary results/dev/rehearsal-4.10.jsonl
```

El informe (`results/dev/rehearsal-4.10.md`) tiene una fila por caso con el
triaje, el resultado (ACCEPTED / ESCALATED / NOT_TP / POLICY / PENDING), la
secuencia de intentos con los oráculos que fallaron, las etiquetas, los tokens y los
tiempos, además del texto que se habría publicado. Validación offline (Groq y
verificador simulados, SARIF y log reales): 19 comprobaciones, incluidas la parada
por cuota a mitad de lote y a mitad de bucle, la reanudación sin llamadas repetidas,
el informe reconstruido sin llamadas y `--policy`.

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
- **`oracle_juiceshop.py`**, **`oracle_secbench.py`** — oráculos de D9 (Paso 4.8)
  sobre el worktree parcheado. Ver "Oráculos de verificación de D9" arriba.
- **`publish.py`** — etiquetado y escalado (Paso 4.9): PR `ai-fixed` [+
  `ai-needs-review`] o issue `ai-escalated`. Ver "Etiquetado y escalado" arriba.
- **`rescan.py`** — rescan local post-parche con CodeQL CLI (Paso 4.2), con la
  misma versión y suite que CI y el SARIF con forma de artefacto unificado. Ver
  "Rescan local con CodeQL" arriba.
- **`worktree.py`** — worktrees aislados para aplicar y verificar parches (Paso
  4.1). Ver "Aislamiento con worktrees" arriba.
  ```bash
  python scripts/ai_agent/worktree.py list
  python scripts/ai_agent/worktree.py remove fix/ai-remediation-<regla>-<fp8> [--delete-branch]
  ```
- **`triage_engine.py`** — orquestador: encadena parse → filtro (CVSS≥7 ∩ traza)
  → triaje → (si TP) bucle reflexivo con verificación (4.7–4.8) → PR o issue
  (4.9). Sin argumentos
  lista los candidatos; con `--fingerprint … --run` ejecuta un hallazgo de punta a
  punta.
  ```bash
  python scripts/ai_agent/triage_engine.py unified/findings.sarif --repo-root .   # lista candidatos
  ```
- **`run_dataset.py`** — el agente completo sobre los 33 casos del dataset, bajo una
  condición, reanudable y con parada limpia por cuota; publicación en dry-run e
  informe en markdown (4.10, reutilizable en la Fase 5).
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
