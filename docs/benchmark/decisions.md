# Registro de decisiones del dataset

Decisiones de diseño del conjunto experimental, con su motivo y su fecha. Alimenta el capítulo de gestión de proyecto de la memoria (Fase 6). La más reciente arriba.

## D12 — Protocolo de la Fase 5: rejilla completa, 3 pasadas, todo en Together (2026-11-25)

> **Aprobada por el autor el 25-11-2026.** Se congela con el tag `phase5-protocol` cuando esté implementada la preparación (5.0). Hasta entonces se puede ajustar sin coste, porque no existe ningún dato de la Fase 5.

**Contexto.** La rejilla completa de la Fase 5, con 3 pasadas de remediación, necesita del orden de 5–7M tokens. En el plan gratuito de Groq (200K/día) serían más de 3 semanas, y el plan Developer no se puede contratar: el 22-11-2026, el soporte de Groq respondió que las altas están pausadas y sin fecha. Tres semanas expuestos a un cambio de límites o a la retirada del modelo, como la de Llama 3.3 en agosto, ponen en riesgo el diseño *within-subject*. Se evaluó servir el mismo modelo de pesos abiertos desde Together AI con un piloto con criterios fijados antes de la primera llamada ([`piloto-proveedor.md`](piloto-proveedor.md)): 4 pasadas de los 33 casos, 2 en Groq y 2 en Together. **Se cumplieron C1–C6**: entrada idéntica salvo un desfase constante de plantilla, el acuerdo entre proveedores dentro del ruido de cada uno, el mismo formato, el mismo nivel de razonamiento y el coste del panel igual al estimado.

**Decisión.**

1. **Proveedor y modelo.**
   - Toda la Fase 5 se ejecuta en Together AI (*serverless*) con `openai/gpt-oss-120b`, con estos parámetros fijos:
     - `reasoning_effort=medium`, `temperature=0`, `max_tokens=16384`;
     - timeout de 180 s;
     - tope de gasto propio por log (`LLM_BUDGET_USD`), además del prepago.
   - **Nunca se mezclan proveedores.** Los ensayos del 4.10 y el piloto en Groq son desarrollo y no entran en el análisis.
   - **Si el modelo servido cambia a mitad** (`model_served` distinto, o aviso de retirada o actualización de Together), se paran las ejecuciones y se repite entero el experimento afectado. Si Together retira el modelo, se repite el piloto con DeepInfra con los mismos criterios.
   - Es una desviación del roadmap («Groq API») en la infraestructura, no en el modelo, que es la constante del diseño.

2. **Experimento de triaje.**
   - **Conjunto:** 83 hallazgos, las 53 filas de `labels.csv` más los 30 objetivos de SecBench.js, que son TP con exploit. Los 3 de Juice Shop ya están en `labels.csv`.
   - **Unidad de análisis:** la vulnerabilidad (`vuln_group`), como en [`dataset.md`](dataset.md): **77 grupos**, con 47 TP, 22 FP y 8 UNCERTAIN.
     - El agente triaja las 83 filas, como haría en producción.
     - Solo 5 grupos tienen más de una fila: 2 TP (con 3 y 2 filas) y 3 FP (con 2 filas cada uno).
     - **En las pruebas estadísticas**, cada grupo puntúa con la proporción de sus filas que el agente acierta. Así cada vulnerabilidad pesa una vez, no se pierde información y no hace falta una regla de agregación arbitraria.
     - **La FPR y la TPR «de producción»** usan la regla del pipeline: el grupo cuenta como TP si lo es cualquiera de sus filas, porque el pipeline lo mandaría a remediar. Se informan de forma descriptiva.
     - **Sensibilidad:** se repiten las pruebas por fila (83).
   - **Rejilla:** 3 estrategias (zero-shot, few-shot, CoT) × 3 contextos, es decir, 9 celdas y 747 llamadas por pasada. Los contextos son:
     - *completo*: traza + RAG, el agente de producción;
     - *ciego*: sin traza, con RAG; es el control del paso 5.3;
     - *sin RAG*: traza sin RAG.
   - **Pasadas: 3.** Cada pasada cuesta unos $0,4 y una hora, sin CodeQL.
   - Si el agente responde UNCERTAIN, cuenta como «no TP», igual que en producción.

3. **Experimento de remediación.**
   - **Conjunto:** los 33 casos (D11), con `--repair-all`: se repara cada caso sin depender del veredicto del triaje.
   - **Rejilla:** 3 estrategias × traza sí/no, es decir, 6 condiciones. El RAG va siempre activo, porque sin el código no se puede parchear.
   - **Pasadas: 3**, con un máximo de **3 intentos** del bucle reflexivo por caso, en todas las condiciones y pasadas (regla fija del proyecto).
   - **Few-shot de remediación con 3 ejemplos sintéticos** (inyección SQL, inyección de comandos y path traversal), ninguno sacado del dataset. Ahora tiene uno solo, de SQLi, pero 30 de los 33 casos son de otras clases: con un ejemplo, la condición mediría ese ejemplo y no la estrategia. El few-shot de triaje se queda como está, con 2 ejemplos sintéticos (TP y FP).

4. **Métricas.**
   - **Triaje.** Todas se calculan por condición y por pasada:
     - *acierto*: veredicto igual a la etiqueta, sobre los 69 grupos TP + FP;
     - *FPR*: grupos FP que el agente llama TP, sobre 22;
     - *TPR*: grupos TP que el agente llama TP, sobre 47;
     - *UNCERTAIN*: se informan aparte, con análisis de sensibilidad contándolos como TP y como FP;
     - *estabilidad entre pasadas*: κ de Fleiss.
   - **Remediación.**
     - *RSR* = ACCEPTED/33, por pasada y en media. Se desglosa por los subconjuntos CodeQL ≥ 7 (12) y NVD ≥ 7 (24) de D11, y por nivel de oráculo (Juice Shop, T1, T2) de D9.
     - *Convergencia*: en qué intento se acepta.
     - *Regresión*: fallo funcional o hallazgo NEW en parches que CodeQL da por FIXED.
     - *Desacuerdo* entre CodeQL y el exploit.
     - *Overhead*: tokens, segundos de LLM, de rescan y de oráculos.
     - *RSR de punta a punta*, con el triaje de la misma ejecución como filtro: métrica secundaria.

5. **Análisis estadístico.** Se escribe y se prueba con datos simulados antes de la primera llamada.
   - **Puntuación por unidad:** la proporción de aciertos en las 3 pasadas.
     - En triaje, sobre filas × pasadas del grupo; en un grupo de una sola fila, 0, ⅓, ⅔ o 1.
     - En remediación, la proporción de pasadas en que el caso se acepta.
     - Así la variabilidad del modelo entra en el diseño en vez de quedar como ruido.
   - **Preguntas de investigación.** El TFM se plantea con preguntas, no con hipótesis formales. Cada pregunta se responde con un contraste estadístico, con α = 0,05 y corrección de Holm dentro de cada pregunta. En términos estadísticos, cada prueba contrasta la hipótesis nula de «no hay diferencia».
     - **PI1. ¿La traza de taint mejora el triaje?** Completo frente a ciego, en acierto, con Wilcoxon de rangos con signo para cada estrategia. Es la pregunta central.
     - **PI2. ¿Qué estrategia de prompting triaja mejor?** Friedman entre las 3 estrategias en el contexto completo y, si es significativo, Wilcoxon dos a dos.
     - **PI3. ¿Qué estrategia de prompting remedia mejor?** Friedman entre las 3 estrategias con traza y, si es significativo, Wilcoxon dos a dos.
     - **PI4. ¿La traza mejora la remediación?** Con frente a sin traza, con Wilcoxon para cada estrategia.
     - **PI5. ¿El RAG mejora el triaje?** Completo frente a sin RAG, con Wilcoxon para cada estrategia. La interacción entre RAG y estrategia se describe, sin contraste.
   - **Componentes:** FPR y TPR se contrastan como secundarios, con las mismas pruebas sobre los grupos FP y TP.
   - **Tamaños de efecto:**
     - W de Kendall para Friedman;
     - correlación biserial de rangos para Wilcoxon;
     - diferencia de proporciones con IC del 95 % por *bootstrap* sobre las unidades.
   - **Sensibilidad:** se repiten las pruebas solo con la pasada 1, binaria, con Q de Cochran y McNemar exacto. Si la conclusión cambia, se informa.
   - **Control de memorización (5.3), exploratorio:** acierto en la condición ciega de Juice Shop, conocido públicamente, frente a SecBench.js, con paquetes poco conocidos. Se informa de forma descriptiva y con Mann-Whitney. En remediación, Juice Shop solo aporta 3 casos.

6. **Ejecución.**
   - **Orden:** las tres pasadas de triaje y después las tres de remediación.
   - **Orden intercalado dentro de cada pasada:** cada bloque de casos recorre todas las condiciones, en un orden aleatorio con semilla fija (20261125). Así ni la hora ni el día quedan confundidos con la condición.
   - **Logs versionados:**
     - ruta `experiments/phase5/<experimento>-p<pasada>.jsonl`, porque `.gitignore` ignora `results/`;
     - se commitean al terminar cada tanda;
     - cada fila lleva la pasada, el proveedor, el modelo servido y `agent_commit`.
   - **Congelación:** todo se ejecuta desde el commit con el tag `phase5-protocol`. Un cambio del agente después de congelar obliga a repetir enteras las condiciones afectadas y se declara.
   - **Fallos de infraestructura** (Docker, CodeQL, red): el intento no se registra y se retoma desde el log, como en el piloto.
   - **Coste estimado:** unos $3 en total, sobre un saldo de $14,77. Duración: unas 30 h de CodeQL en la máquina local, la mayor parte en la remediación.

**Motivo.** El proveedor es la única forma de ejecutar la rejilla completa con 3 pasadas en el calendario de las semanas 7–8 sin exponer el diseño a semanas de cambios en Groq. El piloto muestra que el cambio de infraestructura no se distingue del ruido propio del modelo. Las 3 pasadas convierten esa variabilidad en un dato por unidad en lugar de un error de medida, y las pruebas de Friedman y Wilcoxon sobre esas proporciones son las del roadmap. Fijar todo antes de la primera llamada evita ajustar el análisis a los resultados.

**Consecuencia.**
- **Preparación pendiente (paso 5.0), antes de congelar:**
  - ejecutor de triaje sobre los 83 hallazgos, con log y reanudación;
  - campo de pasada en `RunKey`;
  - los 3 ejemplos sintéticos de remediación;
  - orden intercalado con semilla;
  - script de análisis probado con datos simulados;
  - incorporar a `main` el soporte de proveedor de la rama `exp/proveedor-piloto`.
- **Documentación al adoptar D12:** `CLAUDE.md` y `scripts/ai_agent/README.md` («Decisión de modelo»), donde dice «Groq API».
- **Amenazas a la validez:**
  - el proveedor no es el del roadmap;
  - el *overhead* absoluto es el de Together, que tarda unas 2,7 veces más por llamada que Groq en el piloto;
  - los ejemplos de few-shot cubren 3 de las clases del dataset, y se informa por clase;
  - los términos de Together (§4c) prohíben el *benchmarking*. Se interpreta que la Fase 5 evalúa estrategias de prompting de un modelo, no al proveedor. Es una lectura del autor, sin consulta a Together.

## D11 — La RSR se mide sobre los 33 casos; el umbral CVSS ≥ 7 es política del pipeline, no criterio del experimento (2026-11-18)

**Contexto.** Al preparar el ensayo del 4.10 se fijó el hallazgo objetivo de cada caso ([`remediation-targets.csv`](../../benchmarks/remediation-targets.csv)). Resultado: solo **12 de los 33 casos** pasan el filtro de auto-remediación del roadmap (CVSS ≥ 7.0, paso 3.3). Pasan los 3 de Juice Shop (8.8), los 3 de path traversal y los 6 de ReDoS (7.5). Quedan por debajo las 12 inyecciones de comandos (6.3), las 7 contaminaciones de prototipo y las 2 inyecciones de código (6.1). La causa es que la única severidad que el pipeline tiene de un hallazgo SAST es el `security-severity` de CodeQL, que es **un número por regla**: todos los hallazgos de `js/shell-command-constructed-from-input` valen 6.3, sea cual sea el paquete. CodeQL no puede saber más. Ve un patrón en el código, no un CVE, y en un uso real un hallazgo en código propio no tiene CVE: el CVSS de NVD solo existe aquí porque el dataset se construyó con vulnerabilidades ya publicadas.

**Comprobación con NVD** ([`nvd-cvss.csv`](../../benchmarks/nvd-cvss.csv), `scripts/benchmarks/nvd_cvss.py`, consultado el 18-11-2026). De los 30 CVE de SecBench.js, 29 tienen CVSS v3 en NVD (dns-sync, de 2014, solo v2: 10.0). **CodeQL y NVD coinciden en el lado del umbral en solo 6 de 29**, y se equivocan en las dos direcciones:

| | NVD v3 ≥ 7 | NVD v3 < 7 |
|---|---|---|
| CodeQL ≥ 7 | 5 (tinyserver2, forwarded, fresh, is-email, tough-cookie) | 4 (m-server 6.5, serve-here.js 5.3, color-string 5.3, hosted-git-info 5.3) |
| CodeQL < 7 | 19 (15 de ellos con 9.8–10.0) | 1 (react-dev-utils 5.6) |

**Decisión.** La tasa de éxito de la remediación (RSR) y las demás métricas de remediación de la Fase 5 se miden sobre **los 33 casos**. Además se dan desglosadas por el subconjunto que pasa el filtro con la severidad de CodeQL (12) y por el que pasa con la de NVD v3 (24, todos de SecBench.js: los de Juice Shop no tienen CVE). El filtro CVSS ≥ 7 se mantiene como **política del pipeline en producción**: `triage_engine.py` solo auto-remedia los candidatos que lo cruzan y reporta el resto. El ejecutor de experimentos (`run_dataset.py`) lo ignora por defecto, y `--policy` reproduce el comportamiento de producción.

**Motivo.** El umbral responde a "qué debe arreglar el agente sin que nadie se lo pida". La RSR responde a otra pregunta: si el agente sabe arreglar una vulnerabilidad confirmada cuando se le pide. Los 33 casos son vulnerabilidades reales con exploit, seleccionadas antes de cualquier parche (C1–C8). Aplicar el filtro dejaría N = 12, que es poco para Friedman/Wilcoxon, y además una selección decidida por una puntuación por regla que, según NVD, se equivoca en 23 de 29 casos. El filtro no cambia el procedimiento de reparación de cada caso, así que los 12 dan el mismo resultado en las dos lecturas.

**Consecuencia.** Es una desviación de la letra del roadmap ("auto-remediación solo para CVSS ≥ 7.0") en el *experimento*, no en el pipeline. Se declara en "Amenazas a la validez". La limitación del filtro también es un resultado: un umbral sobre la severidad por regla de una herramienta SAST no prioriza bien, y priorizar por severidad real necesitaría contexto que el SAST no tiene (alcanzabilidad desde la red, impacto).

## D10 — Checkpoint de la Fase 3: alcance completo, recortando profundidad dentro de cada fase (2026-11-13)

**Contexto.** El roadmap cierra la Fase 3 con un punto de decisión: seguir con el alcance completo o recortar las Fases 4–5. Al cerrarla (3.1–3.7 completos; PR demo #7, en el que CodeQL deja de detectar la SQLi de `login.ts:34`) había estas señales: gpt-oss-120b flojo descartando falsos positivos, la traza aporta sobre todo *alcanzabilidad*, el RAG es lo que mueve los FP, y los parches son de buena calidad pero sus diffs no se aplican con `git apply` (cabeceras `@@` vacías).

**Decisión.** **No se recorta ninguna fase**; se recorta profundidad dentro de cada una.

- *Fase 4, se mantiene lo esencial*: rescan con emparejamiento por fingerprint, bucle reflexivo de 3 intentos, etiquetado y escalado de PRs.
- *Fase 4, se simplifica*: en cada intento se reescanea solo con CodeQL el proyecto del hallazgo, no el pipeline entero (aplicado en 4.2: alcance por proyecto, con la equivalencia con CI medida). El oráculo funcional se planteó inicialmente como "exploit + prueba de humo" en SecBench; **D9 lo sustituye por uno más fuerte** (suite del paquete y diferencial).
- *Fase 5, el riesgo es la API, no el diseño*: la rejilla es grande (triaje ≈ 53 hallazgos × 3 estrategias × {sin traza, traza, traza+RAG}; remediación hasta ~300 llamadas), el límite gratuito de Groq ya frenó las pruebas y Groq ya retiró un modelo (Llama 3.3 70B). Mitigaciones: guardar cada resultado en disco con reanudación (hecho en 4.5), fijar la rejilla antes de ejecutar, lanzar los experimentos pronto y valorar el plan de pago de Groq con un tope de gasto (coste estimado de la rejilla completa: ~1–2 USD).
- *Orden de recorte si el calendario aprieta*: primero la remediación de SecBench.js, nunca el triaje (es el que responde a la pregunta de investigación sobre la traza).

**Motivo.** Cada fase sostiene una parte de la tesis: sin la Fase 4 no se puede afirmar que los parches funcionan (no hay rescan, ni oráculo funcional, ni RSR); sin la Fase 5 no se responde a la pregunta de investigación (si la traza ayuda y qué estrategia es mejor). Recortar una fase entera deja la tesis sin una de sus afirmaciones; recortar profundidad solo reduce su alcance, y eso se puede declarar.

**Consecuencia.** La Fase 4 se ejecuta completa (4.1–4.10). Las simplificaciones se declaran en "Amenazas a la validez" junto con las limitaciones de D9.

## D9 — Oráculos de verificación del parche: seguridad doble y funcional por niveles (2026-11-15)

**Contexto.** D1–D8 crearon oráculos para el **triaje**: el exploit (o la ablación de una guarda) demuestra si una vulnerabilidad es real. En la Fase 4 el agente **modifica el código** y hay dos preguntas nuevas: ¿el parche elimina la vulnerabilidad? y ¿el parche rompe el paquete? Para la segunda no había oráculo (limitación abierta en [`dataset.md`](dataset.md) §7). Sin él, un parche que neutraliza la función entera (p. ej. un `return obj;` al inicio de `set-value`) cuenta como éxito: CodeQL deja de ver el flujo y el exploit falla, pero el paquete ya no funciona. La RSR de la Fase 5 saldría inflada y la métrica de regresión no se podría medir.

**Decisión.**

1. **Oráculo de seguridad, con dos fuentes.**
   - *Estático*: rescan local de CodeQL y comparación por fingerprint (pasos 4.2–4.4).
   - *Dinámico*: se ejecuta el **exploit contra el código parcheado**. En SecBench.js, el exploit del harness con una variante de `run_case.sh` que instala el código local del worktree en lugar de la versión publicada en npm. En Juice Shop, los tests de ataque de su propia suite y los exploits de la evidencia de triaje.
   - Si CodeQL da FIXED pero el exploit sigue funcionando, el resultado es **arreglo incompleto** y se reporta como tal.
2. **Oráculo funcional, por niveles.** Cada caso queda etiquetado con el nivel que se le aplica, y los resultados se reportan por nivel.

   | Nivel | Casos | Oráculo |
   |---|---|---|
   | Juice Shop | 3 | Los ficheros de tests de API de la ruta tocada (`login`, `search`, `product-review`: 41 tests). Cada test se clasifica **antes de generar los parches** como *de vulnerabilidad* (comprueba que el reto se puede resolver, así que se espera que falle tras un arreglo correcto) o *funcional* (tiene que seguir pasando). |
   | T1: suite original | hasta 25 de 30 | La suite de tests del propio paquete: los ficheros del tarball de npm o, si no vienen, los del repositorio original en la etiqueta de esa versión. Se ejecuta en el harness Docker (Node 16). Primero se ejecuta sobre el código **sin parchear**, y los tests que ya fallan ahí se excluyen. **Regresión = un test que pasaba sobre la base y falla tras el parche.** |
   | T2: diferencial | el resto (≥ 5) | Para los casos sin tests o con una suite que no corre en el harness (toolchain antigua, red), se llama al mismo punto de entrada que usa el exploit con **entradas benignas** y se exige la misma salida que en la versión vulnerable original, normalizada por clase: `argv` de `child_process` interceptado (command-injection), objeto resultante comparado en profundidad (prototype-pollution), valor devuelto (redos, code-injection), respuesta HTTP a un fichero legítimo (path-traversal). Las entradas benignas se fijan **antes de generar los parches**. |

3. **Requisito de preregistro.** La clasificación de los tests de Juice Shop, la lista de tests válidos de T1 y las entradas benignas de T2 se fijan y se versionan antes de que exista ningún parche de la Fase 5, para que el oráculo no se ajuste a los parches.

**Motivo.** Encuesta de los 30 casos SecBench.js del dataset: **25** declaran un script de test real en su `package.json`, **12** incluyen los ficheros de test en el tarball de npm y **5** no tienen tests (`pixl-class`, `giting`, `portprocesses`, `serve-here.js`, `tinyserver2`). Usar la suite del propio paquete cuando existe es el oráculo más fuerte y menos discutible; el diferencial cubre el resto sin dejar casos fuera. Opciones descartadas:

- *Diferencial contra la versión corregida oficial* (la otra opción de `dataset.md` §7): el salto de versión suele traer cambios ajenos al arreglo (refactorizaciones, nuevas opciones), que darían falsas regresiones.
- *Solo comprobar que el módulo carga* (smoke test): demasiado débil; no detecta el ejemplo de `set-value`.
- *Tests generados por un LLM*: circular, el mismo tipo de modelo juzgaría su propio trabajo.

**Consecuencia.** El paso 4.6 solo registra esta decisión. La implementación es el **paso 4.8**: variante local del harness, ejecución de T1 y T2, clasificación de los tests de Juice Shop y conexión del resultado con el bucle reflexivo (4.7), donde un parche que rompe tests cuenta como intento fallido. En "Amenazas a la validez" se declara que T2 es más débil que una suite real, que las suites originales solo cubren lo que cubren y que Juice Shop aporta solo 3 casos.

**Implementación (paso 4.8, 2026-11-17).** Detalle en [`scripts/ai_agent/README.md`](../../scripts/ai_agent/README.md), "Oráculos de verificación de D9"; preregistro en `benchmarks/oracles/`. Se añadió un requisito que D9 no explicitaba: el oráculo funcional tiene que **llegar al código vulnerable**, comprobado con un mutante que inserta un `throw` antes de la línea del sink (la suite o el driver deben fallar con él). Con esa exigencia el reparto queda en **17 casos T1 y 13 T2** (D9 estimaba hasta 25 T1): 5 suites que pasaban sobre la base no llegaban al sink y bajaron a T2. Contraprueba con las versiones corregidas oficiales (10 casos): el exploit las acepta todas; el oráculo funcional acepta 5, rechaza 4 por cambios ajenos de la nueva versión (el motivo para descartar la comparación con la versión corregida) y 1 por un defecto real del arreglo oficial (giting 0.0.8 rompe las ramas con `/`).

## D8 — El conjunto de triaje se limita a hallazgos CodeQL con traza de taint (2026-10-25)

**Decisión.** El conjunto de triaje incluye solo hallazgos de **CodeQL con un `codeFlows` de dos o más pasos** (criterio T1 de [`triage-labels.md`](triage-labels.md)). Quedan fuera: los hallazgos de Semgrep, Trivy (SCA/contenedor) y TruffleHog, y los hallazgos de CodeQL de consultas **sin dataflow** (una sola ubicación, sin `codeFlows`).

**Motivo.** La pregunta de investigación (Paso 5.3) es si la **traza de taint** ayuda al agente a decidir; un hallazgo sin traza no permite medir eso y no tiene el formato que consume el agente. Además fija un criterio de inclusión objetivo y reproducible (la presencia de `codeFlows` en el SARIF), en vez de un recorte manual.

**Consecuencia (embudo, medido sobre `unified/findings.sarif` de CI).** En `src/app/juice-shop/` hay 261 hallazgos con huella única; 27 ya estaban etiquetados (Fases previas + CP1–CP5) y de los 234 restantes solo **16** cumplen T1. Los 218 excluidos son: Semgrep/Trivy/TruffleHog, y 39 alertas de CodeQL sin traza —`js/missing-rate-limiting` (×31), `js/sensitive-get-query` (×3), `js/incomplete-sanitization` (×2), `js/file-system-race` (×2), `js/missing-token-validation` (×1)—. Esos 16 son el alcance de CP6. (Las alertas sin traza son datos válidos para el capítulo de resultados como “lo que el pipeline reporta pero el conjunto de triaje no cubre”, no un olvido.)

## D7 — Estándar de evidencia mixto para acelerar el etiquetado (2026-10-24)

**Decisión.** Mantener la ablación ejecutable (`ABL`) para los casos **no obvios**, y usar un estándar más ligero (`GATE`) para los **FP claros**: citar la guarda en el código y demostrarla con un check reproducible (la entrada maliciosa se rechaza, un control benigno funciona), sin exigir que la ablación llegue hasta el *sink*.

**Motivo.** Las primeras familias (path traversal, vulnCode*) mostraron que la ablación completa de cada FP es muy costosa (contexto único, observables no triviales) y a veces no encaja cuando el contenido leído no se devuelve. Para un dataset de ~50 hallazgos con una fecha de TFM acotada, aplicar `GATE` a los FP evidentes y reservar `ABL` para los dudosos reduce mucho el tiempo sin perder reproducibilidad ni trazabilidad. Toda etiqueta sigue respaldada por un check ejecutable y por la cita del código; `UNCERTAIN` se mantiene para lo que no se puede decidir.

**Consecuencia.** El runner `triage_evidence.py` admite el tipo `GATE` (ejecuta el check una vez; la función se autovalida). Los FP ya etiquetados con `ABL` se conservan.

## D6 — Los falsos positivos también salen de SecBench.js (2026-10-24)

**Decisión.** El conjunto de falsos positivos se toma de Juice Shop **y** de las versiones corregidas de SecBench.js. Se vendorizan **solo** las versiones corregidas de los casos que CodeQL sigue marcando (~10), que son las que aportan hallazgos; las otras 20 no se añaden. **Supersede la parte de D5** sobre la fuente de FP.

**Motivo.** Los FP de paquetes npm poco conocidos son más diversos y menos memorizables que los de Juice Shop, lo que refuerza la prueba de control de memorización (Paso 5.3). Y el coste real es menor de lo que decía D5: **el job de CodeQL escanea todo el repositorio**, así que vendorizar las versiones corregidas basta para que CI las escanee y les asigne huella real; **no hace falta un job nuevo**. El único coste es el tamaño del repo (~10 árboles de paquete, como ya están los vulnerables en `cases/*/src/`) y etiquetar esos hallazgos.

**Consecuencia.** Se restauró la infraestructura de SecBench (`run_evidence`, rama de `triage_evidence.py`). Cada versión corregida marcada se analiza por separado: si el arreglo es real, es FP (evidencia por ablación); si es un arreglo incompleto que sigue siendo explotable, es TP o se retiene (D3). SecBench.js aporta así TP (30 casos vulnerables) y FP (versiones corregidas marcadas) al triaje.

## D5 — [Superada por D6] El conjunto de falsos positivos sale solo de Juice Shop (2026-10-24)

> Superada el mismo día por D6: se decidió incluir también SecBench.js en los FP. Se conserva el registro porque la alternativa se consideró en serio y el razonamiento de reproducibilidad sigue siendo válido.

**Decisión (revertida).** Los falsos positivos se tomarían únicamente de Juice Shop.

**Motivo.** El agente triará lo que haya en `unified/findings.sarif`, con huella `tfmContextHash` calculada por el pipeline ([`unify_results.py`](../../scripts/pipeline/unify_results.py)); Juice Shop ya lo escanea CI entero. Se creía que usar SecBench exigía un job de escaneo nuevo (incorrecto: CodeQL ya escanea todo el repo, ver D6).

**Resultado cualitativo que se conserva.** Al analizar en local las 30 versiones corregidas de SecBench.js con el mismo CodeQL del pipeline, 10 seguían marcadas. La revisión manual confirmó que **dos** de ellas son **arreglos incompletos realmente explotables**: `connection-tester` 0.2.1 y `dns-sync` 0.1.3 (ambas del mismo autor, con la misma validación de host por una regex construida desde un string, donde `\.` queda como `.`; verificado con `a;id>archivo`, y la versión actual de ambas sigue teniendo esa regex). Se retienen (D3): se marcan `UNCERTAIN` y su exploit no se versiona. Es un dato sobre la validez del oráculo de SecBench.js ("corregido según el exploit" ≠ "no vulnerable") que va a la discusión de la memoria.

## D4 — Priorizar los verdaderos positivos con exploit oficial (2026-10-22)

**Decisión.** Al etiquetar, empezar por los verdaderos positivos de Juice Shop que ya tienen un exploit escrito por OWASP (un test de API o Cypress que resuelve el reto), antes que por los que exigen un PoC propio.

**Motivo.** Un TP respaldado por el test oficial del propio benchmark es la evidencia menos discutible posible: la verdad de base la aporta OWASP, no el autor del TFM. Además son los más rápidos de preparar. Los PoC propios y las ablaciones (más laboriosos y más opinables) se dejan para después.

**Consecuencia.** El etiquetado se entrega de forma incremental para que el autor valide cada tanda (petición del autor, misma fecha).

## D3 — `connection-tester` 0.2.1 retenido, no se publica el exploit (2026-10-22)

**Decisión.** El hallazgo de CodeQL en la versión corregida de `connection-tester` (0.2.1) se marca `UNCERTAIN` y su exploit **no se versiona** en el repositorio. No se añade al conjunto de triaje.

**Motivo.** 0.2.1 es la última versión publicada (sin cambios desde 2020) y la validación mostró que el patrón que CodeQL marca sigue presente. Pero:
- Ninguna fuente pública (OSV, GitHub Advisories, Snyk, NVD) documenta la 0.2.1 como vulnerable; el único CVE conocido, CVE-2020-7781, afecta a versiones anteriores.
- En el repositorio del mantenedor hay una incidencia abierta de divulgación responsable (#12, feb. 2026) sin respuesta, lo que sugiere que un tercero ya está en ese proceso.

Publicar un PoC sería divulgar de forma irresponsable una posible vulnerabilidad no confirmada. Validarla o reportarla queda fuera del alcance y del calendario del TFM (decisión del autor). Regla general en [`triage-labels.md`](triage-labels.md), sección 6.

**Consecuencia.** Afecta a 1 de los 30 casos de SecBench.js; el resto del conjunto no se ve afectado.

## D2 — Las etiquetas se respaldan con evidencia ejecutable (2026-10-21)

**Decisión.** Ninguna etiqueta TP/FP depende solo de la lectura del código. Cada una se respalda con un test versionado y reproducible: un exploit que funciona (TP) o un exploit que falla y pasa a funcionar al desactivar la protección citada (ablación, FP). Criterios completos en [`triage-labels.md`](triage-labels.md).

**Motivo.** Una etiqueta basada en el juicio del autor es discutible ante un tribunal. Una basada en una ejecución es reproducible: quien dude la ejecuta. El piloto de 4 hallazgos lo confirmó y además destapó un error de etiquetado por lectura (en `keyServer` faltaba citar una segunda protección, el middleware `serve-index`), que la ablación detectó.

## D1 — Ampliar el dataset con un conjunto de triaje (TP + FP) (2026-10-21)

**Decisión.** Añadir al dataset hallazgos etiquetados como verdadero o falso positivo, incluidos casos de Juice Shop sin `vuln-code-snippet`/*codefix*, y las versiones corregidas de SecBench.js como fuente de falsos positivos.

**Motivo.** El dataset original ([`dataset.md`](dataset.md)) solo tenía vulnerabilidades confirmadas, con lo que no permite medir la tasa de falsos positivos ni comparar la decisión del agente con y sin traza (Paso 5.3), que es el núcleo de la pregunta de investigación. Además, Juice Shop aportaba solo 3 casos con traza, los más memorizables.

**Consecuencia.** El dataset pasa a tener dos subconjuntos: triaje (TP + FP, para la FPR) y remediación (TP con CVSS ≥ 7, para la RSR). Coste estimado 4-5 días.
