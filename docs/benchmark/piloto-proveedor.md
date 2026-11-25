# Piloto de proveedor: gpt-oss-120b fuera de Groq

Rama `exp/proveedor-piloto`. Este documento se fija **antes de la primera llamada** al proveedor candidato, para que el resultado se juzgue con criterios decididos de antemano y no a la vista de los datos.

## Motivo

La Fase 5 necesita unos 4,3M tokens: la rejilla completa de triaje y 3 pasadas de remediación. El plan gratuito de Groq da 200K tokens al día, así que serían unas 3 semanas. El plan Developer no se puede contratar: el 22-11-2026, el soporte de Groq respondió que las altas siguen «temporalmente pausadas» y sin fecha.

Tres semanas expuestos a un cambio de límites o a la retirada del modelo es un riesgo real; Groq ya retiró Llama 3.3 el 16-08-2026. Por eso se evalúa servir el **mismo modelo de pesos abiertos** desde otro proveedor de pago por uso. El modelo no cambia y la variable controlada del diseño *within-subject* se mantiene. Lo que cambia es la infraestructura que lo sirve.

Antes de adoptarlo hay que comprobar que esa infraestructura no altera el comportamiento del modelo. Eso es lo que mide este piloto.

## Pregunta

¿El proveedor candidato se diferencia de Groq más de lo que cada uno se diferencia de sí mismo?

El modelo no es determinista ni con temperatura 0. En el 4.10, el resultado de remediación cambió en 2 de 20 casos entre dos ejecuciones en Groq. Por eso no se puede exigir que las respuestas sean idénticas: la referencia es el ruido propio de cada proveedor.

## Proveedores considerados

Datos de las páginas oficiales consultadas el 22-11-2026.

| | Together AI | DeepInfra | Fireworks AI | Nebius |
|---|---|---|---|---|
| Precio por 1M tokens (entrada / salida) | $0,15 / $0,60, igual que Groq | $0,037 / $0,17 | $0,15 / $0,60 | no confirmado (página de precios inaccesible) |
| `reasoning_effort` en gpt-oss-120b | documentado: low/medium/high, por defecto `medium` | documentado en general, pero gpt-oss-120b no aparece en su lista de modelos compatibles | documentado, por defecto `medium` | aparece en el esquema, sin confirmar para este modelo |
| Datos | no entrena sin consentimiento; retención cero activable | no almacena entradas ni salidas; no entrena | sin retención por defecto | no confirmado |
| Control de gasto | prepago; se corta al llegar a $0; primera recarga mínima de $15 | prepago y límite de gasto | límite mensual | no confirmado |
| Disponibilidad | servidor compartido (*serverless*) | servidor compartido | contradictoria: la ficha del modelo dice «Serverless: Not Supported» | no confirmado |

**Candidato: Together AI.** Es el único con el parámetro que el piloto necesita controlar (`reasoning_effort`) documentado para este modelo, y con su valor por defecto. Su precio es el mismo que el de lista de Groq, así que las estimaciones de coste no cambian. Y el prepago actúa de tope de gasto real.

DeepInfra es unas cuatro veces más barato, pero no documenta `reasoning_effort` para gpt-oss-120b y su ficha da una precisión ambigua (bf16 o MXFP4). Queda como alternativa si Together no supera el piloto.

### Condiciones de Together verificadas antes de pagar (23-11-2026)

Comprobadas en el catálogo de modelos, la referencia de la API, la documentación de facturación, los términos de servicio (versión del 19-05-2026) y la cuenta, sin cambiar nada en ella.

**Modelo**
- `openai/gpt-oss-120b` está en el catálogo *serverless*, con precisión MXFP4 (la nativa del modelo) y contexto de 131.072 tokens.
- Cuesta $0,15 por 1M de entrada y $0,60 por 1M de salida, sin precio de caché. Los tokens de razonamiento se cobran como salida.
- No figura entre las retiradas programadas. Una retirada se avisa por email con 2–3 semanas de antelación; una «actualización» del mismo identificador, con 3 días. El log guarda el modelo servido en cada llamada.

**API**
- `reasoning_effort` acepta low/medium/high, con `medium` por defecto. Los valores no válidos se aceptan sin error; nuestro cliente los valida antes de enviarlos.
- `temperature` admite valores de 0 a 1.
- La respuesta llega en `content` y el razonamiento en un campo aparte.
- Según la referencia de la API, `usage` solo informa `prompt_tokens` y `completion_tokens`. **Corregido tras pagar:** las respuestas reales también incluyen los tokens de razonamiento y los de caché (ver «Resultados»).
- El valor por defecto de `max_tokens` **no está documentado**. Por eso se fija explícitamente (ver más abajo).

**Datos**
- *Prompt storage*, *Passthrough models* y *Model training* están apagados (*Organization → General → Privacy*).
- Es el «Zero Data Retention» del §3 de los términos.
- Solo se envía código público del benchmark, nada de datos personales (§4).

**Facturación y gasto**
- Prepago. La primera compra es de $15 como mínimo, y hasta hacerla no se puede crear la clave de API ni probar nada.
- **No reembolsable** (§6). Los créditos no caducan.
- **Impuestos aparte** (§6): puede sumarse el IVA según la dirección de facturación.
- La tarjeta tiene que ser de crédito o débito y admitir pagos recurrentes. No se aceptan tarjetas prepago.
- Una compra puede tardar hasta 15 min en confirmarse. Repetirla mientras está pendiente cuenta como otra compra.
- El acceso se corta al llegar a $0, pero el consumo se contabiliza con retraso: el corte «no garantiza un tope exacto» y el exceso se factura aparte.
- La recarga automática no está configurada y debe seguir así. Aun así, el §6 de los términos autoriza recargas a la tarjeta, y los presupuestos y alertas del panel aún no existen («coming soon»).
- Conclusión: el tope de gasto fiable es el nuestro (`LLM_BUDGET_USD`, ver más abajo) más el límite que se ponga a la tarjeta en el banco.

**Términos de uso (§4c)**
- Prohíben usar el servicio para «análisis competitivo o *benchmarking*».
- La Fase 5 evalúa estrategias de prompting del modelo, no al proveedor.
- El piloto se presenta como comprobación de reproducibilidad del modelo entre infraestructuras, no como comparación publicada de proveedores. El autor asume esta lectura sin consultar a Together.

## Cambios de código en la rama

- **Selección de proveedor.** `groq_client.py` elige el proveedor con `LLM_PROVIDER`; sin la variable, se usa Groq como hasta ahora. Cada proveedor lee su propia clave: `GROQ_API_KEY`, `TOGETHER_API_KEY`, `DEEPINFRA_API_KEY`.
- **`reasoning_effort` explícito.** Se envía siempre `medium` (variable `LLM_REASONING_EFFORT`). Los ensayos del 4.10 no lo enviaban, y cada proveedor aplica el suyo: dejarlo implícito permitiría que el proveedor cambiase cuánto razona el modelo sin que se notara.
- **`max_tokens` explícito.** Se envía 16.384 (variable `LLM_MAX_TOKENS`) en todos los proveedores: 5 veces la respuesta más larga de los ensayos del 4.10 (3.072 tokens). Evita que un valor por defecto bajo corte respuestas y limita el coste de una llamada a unos $0,01.
- **`finish_reason` en el log.** Con `length`, la respuesta fue cortada por `max_tokens`. En el C4 cuenta como fallo de formato.
- **Tope de gasto propio** (`LLM_BUDGET_USD`, obligatorio en proveedores de pago):
  - el cliente suma el coste a precio de lista de cada llamada y rechaza la siguiente al llegar al tope;
  - cuenta también lo que el log ya había gastado, así que relanzar no reinicia el contador;
  - `run_dataset.py` se para limpio con código 76;
  - como mucho se pasa en una llamada.
- **Timeout de 180 s** (antes 60 s). Si una respuesta larga de un proveedor más lento agota el tiempo, el cliente reintenta, y la petición abandonada probablemente se cobra igual.
- **Más datos en el log.** Cada llamada guarda los tokens de razonamiento y los de caché, cuando el proveedor los informa. Cada fila guarda el proveedor, el nivel de razonamiento, `max_tokens` y el tope de gasto.
- **Sonda del nivel de razonamiento.** `groq_client.py --probe-effort` compara los tokens con el parámetro omitido y con low, medium y high. Sirve para ver qué nivel aplica cada proveedor por defecto.
- **Comparador.** `pilot_compare.py` aplica los criterios de abajo a los logs y genera un informe.

## Diseño

Las cuatro ejecuciones usan la configuración del ensayo 4.10 con una diferencia:
- 33 casos, zero-shot, traza + RAG, oráculos de D9, el mismo SARIF (`results/dev/ci/findings.sarif`, ejecución de CI 43938956025);
- la diferencia es `--repair-all`: se repara en todos los casos aunque el triaje diga FP, para poder comparar la remediación caso a caso en los 33.

| Orden | Ejecución | Log |
|---|---|---|
| 0 | Sonda de `reasoning_effort` en Groq y en Together | consola |
| 1 | Together, pasada 1 | `results/dev/pilot-together-1.jsonl` |
| 2 | Groq, pasada 1 (plan gratuito, 1–2 días de cuota) | `results/dev/pilot-groq-1.jsonl` |
| 3 | Together, pasada 2 | `results/dev/pilot-together-2.jsonl` |
| 4 | Groq, pasada 2 | `results/dev/pilot-groq-2.jsonl` |

- **Orden intercalado.** Así los dos proveedores reparten las fechas de forma parecida.
- **Nunca en paralelo.** Las ramas de los parches se llaman igual en las dos ejecuciones y chocarían.
- **Nada cuenta como Fase 5.** Los logs quedan en `results/dev/`, que git ignora, como los del 4.10.

## Criterios de aceptación

Grupo A: Groq. Grupo B: Together.
- **«Dentro de A»:** el acuerdo entre las dos pasadas de Groq, que mide el ruido de Groq.
- **«Entre A y B»:** la media de los cuatro pares Groq–Together.

| | Criterio | Qué descarta |
|---|---|---|
| C1 | Misma entrada. En cada llamada comparable (el triaje y el intento 1 de remediación, cuyo prompt no depende de respuestas anteriores), la diferencia de tokens de prompt entre B y A es constante: al menos el 95 % de las llamadas está a ±2 tokens del desfase más común, que corresponde a la plantilla de chat del proveedor. Además, el modelo servido es gpt-oss-120b. | Que el proveedor altere el prompt o sirva otro modelo |
| C2 | Triaje: los veredictos iguales entre A y B no bajan más de **2 casos** respecto a los iguales dentro de A. | Un triaje sistemáticamente distinto |
| C3 | Remediación: el número medio de ACCEPTED de B difiere del de A en **±3** como máximo, y los resultados iguales por caso (aceptado o no) entre A y B no bajan más de **3 casos** respecto a dentro de A. | Una capacidad de reparación distinta |
| C4 | Formato: los fallos de formato de B (triaje sin JSON válido y remediación sin diff) no superan a los de A en más de **2**. | Que el proveedor rompa el formato de salida |
| C5 | Razonamiento: la mediana de tokens de salida por triaje de B está entre **×0,5 y ×2** la de A. | Un nivel de razonamiento distinto aunque el parámetro sea el mismo |
| C6 | Operativo, revisado a mano: ningún fallo que bloquee el lote, coste real del panel del proveedor dentro de lo estimado y almacenamiento de prompts y entrenamiento desactivados (en Together: *Organization → General → Privacy*, interruptores *Prompt storage*, *Passthrough models* y *Model training*; comprobados apagados el 22-11-2026). | Sorpresas de coste, estabilidad o datos |

C1–C5 los evalúa `pilot_compare.py` con estos mismos umbrales, que están escritos en su código. C6 se revisa a mano.

## Qué se decide con el resultado

- **Se cumplen C1–C6:** se propone D12 con toda la Fase 5 en Together: rejilla completa, 3 pasadas de remediación y 3 intentos por caso. Los ensayos en Groq quedan como desarrollo. La Fase 5 se ejecuta entera en un único proveedor.
- **Falla alguno:** se analiza el porqué en los casos que discrepan. Las salidas son dos: piloto con DeepInfra, o Fase 5 en el plan gratuito de Groq por bloques de prioridad (unas 3 semanas).

## Resultados

### Sonda de `reasoning_effort` (23-11-2026)

Comando: `groq_client.py --probe-effort --repeats 3`, una pregunta corta de triaje que exige algo de razonamiento. Media de tokens de salida por llamada (entre paréntesis, los de razonamiento):

| Nivel | Groq | Together | Together / Groq |
|---|---|---|---|
| omitido | 557 (546) | 378 (367) | 0,68 |
| low | 109 (98) | 112 (101) | 1,03 |
| **medium** | **429 (418)** | **450 (439)** | **1,05** |
| high | 5.522 (5.511) | 2.989 (2.978) | 0,54 |

- **Con `medium`, el nivel fijado para el piloto y la Fase 5, los dos proveedores razonan lo mismo** (razón 1,05). Con `low`, también.
- **Por defecto, Groq aplica algo equivalente a `medium`.** Sin el parámetro, sus 557 tokens quedan mucho más cerca de medium que de low o high. Los ensayos del 4.10, que no lo enviaban, se hicieron con un razonamiento comparable. Together, sin el parámetro, también cae en la franja de medium, como documenta.
- **Con `high` divergen casi ×2.** No afecta al diseño, que fija `medium`. Con 3 repeticiones no se concluye nada más. Sí confirma que hacía falta un `max_tokens` explícito: Groq dedicó unos 5.500 tokens a una pregunta trivial.
- **Respuestas:** las 24 llamadas responden UNSAFE.
- **Sin cortes:** el *selftest* de Together termina con `finish_reason=stop`.
- **Datos de uso:** Together informa los tokens de razonamiento y los de caché, aunque su referencia de API no lo indica. En el *selftest*, 69 de los 91 tokens de prompt salieron de caché. Sin precio de caché, el coste no cambia.
- **Coste a precio de lista:** Together, unos $0,0074 entre *selftest* y sonda; Groq, unos $0,0122 (plan gratuito, no se cobra).

### Pasadas (23 al 25-11-2026)

Informe completo: `pilot_compare.py` sobre los cuatro logs del diseño, en `results/dev/pilot-report.md`.

| Ejecución | ACCEPTED | Triaje FP | Fallos de formato | Cortadas por `max_tokens` | Mediana tokens salida (triaje) | LLM s (mediana) | Coste a precio de lista |
|---|---|---|---|---|---|---|---|
| groq-1 | 20 | 4 | 1 | 0 | 397 | 2,0 | $0,073 |
| groq-2 | 22 | 6 | 1 | 0 | 345 | 1,9 | $0,069 |
| together-1 | 23 | 5 | 0 | 0 | 407 | 5,7 | $0,076 |
| together-2 | 22 | 4 | 1 | 0 | 415 | 5,2 | $0,077 |

| | Resultado | Umbral |
|---|---|---|
| C1 | **Cumple.** Desfase constante de −1 token en el 100 % de las 66 llamadas comparables de cada par Groq–Together; 0 dentro de cada proveedor. Modelo servido `openai/gpt-oss-120b` en las 391 llamadas. | ≥ 95 % a ±2 |
| C2 | **Cumple.** Veredictos iguales: dentro de Groq 29, dentro de Together 30, entre ambos 30,5 de 33. | ≥ 27 |
| C3 | **Cumple.** ACCEPTED medio: Groq 21, Together 22,5. Resultado igual por caso: dentro de Groq 29, dentro de Together 28, entre ambos 28,5. | ±3; ≥ 26 |
| C4 | **Cumple.** Fallos de formato medios: Groq 1, Together 0,5. | ≤ 3 |
| C5 | **Cumple.** Mediana de tokens de salida por triaje: Groq 371, Together 411 (×1,11). | ×0,5–×2 |

- **Together se parece a Groq tanto como cada proveedor a sí mismo.** El acuerdo entre proveedores (30,5 y 28,5) queda entre los dos acuerdos internos, en triaje y en remediación.
- **Los fallos de formato son del modelo, no del proveedor.** Por ejemplo, Groq escribió `"confidence": 0. nine` en el triaje de bestzip, y el parser recuperó el veredicto. Ninguna de las 391 respuestas se cortó por `max_tokens`.
- **Latencia:** Together tarda unas 2,7 veces más por llamada. No afecta a la validez si toda la Fase 5 va en un único proveedor. Pero el *overhead* absoluto que mida la Fase 5 será el de ese proveedor.

**Incidencias.** Ninguna se debió a Together.
- **Docker Desktop se bloqueó** en la pasada together-1. El contenedor del oráculo se quedó en *Created* hasta el timeout de 600 s. Se reinició el equipo y se retomó desde el log; la llamada de remediación perdida costó unos $0,0005 y no consta en el log.
- **Tras el reinicio, la clave de API se pegó con un carácter de control.** Together respondió 401 y el preflight no lo detectó porque la variable no estaba vacía. Se repitió la carga de la clave. No hubo coste.
- **En groq-1 hubo dos paradas por cuota de Groq** (código 75) y un fallo de DNS de la red local. Las tres se retomaron desde el log.
- **Pasada extra de Together.** La que debía ser groq-2 se lanzó por error con `LLM_PROVIDER=together`: 99 llamadas, todas a Together según el log. Se renombró `pilot-together-3.jsonl` y se repitió groq-2 contra Groq. La evaluación usa los cuatro logs del diseño; together-3 no entra en los criterios, para no elegir pasadas a la vista de los resultados. Como observación, sus acuerdos con las otras pasadas son 31–32 en triaje y 27–30 en remediación, en el mismo rango, con 21 ACCEPTED.

**C6, revisado a mano.**
- **Estabilidad:** ningún fallo de Together bloqueó un lote.
- **Coste:** el saldo del panel tras together-1 era $14,92, igual que el estimado ($15 − $0,0074 − $0,0763). Al terminar, el panel marcaba **$14,77**, igual que el estimado a precio de lista: $15 menos unos $0,23 de tres pasadas y las sondas. El contador propio de gasto es fiable para la Fase 5.
- **Datos:** el 25-11-2026 se comprobaron de nuevo los interruptores de privacidad: siguen apagados.

**Veredicto: C1–C6 se cumplen.** Según la regla fijada arriba, se propone D12 con toda la Fase 5 en Together.

## Limitaciones

- **No prueba identidad.** Con 33 casos solo se puede afirmar que el proveedor no se diferencia más que el ruido del propio modelo. Las diferencias pequeñas quedan por debajo de lo detectable, igual que en la Fase 5.
- **Pesos y precisión.** Ningún proveedor expone los pesos que sirve. La precisión (MXFP4 nativo u otra) se da por buena según sus fichas, y C1, C3 y C5 son la comprobación indirecta.
- **El servicio puede cambiar.** Un proveedor puede cambiar su despliegue después del piloto. El log guarda `model_served` en cada llamada para detectarlo durante la Fase 5.

## Coste estimado

- **Together:** unos 230K tokens por pasada con `--repair-all`, unos $0,07 por pasada. Las dos pasadas y la sonda quedan por debajo de $0,25, muy lejos de la primera recarga de $15, cuyo resto se usaría en la Fase 5.
- **Groq:** gratis; entre 1 y 2 días de cuota por pasada.
- **CodeQL:** unas 2 h por pasada en la máquina local.
