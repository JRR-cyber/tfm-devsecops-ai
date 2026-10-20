# Criterios de etiquetado del conjunto de triaje

Este documento fija, **antes de etiquetar**, qué hallazgos entran en el conjunto de triaje y cómo se decide si cada uno es un verdadero positivo (TP) o un falso positivo (FP). Se versiona antes que las etiquetas para que el historial de git muestre que los criterios no se ajustaron a posteriori.

## 1. Por qué hace falta

El dataset de [`dataset.md`](dataset.md) solo contiene vulnerabilidades confirmadas. Sirve para medir la remediación (RSR), pero no el triaje: un LLM que respondiera siempre "es real" acertaría el 100 %. Para medir la tasa de falsos positivos (FPR, Paso 5.2) y comprobar si la traza de taint ayuda a **decidir** (pregunta de investigación), hacen falta hallazgos que el escáner reporta y que no son explotables, con una etiqueta de referencia (verdad de base).

La etiqueta es la respuesta correcta contra la que se compara la decisión del agente. El agente no la ve nunca: solo recibe el hallazgo, la traza y el código.

## 2. Inclusión

| Criterio | Definición |
|---|---|
| T1 | Hallazgo de **CodeQL** con traza de taint de dos o más pasos (`codeFlows`), igual que C8. Semgrep OSS no da trazas ([`pipeline.md`, sección 4](../architecture/pipeline.md)). |
| T2 | Producido por el pipeline con la misma versión y suite de CodeQL (2.27.2, `security-extended`). Se anota el run de CI o la versión usada. |
| T3 | **Juice Shop:** cualquier archivo de `src/app/juice-shop/`, salvo `test/` y `data/static/codefixes/` (los fragmentos de los retos de código, que no se ejecutan). Todas las reglas y severidades. |
| T4 | **SecBench.js:** hallazgos en la **versión corregida** de los 30 casos del dataset, de una regla etiquetada con una CWE de la clase del caso (`CLASS_CWES` de `secbench_detect.py`), en cualquier archivo del paquete. |

No se filtra por severidad: la FPR se mide sobre todo lo que el escáner reporta. El umbral CVSS ≥ 7.0 (Paso 3.3) se aplica después, al decidir qué se remedia.

Los hallazgos de las versiones vulnerables de SecBench.js fuera del *sink* (`other_findings` en `detection.csv`) quedan fuera para acotar el esfuerzo. Es una limitación documentada.

## 3. Unidad

La unidad es la **vulnerabilidad**, como en Juice Shop (sección 3 de `dataset.md`). Varios resultados de CodeQL que comparten fuente, regla y archivo, y cuyo arreglo es el mismo (p. ej., los cuatro accesos con el mismo `id` en `likeProductReviews.ts`), forman un `vuln_group` y cuentan una vez en la métrica principal. Cada resultado se etiqueta por separado y se identifica por su huella `partialFingerprints["tfmContextHash/v1"]`, nunca por número de línea.

## 4. Modelo de amenaza

La etiqueta depende de quién controla la fuente:

- **Juice Shop:** un usuario remoto, autenticado o no, que envía peticiones HTTP arbitrarias. No controla la configuración del servidor, los archivos del disco ni la base de datos salvo a través de la propia aplicación. Los retos desactivados por configuración se consideran activos (configuración por defecto).
- **SecBench.js:** el modelo de SecBench.js y de las consultas de librería de CodeQL. El atacante controla los argumentos de las funciones exportadas por el paquete.

## 5. Etiquetas

| Etiqueta | Definición | Evidencia obligatoria (al menos una) |
|---|---|---|
| **TP** | Existe una entrada del atacante (sección 4) que llega al *sink* y produce el efecto de la CWE de la regla. | `CH`: reto de `data/static/challenges.yml` cuya solución explota ese *sink*. `EX`: exploit que funciona (SecBench.js). `POC`: entrada concreta escrita en la justificación y razonamiento sobre el código. |
| **FP** | No existe esa entrada. | `G`: comprobación o saneamiento en el camino que CodeQL no modela (citar archivo:línea). `S`: la fuente no la controla el atacante. `C`: el valor que llega al *sink* está restringido (lista cerrada, tipo, formato). `U`: código inalcanzable. |
| **UNCERTAIN** | No se puede decidir con el código y la documentación disponibles. | Motivo por escrito. |

Reglas adicionales:
- La severidad no cambia la etiqueta: una inyección en logs explotable es TP aunque su impacto sea bajo.
- El código que detecta si un reto está resuelto (`solveIf`, `routes/verify.ts`) es parte de la aplicación y se etiqueta con el mismo criterio.
- **El oráculo de SecBench.js no basta para etiquetar FP.** Que el exploit original falle contra la versión corregida no prueba que esta sea segura. Ejemplo encontrado en el análisis previo: `connection-tester` 0.2.1 valida el host con `new RegExp("…\.…")` dentro de un string, donde `\.` se convierte en `.` y la expresión acepta `a;id`. CodeQL sigue marcando el *sink* y es un TP. Cada hallazgo de una versión corregida se revisa a mano.
- Los UNCERTAIN quedan fuera de la métrica principal y se informan aparte, con un análisis de sensibilidad (contándolos como TP y como FP).

## 6. Procedimiento

1. Los criterios se versionan antes que las etiquetas (este documento).
2. Las etiquetas se hacen antes de ejecutar el agente de la Fase 3, sin ver ninguna salida del LLM.
3. Cada fila de `benchmarks/triage/labels.csv` registra: huella, fuente, archivo, línea, regla, CWE, `vuln_group`, etiqueta, código de evidencia, referencia (archivo:línea o clave del reto) y justificación en una o dos frases.
4. **Segunda revisión:** otra persona (idealmente el tutor) etiqueta a ciegas una muestra aleatoria estratificada de al menos el 20 % de los grupos. Se informa el acuerdo (kappa de Cohen) y cómo se resolvió cada desacuerdo.
5. Cualquier cambio posterior de una etiqueta se hace en un commit propio con el motivo.

## 7. Relación con el conjunto de remediación

Los TP nuevos de Juice Shop con un reto asociado (evidencia `CH`) se añaden también a `benchmarks/dataset.csv` como casos de remediación. Así se sustituye, para Juice Shop, el requisito de estar marcado con `vuln-code-snippet`: la corrección de referencia es el *codefix* cuando existe, y si no, la validación de la Fase 4 (re-escaneo + el test de Cypress que resuelve el reto). Los FP no se remedian; solo sirven para el triaje.
