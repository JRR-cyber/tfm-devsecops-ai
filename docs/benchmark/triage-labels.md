# Criterios de etiquetado del conjunto de triaje

Este documento fija, **antes de etiquetar**, qué hallazgos entran en el conjunto de triaje y cómo se decide si cada uno es un verdadero positivo (TP) o un falso positivo (FP). Se versiona antes que las etiquetas para que el historial de git muestre que los criterios no se ajustaron a posteriori.

## 1. Por qué hace falta

El dataset de [`dataset.md`](dataset.md) solo contiene vulnerabilidades confirmadas. Sirve para medir la remediación (RSR), pero no el triaje: un LLM que respondiera siempre "es real" acertaría el 100 %. Para medir la tasa de falsos positivos (FPR, Paso 5.2) y comprobar si la traza de taint ayuda a **decidir** (pregunta de investigación), hacen falta hallazgos que el escáner reporta y que no son explotables, con una etiqueta de referencia (verdad de base).

La etiqueta es la respuesta correcta contra la que se compara la decisión del agente. El agente no la ve nunca: solo recibe el hallazgo, la traza y el código.

## 2. Principio: toda etiqueta se apoya en una ejecución

Una etiqueta basada solo en la lectura del código es una opinión del autor y se puede discutir. Por eso **cada etiqueta TP o FP debe estar respaldada por un test versionado que cualquiera puede ejecutar**, y es el resultado de ese test, no el juicio del autor, lo que fija la etiqueta. Lo que no se puede demostrar así queda como `UNCERTAIN` y fuera de la métrica principal.

## 3. Inclusión

| Criterio | Definición |
|---|---|
| T1 | Hallazgo de **CodeQL** con traza de taint de dos o más pasos (`codeFlows`), igual que C8. Semgrep OSS no da trazas ([`pipeline.md`, sección 4](../architecture/pipeline.md)). |
| T2 | Producido con la misma versión y suite de CodeQL que el pipeline (2.27.2, `security-extended`). Se anota el run de CI o la versión usada. |
| T3 | **Juice Shop:** cualquier archivo de `src/app/juice-shop/`, salvo `test/` y `data/static/codefixes/` (los fragmentos de los retos de código, que no se ejecutan). Todas las reglas y severidades. |
| T4 | **SecBench.js:** hallazgos en la **versión corregida** de los 30 casos del dataset, de una regla etiquetada con una CWE de la clase del caso (`CLASS_CWES` de `secbench_detect.py`), en cualquier archivo del paquete. |

No se filtra por severidad: la FPR se mide sobre todo lo que el escáner reporta. El umbral CVSS ≥ 7.0 (Paso 3.3) se aplica después, al decidir qué se remedia.

Los hallazgos de las versiones vulnerables de SecBench.js fuera del *sink* (`other_findings` en `detection.csv`) quedan fuera para acotar el esfuerzo. Es una limitación documentada.

## 4. Unidad

La unidad es la **vulnerabilidad**, como en Juice Shop (sección 3 de `dataset.md`). Varios resultados de CodeQL que comparten fuente, regla y archivo, y cuyo arreglo es el mismo (p. ej., los cuatro accesos con el mismo `id` en `likeProductReviews.ts`), forman un `vuln_group` y cuentan una vez en la métrica principal. Cada resultado se identifica por su huella `partialFingerprints["tfmContextHash/v1"]`, nunca por número de línea.

## 5. Modelo de amenaza

El exploit tiene que respetar quién controla la fuente:

- **Juice Shop:** un usuario remoto, autenticado o no, que envía peticiones HTTP arbitrarias. No controla la configuración del servidor, los archivos del disco ni la base de datos salvo a través de la propia aplicación. Los exploits se lanzan por HTTP contra la imagen de contenedor que construye el pipeline (`docker build src/app/juice-shop`, la misma que escanea Trivy), en Linux, no contra funciones sueltas, para que cuenten todos los *middlewares*.
  - **Configuración: todos los retos activos** (`challenges.safetyMode: disabled`). En contenedores, el modo `auto` por defecto desactiva los retos marcados como peligrosos, y parte del código aplica entonces una protección que no existe con el reto activo. Por ejemplo, `routes/trackOrder.ts` sanea el `id` si el reto de XSS reflejado está desactivado. El análisis estático examina el código sin configuración, así que la etiqueta se fija con la configuración que activa todas las rutas de código. Las protecciones que dependen de la configuración se anotan en la justificación.
  - **Plataforma: Linux.** El resultado puede depender del sistema operativo. Por ejemplo, `routes/keyServer.ts` solo rechaza `/`, y en Windows `\` también separa rutas.
- **SecBench.js:** el modelo de SecBench.js y de las consultas de librería de CodeQL. El atacante controla los argumentos de las funciones exportadas por el paquete. Los exploits se ejecutan en el arnés de Docker (`benchmarks/secbench-js/harness/`, Node 16, Linux).

## 6. Etiquetas y evidencia

| Etiqueta | Se asigna cuando… | Evidencia ejecutable |
|---|---|---|
| **TP** | Un exploit que respeta el modelo de amenaza **tiene éxito** contra el código tal cual. | `OFF`: exploit oficial (test de Juice Shop que resuelve un reto, o exploit de SecBench.js). `POC`: exploit propio versionado en `benchmarks/triage/evidence/`. |
| **FP** | El exploit **falla** contra el código tal cual **y tiene éxito** cuando se desactiva la protección que se cita (ablación). | `ABL`: el mismo exploit, ejecutado dos veces: con el código original y con la protección eliminada por un cambio mínimo y explícito. |
| **UNCERTAIN** | No se puede construir ninguna de las dos pruebas (p. ej., no hay protección concreta que desactivar, o el efecto no es observable). | Motivo por escrito. |

**Por qué la ablación.** Que un exploit falle no prueba nada: puede que el exploit esté mal escrito. Si el mismo exploit funciona en cuanto se quita la protección, queda demostrado que el código es atacable en principio y que es precisamente esa protección la que lo impide, que es lo que el agente debería reconocer. La ablación se aplica a una **copia temporal** del código; el benchmark nunca se modifica.

Para que la ablación sea un control válido:
- El cambio debe ser mínimo: quitar o neutralizar la comprobación citada, nada más. Se versiona como `old`/`new` exactos, y el test falla si el texto ya no coincide con el código.
- Se citan **todas** las protecciones del camino. Si el exploit sigue fallando después de la ablación, hay otra protección que no se había visto, y hay que encontrarla y citarla. Ejemplo del piloto: en `routes/keyServer.ts`, además de la comprobación de `/`, el *middleware* `serve-index` montado antes en `/encryptionkeys` (`server.ts:296`) rechaza las rutas con `..`. Las protecciones pueden estar en dependencias (`node_modules/`).
- El exploit es idéntico en las dos ejecuciones.
- El éxito del exploit se comprueba por su efecto (datos devueltos que no deberían, archivo leído, comando ejecutado, `Object.prototype` contaminado…), no por el código de estado.

Reglas adicionales:
- La severidad no cambia la etiqueta: una inyección en logs explotable es TP aunque su impacto sea bajo.
- El código que detecta si un reto está resuelto (`solveIf`, `routes/verify.ts`) es parte de la aplicación y se etiqueta con el mismo criterio.
- **El oráculo de SecBench.js no basta para etiquetar FP.** Que el exploit original falle contra la versión corregida no prueba que esta sea segura. Ejemplo del análisis previo: `connection-tester` 0.2.1 valida el host con `new RegExp("…\.…")` dentro de un string, donde `\.` se convierte en `.` y la expresión acepta `a;id`. Cada hallazgo de una versión corregida necesita su propia evidencia.
- Los `UNCERTAIN` se informan aparte, con un análisis de sensibilidad (contándolos como TP y como FP).
- **Retención por posible divulgación.** Si el hallazgo está en la versión **actual** de un paquete todavía usado y no hay un advisory público que lo documente (es decir, el exploit podría ser una vulnerabilidad no divulgada), el caso se marca `UNCERTAIN` y **su exploit no se versiona** en este repositorio público. Validar o reportar esa vulnerabilidad queda fuera del alcance del TFM. Caso conocido: `connection-tester` 0.2.1 (ver [`decisions.md`](decisions.md), D3).

## 7. Procedimiento

1. Los criterios se versionan antes que las etiquetas (este documento).
2. Las etiquetas se hacen antes de ejecutar el agente de la Fase 3, sin ver ninguna salida del LLM.
3. Cada fila de `benchmarks/triage/labels.csv` registra: huella, fuente, archivo, línea, regla, CWE, `vuln_group`, etiqueta, tipo de evidencia, test que la respalda y una justificación de una o dos frases.
4. Un script vuelve a ejecutar todas las evidencias y comprueba que cada una da el resultado que exige su etiqueta. Si alguna deja de hacerlo, la etiqueta no es válida.
5. Cualquier cambio posterior de una etiqueta se hace en un commit propio con el motivo.
6. Opcional: otra persona (idealmente el tutor) revisa una muestra de las evidencias.

## 8. Relación con el conjunto de remediación

Los TP nuevos de Juice Shop se añaden también a `benchmarks/dataset.csv` como casos de remediación. Así se sustituye, para Juice Shop, el requisito de estar marcado con `vuln-code-snippet`: la corrección de referencia es el *codefix* cuando existe. Si no existe, el parche se valida en la Fase 4 con el re-escaneo y el mismo exploit de la evidencia, que tiene que dejar de funcionar. Los FP no se remedian; solo sirven para el triaje.
