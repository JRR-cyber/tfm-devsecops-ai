# Registro de decisiones del dataset

Decisiones de diseño del conjunto experimental, con su motivo y su fecha. Alimenta el capítulo de gestión de proyecto de la memoria (Fase 6). La más reciente arriba.

## D6 — Los falsos positivos también salen de SecBench.js (2026-10-24)

**Decisión.** El conjunto de falsos positivos se toma de Juice Shop **y** de las versiones corregidas de SecBench.js. Se vendorizan **solo** las versiones corregidas de los casos que CodeQL sigue marcando (~10), que son las que aportan hallazgos; las otras 20 no se añaden. **Supersede la parte de D5** sobre la fuente de FP.

**Motivo.** Los FP de paquetes npm poco conocidos son más diversos y menos memorizables que los de Juice Shop, lo que refuerza la prueba de control de memorización (Paso 5.3). Y el coste real es menor de lo que decía D5: **el job de CodeQL escanea todo el repositorio**, así que vendorizar las versiones corregidas basta para que CI las escanee y les asigne huella real; **no hace falta un job nuevo**. El único coste es el tamaño del repo (~10 árboles de paquete, como ya están los vulnerables en `cases/*/src/`) y etiquetar esos hallazgos.

**Consecuencia.** Se restauró la infraestructura de SecBench (`run_evidence`, rama de `triage_evidence.py`). Cada versión corregida marcada se analiza por separado: si el arreglo es real, es FP (evidencia por ablación); si es un arreglo incompleto que sigue siendo explotable, es TP o se retiene (D3). SecBench.js aporta así TP (30 casos vulnerables) y FP (versiones corregidas marcadas) al triaje.

## D5 — [Superada por D6] El conjunto de falsos positivos sale solo de Juice Shop (2026-10-24)

> Superada el mismo día por D6: se decidió incluir también SecBench.js en los FP. Se conserva el registro porque la alternativa se consideró en serio y el razonamiento de reproducibilidad sigue siendo válido.

**Decisión (revertida).** Los falsos positivos se tomarían únicamente de Juice Shop.

**Motivo.** El agente triará lo que haya en `unified/findings.sarif`, con huella `tfmContextHash` calculada por el pipeline ([`unify_results.py`](../../scripts/pipeline/unify_results.py)); Juice Shop ya lo escanea CI entero. Se creía que usar SecBench exigía un job de escaneo nuevo (incorrecto: CodeQL ya escanea todo el repo, ver D6).

**Resultado cualitativo que se conserva.** Al analizar en local las 30 versiones corregidas de SecBench.js con el mismo CodeQL del pipeline, 10 seguían marcadas. La revisión manual confirmó que al menos una, `connection-tester` 0.2.1, es un **arreglo incompleto realmente explotable** (la validación del host usa una regex construida desde un string, donde `\.` queda como `.`). Es un dato sobre la validez del oráculo de SecBench.js ("corregido según el exploit" ≠ "no vulnerable") que va a la discusión de la memoria; el exploit no se versiona (D3).

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
