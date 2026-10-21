# Registro de decisiones del dataset

Decisiones de diseño del conjunto experimental, con su motivo y su fecha. Alimenta el capítulo de gestión de proyecto de la memoria (Fase 6). La más reciente arriba.

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
