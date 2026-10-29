# Agente de IA (Fase 3)

Agente híbrido del pipeline: lee el SARIF unificado que produce CI
(`scripts/pipeline/unify_results.py` → `unified/findings.sarif`), triaje cada
hallazgo apoyándose en la traza de taint de CodeQL y, para los de severidad alta,
propone un parche y abre un PR para revisión humana (postura asistiva).

Diseño fijo del roadmap (no sustituir sin pedirlo): un solo modelo —Llama 3.3 70B
en Groq—, los experimentos comparan *estrategias de prompting* (zero-shot /
few-shot / CoT); auto-remediación solo para CVSS ≥ 7.0; emparejamiento pre/post
parche por `partialFingerprints`, nunca por línea; el agente no corre en
`pull_request_target`.

## Estado por paso

| Paso | Descripción | Estado |
|---|---|---|
| 3.1 | Cliente Groq (clave `GROQ_API_KEY`) | **hecho** — `groq_client.py` |
| 3.2 | Parser del SARIF unificado (fichero, línea, regla, snippet, `codeFlows`, fingerprint, severidad) | **hecho** — `sarif_parser.py` |
| 3.3 | Filtro CVSS ≥ 7.0 + mapeo documentado de severidad Semgrep | pendiente |
| 3.4 | Traza de taint como contexto estructurado; decisión FP a partir de la traza | pendiente |
| 3.5 | RAG ligero (imports y funciones relacionadas del fichero vulnerable) | pendiente |
| 3.6 | Prompts zero-shot / few-shot / CoT; parche como diff | pendiente |
| 3.7 | Rama `fix/ai-remediation-...` + PR | pendiente |

## Módulos

- **`sarif_parser.py`** — convierte el SARIF unificado en objetos `Finding`
  tipados. Es el único punto que normaliza la severidad entre herramientas (ver
  abajo). No filtra ni triaje: solo parsea.
  ```bash
  python scripts/ai_agent/sarif_parser.py unified/findings.sarif --repo-root . [--json]
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
