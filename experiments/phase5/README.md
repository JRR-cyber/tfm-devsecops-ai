# Fase 5: datos de los experimentos

Protocolo: [D12](../../docs/benchmark/decisions.md). Ejecutor y análisis: `scripts/ai_agent/phase5.py` y `phase5_analysis.py` (ver el [README del agente](../../scripts/ai_agent/README.md), «Fase 5»).

## Contenido

| Ruta | Qué es |
|---|---|
| `input/findings.sarif.gz` | Entrada de los dos experimentos: el SARIF unificado de la ejecución de CI 43938956025, reducido a los 92 resultados de los 116 hallazgos (83 de triaje y 33 de remediación). |
| `input/MANIFEST.json` | Origen y hashes de la entrada. Cada ejecución comprueba `content_sha256` antes de empezar. |
| `triage-p1.jsonl` … `triage-p3.jsonl` | Triaje: una línea por llamada (83 hallazgos × 9 celdas = 747 por pasada). |
| `remediation-p1.jsonl` … `remediation-p3.jsonl` | Remediación: una línea por intento del bucle (33 casos × 6 condiciones, hasta 3 intentos). |
| `discarded/remediation-p1-r1.jsonl` | Las 5 filas de la primera pasada de remediación con el tag `phase5-protocol`, descartadas al congelar `phase5-protocol-r2` (apéndice de D12 del 26-11-2026). No entran en el análisis. |
| `analysis.md` | Informe de `phase5_analysis.py analyze`. |

Cada línea de log lleva la clave del intento (hallazgo, estrategia, traza, RAG, intento, pasada), el resultado, los tokens, los tiempos y la procedencia: proveedor, modelo servido, commit del protocolo y hash de la entrada.

## Antes de la primera ejecución oficial

1. **Prueba de humo** con la API real (`--dev`, logs en `results/dev/phase5/`, que git ignora). Sirve para ver few-shot y CoT funcionando en Together, que el piloto no probó:
   ```bash
   export CODEQL_CLI=~/tools/codeql/codeql.exe
   LLM_PROVIDER=together LLM_BUDGET_USD=0.10 python scripts/ai_agent/phase5.py triage --rep 1 --dev --limit 3
   LLM_PROVIDER=together LLM_BUDGET_USD=0.20 python scripts/ai_agent/phase5.py remediation --rep 1 --dev --limit 1
   ```
2. **Congelación:** fusionar en `main` y crear el tag sobre ese commit:
   ```bash
   git tag -a phase5-protocol -m "Protocolo de la Fase 5 (D12) congelado"
   git push origin phase5-protocol
   ```
   Desde ese momento, el ejecutor rechaza cualquier cambio en `scripts/ai_agent/`, `benchmarks/` o `experiments/phase5/input/` respecto al tag.

## Ejecución

En Git Bash, desde la raíz, con `TOGETHER_API_KEY` exportada (`read -rsp`, nunca en el chat). Orden de D12: primero las tres pasadas de triaje y después las tres de remediación, de una en una y nunca en paralelo.

```bash
git switch -c exp/phase5-datos phase5-protocol      # rama para ir commiteando los logs

export LLM_PROVIDER=together
LLM_BUDGET_USD=1.00 python scripts/ai_agent/phase5.py triage --rep 1        # ~1 h
LLM_BUDGET_USD=1.00 python scripts/ai_agent/phase5.py triage --rep 2
LLM_BUDGET_USD=1.00 python scripts/ai_agent/phase5.py triage --rep 3

# La remediación se ejecuta con el tag phase5-protocol-r2 (apéndice de D12 del 26-11-2026)
export CODEQL_CLI=~/tools/codeql/codeql.exe          # y Docker Desktop arrancado
LLM_BUDGET_USD=1.50 python scripts/ai_agent/phase5.py remediation --rep 1   # ~10 h
LLM_BUDGET_USD=1.50 python scripts/ai_agent/phase5.py remediation --rep 2
LLM_BUDGET_USD=1.50 python scripts/ai_agent/phase5.py remediation --rep 3
```

- **Coste estimado:** unos $0,45 por pasada de triaje y $0,45–0,60 por pasada de remediación; unos $3 en total. El tope es por log y cuenta lo que ese log ya gastó.
- **Progreso:** `python scripts/ai_agent/phase5.py status`.
- **Al terminar cada tanda:**
  ```bash
  git add experiments/phase5/*.jsonl
  git commit -m "Fase 5: <experimento> pasada <n>"
  ```

### Si la ejecución se para

| Código | Qué pasó | Qué hacer |
|---|---|---|
| 0 | La pasada terminó. | Commitear el log. |
| 1 | Fallo de infraestructura: Docker, CodeQL o red. El intento no se registra. Un parche que deja el fichero sin parsear ya no es fallo de infraestructura: se registra como intento PARSE_ERROR. | Arreglar la causa, por ejemplo reiniciando Docker Desktop, y relanzar el mismo comando. |
| 75 | Cuota del proveedor. | Relanzar más tarde. |
| 76 | Tope de gasto del log. | Revisar el gasto en el panel de Together antes de subir `LLM_BUDGET_USD` y relanzar. |
| 77 | **La API sirvió otro modelo.** | **No relanzar.** D12: se repite el experimento afectado. Hay que decidirlo antes de seguir. |
| 130 | Interrumpido a mano. | Relanzar cuando se quiera. |

Relanzar el mismo comando retoma donde se quedó: lo que ya está en el log no se vuelve a pagar.

## Análisis

```bash
python scripts/ai_agent/phase5_analysis.py analyze        # escribe experiments/phase5/analysis.md
```

El análisis está fijado en D12 y se probó con datos simulados antes de la primera llamada (`phase5_analysis.py selftest`).
