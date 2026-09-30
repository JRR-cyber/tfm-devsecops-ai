# Política de Seguridad - TFM DevSecOps AI

## Reporte de Vulnerabilidades

Este repositorio alberga un pipeline DevSecOps experimental con capacidades de remediación autónoma.
Si descubres una vulnerabilidad crítica no intencionada en la infraestructura del pipeline, por favor repórtala abriendo un Issue etiquetado como `security-report`.

## Herramientas de Análisis Integradas

- **SAST / SCA:** CodeQL, Snyk, Trivy
- **Secret Scanning:** GitGuardian / TruffleHog
- **Triaje e IA:** Agente basado en LLM para análisis SARIF
