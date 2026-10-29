"""AI triage/remediation agent (Fase 3).

Hybrid DevSecOps agent: it reads the pipeline's unified SARIF, triages each
finding with the help of the CodeQL taint trace, and proposes a patch for the
high-severity ones. See README.md for the step-by-step status.
"""
