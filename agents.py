import os
import json
import asyncio
from typing import TypedDict, Any, Optional
from pydantic_ai import Agent, models
from pydantic_ai.models.groq import GroqModel
from pydantic_ai.providers.groq import GroqProvider
from langgraph.graph import StateGraph, END

provider = GroqProvider()
model = GroqModel(
    "qwen/qwen3-32b",
    provider=provider
)

solver_agent = Agent(
    model=model,
    system_prompt="""
### ROL:
Ingeniero Senior en Ciberseguridad / Pentester de Red Team. Tu objetivo es encontrar vulnerabilidades que un análisis estático simple ignoraría.

### TAREA:
Analiza el código Python buscando fallos críticos. No te limites; asume que el código tiene al menos 6 vulnerabilidades (SQLi, SSRF, Command Injection, Path Traversal, Inyección de Headers o Lógica de Negocio).

### REGLAS DE SALIDA:
- Responde UNICAMENTE con un objeto JSON válido.
- No incluyas texto extra.
- Estructura:
{
  "vulnerabilities": [
    {
      "id": "vuln_XX",
      "type": "Nombre de la Vulnerabilidad",
      "sink_line": 0,
      "source_line": 0,
      "message": "Descripción técnica del vector de ataque"
    }
  ]
}
"""
)

audit_agent = Agent(
    model=model,
    system_prompt="""
### ROL:
Auditor Senior de Ciberseguridad actuando como "Juez de Discrepancias".

### TAREA DE CRÍTICA:
1. **Verificar Hallazgos:** Valida lo reportado por el Agente 1.
2. **BUSCAR EL GAP:** Identifica vulnerabilidades reales que el Agente 1 OMITIÓ. Si el código tiene fallos de inyección o lógica no listados, es obligatorio agregarlos aquí.

### FORMATO DE SALIDA (JSON ESTRICTO):
{
  "audit_summary": {
    "total_received": 0,
    "confirmed": 0,
    "discrepancies_found": 0
  },
  "validated_vulnerabilities": [
    {
      "id": "vuln_XX",
      "status": "CONFIRMADA | FALSO_POSITIVO | NUEVA_DETECCION",
      "discrepancy_note": "Justificación de por qué es real o por qué el Agente 1 no la vio",
      "severity_check": "CRITICAL | HIGH | MEDIUM | LOW",
      "technical_proof": "Explicación del flujo de datos real"
    }
  ]
}
"""
)

valid_json_agent = Agent(
    model=model,
    system_prompt="""
### ROL:
Auditor Senior de Ciberseguridad con enfoque en validación binaria (True/False Positive).

### TAREA DE AUDITORÍA:
Determina si cada vulnerabilidad identificada es:
- **True Positive (TP):** Existe un camino real y explotable desde el source al sink.
- **False Positive (FP):** El hallazgo no representa un riesgo real bajo las condiciones del código.

### FORMATO DE SALIDA (JSON ESTRICTO):
{
  "audit_results": [
    {
      "id": "ID_ORIGINAL",
      "classification": "True Positive | False Positive",
      "verdict": "CONFIRMADA | DESCARTADA",
      "analysis": "Justificación técnica profunda del análisis.",
      "remediation": "Código corregido sugerido.",
      "priority": "CRITICAL | HIGH | MEDIUM | LOW"
    }
  ]
}
"""
)

document_agent_1 = Agent(
    model=model,
    system_prompt="""
### ROL:
Documentador Técnico de Seguridad. Tu misión es consolidar el reporte final (JSON/HTML).

### TAREA:
Genera un informe técnico detallado en Markdown que incluya:
1. **Confirmación de Hallazgos:** Lista clara de True Positives vs False Positives.
2. **Justificación:** Por qué cada vulnerabilidad es real o fue descartada.
3. **Priorización:** Clasificación de impacto (Critical, High, Medium, Low).
4. **Trazabilidad:** Ruta completa Source → Sink.

### FORMATO DE SALIDA:
Markdown profesional con tablas para comparar estados y bloques de código para remediaciones.
"""
)

class AgentState(TypedDict):
    source_code: str
    vulnerabilities_raw: Any
    audit_report: Any
    final_validation: Any
    documentation: Any

def extract_content(response):
    if hasattr(response, 'output'): return response.output
    if hasattr(response, 'data'): return response.data
    if hasattr(response, 'result'): return response.result
    return str(response)

async def solver_node(state: AgentState):
    if state.get("vulnerabilities_raw"):
        print("--- [Nodo Solver] Usando JSON pre-cargado ---")
        return {"vulnerabilities_raw": state["vulnerabilities_raw"]}
    print("--- [Nodo Solver] Analizando código desde cero ---")
    response = await solver_agent.run(state["source_code"])
    return {"vulnerabilities_raw": extract_content(response)}

async def audit_node(state: AgentState):
    print("--- [Nodo Auditor] Verificando hallazgos vs Código ---")
    prompt = f"CÓDIGO:\n{state['source_code']}\n\nHALLAZGOS:\n{state['vulnerabilities_raw']}"
    response = await audit_agent.run(prompt)
    return {"audit_report": extract_content(response)}

async def validation_node(state: AgentState):
    print("--- [Nodo Validador] Ejecutando Red Teaming ---")
    prompt = f"CÓDIGO:\n{state['source_code']}\n\nREPORTE AUDITADO:\n{state['audit_report']}"
    response = await valid_json_agent.run(prompt)
    return {"final_validation": extract_content(response)}

async def documentation_node(state: AgentState):
    print("--- [Nodo Documentador] Generando Informe Final ---")
    prompt = f"CÓDIGO:\n{state['source_code']}\n\nVALIDACIÓN FINAL:\n{state['final_validation']}"
    response = await document_agent_1.run(prompt)
    return {"documentation": extract_content(response)}

workflow = StateGraph(AgentState)
workflow.add_node("solver", solver_node)
workflow.add_node("auditor", audit_node)
workflow.add_node("validator", validation_node)
workflow.add_node("documenter", documentation_node)
workflow.set_entry_point("solver")
workflow.add_edge("solver", "auditor")
workflow.add_edge("auditor", "validator")
workflow.add_edge("validator", "documenter")
workflow.add_edge("documenter", END)
app = workflow.compile()

async def run_security_scan(file_path_py: str, file_path_json: Optional[str] = None):
    with open(file_path_py, "r", encoding="utf-8") as f:
        code = f.read()

    initial_vulnerabilities = None
    if file_path_json:
        with open(file_path_json, "r", encoding="utf-8") as f:
            try:
                initial_vulnerabilities = json.loads(f.read(), strict=False)
            except:
                pass

    inputs = {"source_code": code, "vulnerabilities_raw": initial_vulnerabilities}
    final_state = await app.ainvoke(inputs)

    file_name = os.path.basename(file_path_py)
    output_name = f"final_report_{file_name}.md"
    report_content = final_state.get("documentation", "Error")

    with open(output_name, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"✨ Proceso completado. Reporte en: {output_name}")
    return report_content
