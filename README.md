README
---

## 🔹 Componentes

### 1️⃣ CLI (Capa de Entrada)

- Maneja argumentos:
  - Archivo Python de ejemplo
  - JSON de hallazgos previos
  - orquestador(CLI)
  - 
- salida :
  - un archivo .md

---

### 2️⃣ Orquestador

- Función principal: `run_security_scan`
- Coordina ejecución de agentes
- Maneja flujo de datos entre:
  - Código fuente
  - Hallazgos previos
  - Modelo LLM

---

### 3️⃣ Agentes

Arquitectura basada en separación de responsabilidades:

- Agente de análisis 
- Agente Auditor
- Agente evaluador de falsos positivos
- Agente generador de reporte

Cada agente:
- Recibe contexto
- Invoca el modelo
- Devuelve salida estructurada

---

### 4️⃣ Modelo LLM

Modelo utilizado:

- QWEN-3

El modelo se usa para:

- Detección de vulnerabilidades
- Clasificación de severidad
- Generación de recomendaciones
- Consolidación del reporte final

---

# 🛠️ Herramientas Utilizadas

| Categoría | Herramienta |
|------------|-------------|
| orquestacion de agentes | langgraph |
| agentes | pydantic-ai |
| LLM | QWEN-3|
| Lenguaje | Python |

---

# 🔌 MCP Tools Utilizados

La solución puede integrarse con herramientas bajo el estándar **Model Context Protocol (MCP)** para extender capacidades del modelo.

Ejemplos de tools utilizadas:

- 📂 File Reader Tool (lectura de archivos locales)
- 🧮 Code Analysis Tool (procesamiento estructural)
- 📊 JSON Parsing Tool
- 🔎 Security Pattern Detection Tool

Estas tools permiten que el modelo:

- Acceda a contexto estructurado
- Procese código de forma controlada
- Mantenga trazabilidad en el flujo

---

# ⚙️ Flujo de Ejecución

1. Usuario ejecuta:

```bash
python mi_orquestador.py scan servidor.py hallazgos.json
```
# Estructura del Projecto
```bash
│
│
├── mi_orquestador.py
├── agents.py
├── hallazgos_previos.json
├── servidor.py
└── README.md
```
# Consideraciones de ejecucion:
- Cree un ambiente de python para la instalacion de las librerias
- instale las librerias
  ```bash
  pip install pydantic-ai
  pip install groq
  pip install langgraph
  pip install requests
  ```
- configure la llave o API-key de GROQ desde cmd con el siguiente comando dentro del ambiente
  ```bash
   set GROQ_API_KEY="tu_clave_api_aqui"
  ```

---







