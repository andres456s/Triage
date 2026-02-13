

# Informe Técnico de Auditoría de Seguridad

## Confirmación de Hallazgos

| ID        | Clasificación     | Veredicto      | Prioridad  | Estado Final   |
|-----------|------------------|----------------|------------|----------------|
| vuln_01   | True Positive     | CONFIRMADA       | CRITICAL   | Vulnerabilidad |
| vuln_02   | False Positive    | DESCARTADA       | LOW        | Seguro         |
| vuln_03   | False Positive    | DESCARTADA       | LOW        | Seguro         |
| vuln_04   | True Positive     | CONFIRMADA       | CRITICAL   | Vulnerabilidad |

## Justificación y Análisis

### **vuln_01 - Inyección SQL en `login()`**
```python
# Fuente: Función login en la línea 13
def login(con, username, password):
    cur = con.cursor()
    sql_query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
    cur.execute(sql_query)
```
**¿Por qué es vulnerable?**  
Uso de f-strings sin parámetros parametrizados permite inyecciones como:
```sql
' OR '1'='1
```
**Ruta trazada:**  
Fuente → `input("Username: ")` → `login(username)` → SQL Query  
Sumidero → `cur.execute(sql_query)`

---

### **vuln_02 - `new_login()`**
```python
# Fuente: Función new_login en la línea 22
cur.execute(
    "SELECT id FROM users WHERE username = ? AND password = ?",
    (username, password)
)
```
**¿Por qué es seguro?**  
Uso correcto de parámetros parametrizados (`?` + tupla) previene inyecciones por completo.

---

### **vuln_03 - SSRF en `check_username()`**
```python
# Fuente: Función check_username en la línea 30
response = requests.get(f"https://api.github.com/users/{username}")
```
**¿Por qué no es crítico?**  
El endpoint externo (`api.github.com`) no permite acceso interno al sistema o redes. La entrada se inyecta en la URL pero no en parámetros internos de red.

---

### **vuln_04 - Ejecución de Comandos en `is_online_username()`**
```python
# Fuente: Función is_online_username en la línea 37
os.system(f"touch /tmp/{username}")
```
**¿Por qué es vulnerable?**  
Permite ejecutar comandos arbitrarios como:
```bash
malicious; rm -rf /
```
**Ruta trazada:**  
Fuente → `input("Username: ")` → `is_online_username(username)` → `os.system()`  
Sumidero → `os.system()` ejecuta comandos no validados.

---

## Priorización de Impacto

| ID        | Prioridad  | Riesgo asociado                          |
|-----------|------------|------------------------------------------|
| vuln_01   | **CRITICAL** | Pérdida de credenciales/daño estructural |
| vuln_04   | **CRITICAL** | Ejecución remota de código               |
| vuln_02   | **LOW**      | Sin riesgo real                          |
| vuln_03   | **LOW**      | Sin riesgo real                          |

---

## Recomendaciones de Remediation

### Para `vuln_01`:
```python
# Reemplazar:
sql_query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
cur.execute(sql_query)

# Por:
cur.execute(
    "SELECT id FROM users WHERE username = ? AND password = ?",
    (username, password)
)
```

### Para `vuln_04`:
```python
# Reemplazar:
os.system(f"touch /tmp/{username}")

# Por:
import subprocess
subprocess.run(['touch', f'/tmp/{username}'], check=True)
```

---

## Conclusiones
- **Hallazgos confirmados:** 2 vulnerabilidades críticas (`vuln_01`, `vuln_04`).  
- **Prácticas seguras:** `new_login()` y `check_username()` implementadas correctamente.  
- **Acciones inmediatas:** Reemplazar `f-strings` por parámetros parametrizados y evitar `os.system()` para comandos inseguros.  

Este informe clasifica y prioriza riesgos para una remediation efectiva alineada a estándares de seguridad OWASP.