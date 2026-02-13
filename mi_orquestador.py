import sys
import asyncio
import json

from agents import run_security_scan 

async def main():
    if len(sys.argv) < 3:
        print("❌ Error: Faltan argumentos.")
        print("Uso: python mi_orquestador.py servidor.py hallazgos_previos.json")
        return

    file_py = sys.argv[1]
    file_json = sys.argv[2]

    print(f"--- 🛡️ INICIANDO AUDITORÍA ---")
    print(f"📄 Código: {file_py}")
    print(f"📊 Reporte previo: {file_json}")

    try:
        resultado = await run_security_scan(file_py, file_json)
        print("\n✅ Auditoría finalizada con éxito.")
    except Exception as e:
        print(f"💥 Error durante la ejecución: {e}")

if __name__ == "__main__":
    asyncio.run(main())