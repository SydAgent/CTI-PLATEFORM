import httpx
import asyncio
import time

API_URL = "http://localhost:8000/api/v1/internal/nlp/inject"

# Note: Pour que ce script fonctionne en temps réel, l'API FastAPI doit exposer cet endpoint 
# ou l'injection directe en WebSocket. Si l'endpoint n'est pas encore câblé dans le backend, 
# nous allons utiliser le cache Redis ou un mock endpoint (ce script en est la preuve de concept).

async def fire_nlp_event():
    print("[+] Armement Séquence NLP Live (Cible: SciBERTEnginePanel)")
    payload = {
        "rawText": "Opération Phantom: APT29 suspecté. Exfiltration vers 185.199.108.153 validée. Hash du binaire: c54413009fe91a5ccdb8...",
        "entities": [
            {"label": "ACTOR", "text": "APT29", "conf": 0.99},
            {"label": "IP", "text": "185.199.108.153", "conf": 0.95},
            {"label": "MITRE_TTP", "text": "T1048 Exfiltration", "conf": 0.88},
            {"label": "IOC_HASH", "text": "c54413...", "conf": 0.91}
        ]
    }
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(API_URL, json=payload, timeout=5.0)
            if resp.status_code == 200:
                print(f"[!] Injection Validée: {payload['rawText'][:40]}...")
            else:
                print(f"[-] Endpoint non-disponible (Statut: {resp.status_code}).")
                print("Assurez-vous d'avoir ouvert un endpoint /api/v1/internal/nlp/inject pour recevoir le flux.")
    except Exception as e:
        print(f"[-] Erreur de connexion au C2 ONYX: {e}")

if __name__ == "__main__":
    print("=== ONYX AI STRESS TEST ===")
    for _ in range(3):
        asyncio.run(fire_nlp_event())
        time.sleep(2)
