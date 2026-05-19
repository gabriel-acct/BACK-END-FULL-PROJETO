import sys
from pathlib import Path

# Permite rodar: python test/login_api.py a partir da pasta back-end (ou caminho absoluto ao arquivo)
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from db.queires import update_token
import requests

try:

    url = "https://api.dataimpulse.com/reseller/user/token/get"

    payload = {
        "login": "miguelgaciahen@gmail.com",
        "password": "3p5pJwn87hBEb8TAlV06hZVicpnLDNKO"
    }

    r = requests.post(url, json=payload)

    data = r.json()

    if data:
        print(data["token"])
        update_token(data["token"], 1)
        
    else:
        print(data["message"])

except Exception as e:
    print(f"Error: {e}")