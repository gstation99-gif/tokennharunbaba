import base64
import json
import re
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import os
import uvicorn

app = FastAPI(title="Supercell ID HDX Token Servisi")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/parse")
def parse_token(raw_data: str = Form("")):
    try:
        if not raw_data:
            return JSONResponse(status_code=400, content={"status": "error", "message": "Boş veri gönderildi!"})

        player_id = ""
        pass_token = ""
        jwt_token = ""

        # 1. JWT bulma (Basit ve güvenli regex)
        jwt_matches = re.findall(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', raw_data)
        if jwt_matches:
            jwt_matches.sort(key=len, reverse=True)
            jwt_token = jwt_matches[0]

            try:
                parts = jwt_token.split('.')
                if len(parts) >= 2:
                    payload_b64 = parts[1] + '==='
                    decoded_bytes = base64.urlsafe_b64decode(payload_b64.encode('utf-8'))
                    decoded_json = json.loads(decoded_bytes.decode('utf-8'))
                    
                    for k, v in decoded_json.items():
                        if isinstance(v, str):
                            if re.match(r'^\d+-\d+$', v) and not player_id:
                                player_id = v
            except Exception:
                pass

        # 2. Player ID arama
        if not player_id:
            pid_match = re.search(r'\b\d{1,3}-\d{6,12}\b', raw_data)
            if pid_match:
                player_id = pid_match.group(0)

        # 3. Pass Token arama
        pass_match = re.search(r'(?:passToken|pass_token|password|token)["'\s:=]+([a-zA-Z0-9]{24,64})', raw_data, re.IGNORECASE)
        if pass_match:
            pass_token = pass_match.group(1)
        else:
            hex_match = re.search(r'\b[a-f0-9]{32,64}\b', raw_data, re.IGNORECASE)
            if hex_match:
                pass_token = hex_match.group(0)

        if not jwt_token and not pass_token and not player_id:
            return JSONResponse(status_code=400, content={"status": "error", "message": "Geçerli bir JWT veya oturum bilgisi bulunamadı!"})

        hdx_line = f"{player_id} {pass_token} {jwt_token}".strip()

        return {
            "status": "success",
            "player_id": player_id,
            "pass_token": pass_token,
            "jwt": jwt_token,
            "hdx_line": hdx_line
        }
    except Exception as e:
        return JSONResponse(status_code=400, content={"status": "error", "message": str(e)})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
