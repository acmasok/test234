from fastapi import FastAPI, Request
import hmac
import hashlib
import urllib.parse
from mangum import Mangum
import os
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Или укажи конкретный origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")


def is_valid_init_data(init_data: str, bot_token: str) -> bool:
    parsed = dict(urllib.parse.parse_qsl(init_data))
    received_hash = parsed.pop("hash", None)

    if not received_hash:
        return False

    data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(parsed.items()))
    secret_key = hashlib.sha256(bot_token.encode()).digest()
    calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    return calculated_hash == received_hash


@app.post("/webapp")
async def handle_webapp(request: Request):
    body = await request.json()
    print("body", body)
    query_id = body.get("query_id")
    init_data = body.get("initData")

    if not query_id or not init_data:
        return {"ok": False, "error": "Missing query_id or initData"}

    if not is_valid_init_data(init_data, BOT_TOKEN):
        return {"ok": False, "error": "Invalid initData"}

    return {"ok": True, "query_id": query_id, "init_data": init_data}

handler = Mangum(app)
