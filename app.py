import json
import os
import hmac
import hashlib
import urllib.parse
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI()

# Логирование запуска
print("🚀 Starting FastAPI app...")

# Разрешаем запросы с любых источников (для разработки)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Для продакшена укажи конкретный origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Загружаем токен из окружения
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
if not BOT_TOKEN:
    print("⚠️ BOT_TOKEN не найден в переменных окружения")


# Проверка подписи
def is_valid_init_data(init_data: str, bot_token: str) -> bool:
    print(f"🔐 Начало проверки initData:\n{init_data}\n")
    try:
        parsed = dict(urllib.parse.parse_qsl(init_data))
        print(f"📦 Распарсенные параметры:\n{parsed}\n")

        received_hash = parsed.pop("hash", None)
        parsed.pop("signature", None)

        if not received_hash:
            print("❌ Hash отсутствует в initData")
            return False

        # Фиксируем формат поля user
        if "user" in parsed:
            try:
                user_obj = json.loads(parsed["user"])
                parsed["user"] = json.dumps(user_obj, separators=(",", ":"), ensure_ascii=False)
            except Exception as e:
                print(f"⚠️ Не удалось распарсить user: {e}")

        sorted_items = sorted(parsed.items())
        data_check_string = "\n".join(f"{k}={v}" for k, v in sorted_items)
        print(f"📄 Data check string:\n{data_check_string}\n")

        secret_key = hmac.new(bot_token.encode(), b"WebAppData", hashlib.sha256).digest()
        print(f"🔑 Секретный ключ: {secret_key.hex()}\n")

        calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        print(f"🧮 Вычисленный hash: {calculated_hash}")
        print(f"✅ Результат проверки: {'валидный' if calculated_hash == received_hash else 'невалидный'}\n")

        return calculated_hash == received_hash

    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return False



# Основной обработчик запроса от Telegram WebApp
@app.post("/webapp")
async def handle_webapp(request: Request):
    try:
        body = await request.json()
        print("📥 Получен запрос:", body)

        query_id = body.get("query_id")
        init_data = body.get("initData")

        if not query_id or not init_data:
            print("⚠️ Нет query_id или initData")
            return JSONResponse(content={"ok": False, "error": "Missing query_id or initData"}, status_code=400)

        if not is_valid_init_data(init_data, BOT_TOKEN):
            print("⚠️ Подпись initData не прошла проверку")
            return JSONResponse(content={"ok": False, "error": "Invalid initData"}, status_code=403)

        print("✅ Успешно обработано")
        return {"ok": True, "query_id": query_id, "init_data": init_data}

    except Exception as e:
        print(f"❌ Ошибка при обработке запроса: {e}")
        return JSONResponse(content={"ok": False, "error": "Server error"}, status_code=500)
