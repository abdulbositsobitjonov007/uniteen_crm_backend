from fastapi import FastAPI, HTTPException, Header, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client, Client
from typing import List, Optional
import os
import base64
import time
import hmac
import hashlib
import json
from urllib.parse import parse_qsl
import httpx
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

# Инициализируем Supabase клиент с правами супер-админа
url: str = os.getenv("SUPABASE_URL") or ""
key: str = os.getenv("SUPABASE_KEY") or ""
supabase: Client = create_client(url, key)

app = FastAPI(title="Uniteen CRM API")

# Настройка CORS: разрешаем твоему React делать запросы к Python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "https://uniteen-crm.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Роли, которым разрешено создавать новых сотрудников.
# head_teacher может добавлять только учителей — это принудительно применяется ниже,
# независимо от того, что прислал клиент (защита от подмены запроса напрямую, в обход UI).
ALLOWED_CREATOR_ROLES = {"boss", "manager", "academic_director", "head_teacher"}


def get_caller_profile(authorization: str | None) -> dict:
    """Проверяет JWT из заголовка Authorization и возвращает profile вызывающего.
    Бросает HTTPException(401/403), если токен отсутствует/невалиден или роль не разрешена."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Отсутствует токен авторизации")

    token = authorization.split(" ", 1)[1].strip()
    try:
        user_response = supabase.auth.get_user(token)
        user = user_response.user if user_response else None
    except Exception:
        user = None

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Недействительный токен авторизации")

    profile = supabase.table("profiles").select("role, assigned_subject_id").eq("id", user.id).single().execute()
    caller_profile = profile.data or {}

    if caller_profile.get("role") not in ALLOWED_CREATOR_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав для добавления сотрудников")

    return caller_profile


# Схема данных для валидации запроса от React
class EmployeeCreate(BaseModel):
    email: str
    password: str
    full_name: str
    role: str
    phone: Optional[str] = None
    date_of_birth: Optional[str] = None
    branches: List[str] = []
    assigned_subject_id: Optional[str] = None
    assigned_subject: Optional[str] = None
    assigned_teachers: List[str] = []


@app.get("/")
def read_root():
    return {"message": "Бэкенд Uniteen CRM на Python успешно запущен!"}


@app.post("/api/employees/create", status_code=status.HTTP_201_CREATED)
def create_employee(employee: EmployeeCreate, authorization: str | None = Header(default=None)):
    caller_profile = get_caller_profile(authorization)
    caller_role = caller_profile.get("role")

    requested_role = employee.role
    requested_subject_id = employee.assigned_subject_id
    requested_subject = employee.assigned_subject
    requested_assigned_teachers = employee.assigned_teachers
    # head_teacher может добавлять только учителей своего направления — принудительно,
    # даже если в теле запроса прислали другое (защита от прямого вызова API в обход UI).
    if caller_role == "head_teacher":
        requested_role = "teacher"
        requested_subject_id = caller_profile.get("assigned_subject_id")
        requested_assigned_teachers = []

    try:
        admin_auth_client = supabase.auth.admin

        response = admin_auth_client.create_user({
            "email": employee.email,
            "password": employee.password,
            "email_confirm": True,  # Сразу подтверждаем email, чтобы аккаунт был активен
            "user_metadata": {
                "full_name": employee.full_name,
                "role": requested_role
            }
        })

        new_user_id = response.user.id

        # Достраиваем профиль сервером (service_role), а не с фронтенда напрямую —
        # чтобы role/branches/salary-поля нельзя было подделать прямым запросом к Supabase.
        supabase.table("profiles").update({
            "phone": employee.phone,
            "status": "working",
            "date_of_birth": employee.date_of_birth,
            "assigned_subject": requested_subject,
            "assigned_subject_id": requested_subject_id,
            "branches": employee.branches,
            "role": requested_role,
            "assigned_teachers": requested_assigned_teachers if requested_role == "academic_support" else [],
        }).eq("id", new_user_id).execute()

        return {"status": "success", "user_id": new_user_id}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Ошибка создания сотрудника: {str(e)}"
        )


# =========================================================
# Payme Merchant API (JSON-RPC 2.0) — приём вебхуков от Payme.
# ВНИМАНИЕ: без реального PAYME_KEY (секретный ключ мерчанта из кабинета
# Payme Business) и PAYME_MERCHANT_ID (публичный, используется на фронтенде
# для ссылки оплаты) эта интеграция не заработает — код готов, но не
# протестирован против настоящего мерчант-аккаунта Payme.
# =========================================================
PAYME_KEY = os.getenv("PAYME_KEY") or ""


def _payme_error(request_id, code: int, message_ru: str):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": {"ru": message_ru, "uz": message_ru, "en": message_ru}},
    }


def _payme_result(request_id, result: dict):
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _payme_find_one(table: str, column: str, value):
    rows = supabase.table(table).select("*").eq(column, value).limit(1).execute().data
    return rows[0] if rows else None


def _payme_get_invoice(account: dict):
    invoice_id = account.get("invoice_id") if account else None
    if not invoice_id:
        return None
    return _payme_find_one("invoices", "id", invoice_id)


def _payme_check_perform_transaction(request_id, params):
    invoice = _payme_get_invoice(params.get("account", {}))
    if not invoice:
        return _payme_error(request_id, -31050, "Счёт не найден")
    if invoice["status"] == "paid":
        return _payme_error(request_id, -31008, "Счёт уже оплачен")
    expected_tiyin = int(round(float(invoice["amount"]) * 100))
    if params.get("amount") != expected_tiyin:
        return _payme_error(request_id, -31001, "Неверная сумма")
    return _payme_result(request_id, {"allow": True})


def _payme_create_transaction(request_id, params):
    payme_id = params.get("id")
    time_ms = params.get("time")
    amount = params.get("amount")

    existing = _payme_find_one("payme_transactions", "id", payme_id)
    if existing:
        if existing["state"] != 1:
            return _payme_error(request_id, -31008, "Транзакция уже обработана")
        return _payme_result(request_id, {
            "create_time": existing["create_time"], "transaction": existing["id"], "state": existing["state"],
        })

    invoice = _payme_get_invoice(params.get("account", {}))
    if not invoice:
        return _payme_error(request_id, -31050, "Счёт не найден")
    if invoice["status"] == "paid":
        return _payme_error(request_id, -31008, "Счёт уже оплачен")

    expected_tiyin = int(round(float(invoice["amount"]) * 100))
    if amount != expected_tiyin:
        return _payme_error(request_id, -31001, "Неверная сумма")

    active = supabase.table("payme_transactions").select("id").eq("invoice_id", invoice["id"]).eq("state", 1).execute().data
    if active:
        return _payme_error(request_id, -31050, "У счёта уже есть активная транзакция")

    supabase.table("payme_transactions").insert({
        "id": payme_id, "invoice_id": invoice["id"], "amount_tiyin": amount, "state": 1, "create_time": time_ms,
    }).execute()

    return _payme_result(request_id, {"create_time": time_ms, "transaction": payme_id, "state": 1})


def _payme_perform_transaction(request_id, params):
    payme_id = params.get("id")
    tx = _payme_find_one("payme_transactions", "id", payme_id)
    if not tx:
        return _payme_error(request_id, -31003, "Транзакция не найдена")

    if tx["state"] == 2:
        return _payme_result(request_id, {"transaction": tx["id"], "perform_time": tx["perform_time"], "state": 2})
    if tx["state"] != 1:
        return _payme_error(request_id, -31008, "Невозможно выполнить операцию")

    invoice = _payme_find_one("invoices", "id", tx["invoice_id"])
    perform_time = int(time.time() * 1000)
    amount_sum = tx["amount_tiyin"] / 100

    payment = supabase.table("payments").insert({
        "student_id": invoice["student_id"],
        "amount": amount_sum,
        "method": "payme",
        "branch": invoice.get("branch"),
        "period": invoice.get("period"),
        "note": f"Payme transaction {payme_id}",
    }).execute().data[0]

    supabase.table("payment_allocations").insert({
        "payment_id": payment["id"], "invoice_id": invoice["id"], "amount": amount_sum,
    }).execute()
    supabase.table("invoices").update({"status": "paid"}).eq("id", invoice["id"]).execute()
    supabase.rpc("recompute_payment_status", {"p_student_id": invoice["student_id"]}).execute()

    supabase.table("payme_transactions").update({
        "state": 2, "perform_time": perform_time, "payment_id": payment["id"],
    }).eq("id", payme_id).execute()

    return _payme_result(request_id, {"transaction": payme_id, "perform_time": perform_time, "state": 2})


def _payme_cancel_transaction(request_id, params):
    payme_id = params.get("id")
    reason = params.get("reason")
    tx = _payme_find_one("payme_transactions", "id", payme_id)
    if not tx:
        return _payme_error(request_id, -31003, "Транзакция не найдена")

    cancel_time = int(time.time() * 1000)
    if tx["state"] == 2:
        # Отмена уже проведённого платежа — снимаем разнесение по счёту.
        # Саму запись payments не удаляем (never-delete), только отвязываем счёт.
        if tx.get("payment_id"):
            supabase.table("payment_allocations").delete().eq("payment_id", tx["payment_id"]).execute()
            supabase.table("invoices").update({"status": "pending"}).eq("id", tx["invoice_id"]).execute()
        new_state = -2
    elif tx["state"] == 1:
        new_state = -1
    else:
        return _payme_result(request_id, {"transaction": tx["id"], "cancel_time": tx["cancel_time"], "state": tx["state"]})

    supabase.table("payme_transactions").update({
        "state": new_state, "cancel_time": cancel_time, "reason": reason,
    }).eq("id", payme_id).execute()

    return _payme_result(request_id, {"transaction": payme_id, "cancel_time": cancel_time, "state": new_state})


def _payme_check_transaction(request_id, params):
    tx = _payme_find_one("payme_transactions", "id", params.get("id"))
    if not tx:
        return _payme_error(request_id, -31003, "Транзакция не найдена")
    return _payme_result(request_id, {
        "create_time": tx["create_time"], "perform_time": tx["perform_time"], "cancel_time": tx["cancel_time"],
        "transaction": tx["id"], "state": tx["state"], "reason": tx.get("reason"),
    })


def _payme_get_statement(request_id, params):
    rows = supabase.table("payme_transactions").select("*") \
        .gte("create_time", params.get("from")).lte("create_time", params.get("to")).execute().data or []
    transactions = [{
        "id": r["id"], "time": r["create_time"], "amount": r["amount_tiyin"],
        "account": {"invoice_id": r["invoice_id"]},
        "create_time": r["create_time"], "perform_time": r["perform_time"], "cancel_time": r["cancel_time"],
        "transaction": r["id"], "state": r["state"], "reason": r.get("reason"),
    } for r in rows]
    return _payme_result(request_id, {"transactions": transactions})


PAYME_METHODS = {
    "CheckPerformTransaction": _payme_check_perform_transaction,
    "CreateTransaction": _payme_create_transaction,
    "PerformTransaction": _payme_perform_transaction,
    "CancelTransaction": _payme_cancel_transaction,
    "CheckTransaction": _payme_check_transaction,
    "GetStatement": _payme_get_statement,
}


@app.post("/payme/webhook")
async def payme_webhook(request: Request):
    body = await request.json()
    request_id = body.get("id")
    method = body.get("method")
    params = body.get("params") or {}

    auth_header = request.headers.get("Authorization", "")
    login, _, password = "", "", ""
    if auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode()
            login, _, password = decoded.partition(":")
        except Exception:
            pass
    if login != "Paycom" or password != PAYME_KEY or not PAYME_KEY:
        return _payme_error(request_id, -32504, "Недостаточно прав")

    handler = PAYME_METHODS.get(method)
    if not handler:
        return _payme_error(request_id, -32601, "Метод не найден")
    return handler(request_id, params)


# =========================================================
# Telegram-кабинет ученика — двусторонний бот (не только рассылка чеков,
# но и команды: расписание, домашка, баланс, отработки).
# ВНИМАНИЕ: без реального TELEGRAM_BOT_TOKEN (от @BotFather) и без
# регистрации вебхука через setWebhook эта интеграция не заработает.
# =========================================================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or ""
TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

MAIN_MENU_KEYBOARD = {
    "keyboard": [
        [{"text": "📅 Jadval"}, {"text": "📚 Vazifalar"}],
        [{"text": "💰 Balans"}, {"text": "🔄 Otrabotkalar"}],
    ],
    "resize_keyboard": True,
}

CONTACT_REQUEST_KEYBOARD = {
    "keyboard": [[{"text": "📱 Telefon raqamni yuborish", "request_contact": True}]],
    "resize_keyboard": True,
    "one_time_keyboard": True,
}


def _tg_send(chat_id, text: str, reply_markup: Optional[dict] = None):
    if not TELEGRAM_BOT_TOKEN:
        print("[telegram send skipped] TELEGRAM_BOT_TOKEN is not set on this server")
        return
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    try:
        resp = httpx.post(f"{TELEGRAM_API}/sendMessage", json=payload, timeout=10)
        if resp.status_code != 200:
            print(f"[telegram send failed] {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[telegram send error] {e}")


def _tg_last_digits(phone: str, n: int = 9) -> str:
    digits = "".join(ch for ch in phone if ch.isdigit())
    return digits[-n:] if len(digits) >= n else digits


def _tg_linked_student_ids(chat_id) -> List[str]:
    rows = supabase.table("telegram_links").select("student_id").eq("chat_id", chat_id).execute().data or []
    return [r["student_id"] for r in rows]


def _tg_handle_start(chat_id):
    _tg_send(
        chat_id,
        "Assalomu alaykum! Uniteen o'quv markazi botiga xush kelibsiz.\n\n"
        "Ro'yxatdan o'tish uchun telefon raqamingizni yuboring:",
        CONTACT_REQUEST_KEYBOARD,
    )


def _tg_handle_contact(chat_id, contact: dict):
    phone = contact.get("phone_number", "")
    digits = _tg_last_digits(phone)
    if not digits:
        _tg_send(chat_id, "Telefon raqam noto'g'ri.")
        return

    students = supabase.table("students").select("id, name, phone, parent_number").execute().data or []
    matched = [
        s for s in students
        if (s.get("parent_number") and _tg_last_digits(s["parent_number"]) == digits)
        or (s.get("phone") and _tg_last_digits(s["phone"]) == digits)
    ]

    if not matched:
        _tg_send(chat_id, "Bu raqam bo'yicha o'quvchi topilmadi. Administratorga murojaat qiling.")
        return

    for s in matched:
        supabase.table("telegram_links").upsert(
            {"student_id": s["id"], "chat_id": chat_id, "phone": phone},
            on_conflict="chat_id,student_id",
        ).execute()

    names = ", ".join(s["name"] for s in matched)
    _tg_send(chat_id, f"Bog'landi: {names}\n\nQuyidagi menyudan foydalaning:", MAIN_MENU_KEYBOARD)


def _tg_handle_schedule(chat_id, student_ids: List[str]):
    students = supabase.table("students").select("id, name, group_id").in_("id", student_ids).execute().data or []
    lines = []
    for s in students:
        if not s.get("group_id"):
            continue
        entries = supabase.table("schedule_entries").select("day_of_week, start_time").eq("group_id", s["group_id"]).execute().data or []
        schedule_str = ", ".join(f"{e['day_of_week']} {e['start_time']}" for e in entries) or "jadval belgilanmagan"
        lines.append(f"<b>{s['name']}</b>: {schedule_str}")
    _tg_send(chat_id, "\n".join(lines) if lines else "Ma'lumot topilmadi")


def _tg_handle_homework(chat_id, student_ids: List[str]):
    students = supabase.table("students").select("id, name, group_id").in_("id", student_ids).execute().data or []
    lines = []
    for s in students:
        if not s.get("group_id"):
            continue
        hw = supabase.table("homework_assignments").select("title, due_date") \
            .eq("group_id", s["group_id"]).order("due_date", desc=True).limit(3).execute().data or []
        if not hw:
            continue
        lines.append(f"<b>{s['name']}</b>:")
        for h in hw:
            lines.append(f"  • {h['title']} (muddat: {h.get('due_date') or '-'})")
    _tg_send(chat_id, "\n".join(lines) if lines else "Vazifalar topilmadi")


def _tg_handle_balance(chat_id, student_ids: List[str]):
    lines = []
    for sid in student_ids:
        student = supabase.table("students").select("name").eq("id", sid).limit(1).execute().data
        student_name = student[0]["name"] if student else "?"
        coverage = supabase.table("student_coverage_view").select("covered").eq("student_id", sid).limit(1).execute().data
        covered = coverage[0]["covered"] if coverage else None
        status_text = "✅ To'langan" if covered else ("⚠️ Qarzdorlik bor" if covered is False else "Ma'lumot yo'q")
        lines.append(f"<b>{student_name}</b>: {status_text}")
    _tg_send(chat_id, "\n".join(lines) if lines else "Ma'lumot topilmadi")


def _tg_handle_makeup(chat_id, student_ids: List[str]):
    rows = supabase.table("makeup_lessons").select("*").in_("student_id", student_ids).in_("status", ["owed", "scheduled"]).execute().data or []
    if not rows:
        _tg_send(chat_id, "Otrabotkalar yo'q ✅")
        return
    lines = []
    for r in rows:
        if r["status"] == "owed":
            lines.append(f"⏳ {r['original_date']} — hali belgilanmagan")
        else:
            lines.append(f"📌 {r['original_date']} → {r.get('makeup_date') or '-'} sanasiga o'tkazildi")
    _tg_send(chat_id, "\n".join(lines))


@app.post("/telegram/webhook")
async def telegram_webhook(request: Request):
    # Telegram ретраит и в итоге отключает вебхук после серии 5xx — что бы ни
    # случилось внутри, отвечаем 200, иначе бот выглядит "мёртвым" для всех
    # пользователей из-за одной сломанной таблицы/запроса.
    try:
        return await _telegram_webhook_inner(request)
    except Exception as e:
        print(f"[telegram webhook error] {e}")
        return {"ok": True}


async def _telegram_webhook_inner(request: Request):
    update = await request.json()
    message = update.get("message")
    if not message:
        return {"ok": True}

    chat_id = message["chat"]["id"]
    text = (message.get("text") or "").strip()
    contact = message.get("contact")

    if text == "/start":
        _tg_handle_start(chat_id)
        return {"ok": True}

    if contact:
        _tg_handle_contact(chat_id, contact)
        return {"ok": True}

    student_ids = _tg_linked_student_ids(chat_id)
    if not student_ids:
        _tg_send(chat_id, "Avval ro'yxatdan o'ting: /start buyrug'ini yuboring.")
        return {"ok": True}

    if text in ("📅 Jadval", "/schedule"):
        _tg_handle_schedule(chat_id, student_ids)
    elif text in ("📚 Vazifalar", "/homework"):
        _tg_handle_homework(chat_id, student_ids)
    elif text in ("💰 Balans", "/balance"):
        _tg_handle_balance(chat_id, student_ids)
    elif text in ("🔄 Otrabotkalar", "/makeup"):
        _tg_handle_makeup(chat_id, student_ids)
    else:
        _tg_send(chat_id, "Quyidagi menyudan tanlang:", MAIN_MENU_KEYBOARD)

    return {"ok": True}


# =========================================================
# Telegram Mini App — веб-интерфейс, открывающийся прямо внутри Telegram
# (не отдельное приложение, HTML-страница на фронтенде + telegram-web-app.js).
# Авторизация — не через email/пароль, а через initData, которую Telegram
# подписывает сам и передаёт в открытую страницу; бэкенд проверяет подпись
# тем же BOT_TOKEN, которым бот был создан (только у нас и у Telegram он есть).
# =========================================================

def _tg_verify_init_data(init_data: str) -> dict:
    """Проверяет подпись initData по алгоритму Telegram. Бросает ValueError, если невалидна."""
    if not TELEGRAM_BOT_TOKEN:
        raise ValueError("TELEGRAM_BOT_TOKEN не задан на сервере")

    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = pairs.pop("hash", None)
    if not received_hash:
        raise ValueError("Отсутствует hash")

    data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
    secret_key = hmac.new(b"WebAppData", TELEGRAM_BOT_TOKEN.encode(), hashlib.sha256).digest()
    computed_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(computed_hash, received_hash):
        raise ValueError("Подпись initData не совпадает")

    auth_date = int(pairs.get("auth_date", "0"))
    if auth_date and (time.time() - auth_date) > 86400:
        raise ValueError("initData устарела")

    user_raw = pairs.get("user")
    user = json.loads(user_raw) if user_raw else {}
    return {"user": user}


class MiniAppRequest(BaseModel):
    initData: str


@app.post("/telegram/miniapp/data")
def telegram_miniapp_data(payload: MiniAppRequest):
    try:
        verified = _tg_verify_init_data(payload.initData)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    chat_id = verified["user"].get("id")
    if not chat_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Telegram foydalanuvchisi topilmadi")

    student_ids = _tg_linked_student_ids(chat_id)
    if not student_ids:
        return {"linked": False, "students": []}

    students = supabase.table("students").select("id, name, group_id").in_("id", student_ids).execute().data or []

    result = []
    for s in students:
        schedule = []
        homework = []
        if s.get("group_id"):
            schedule = supabase.table("schedule_entries").select("day_of_week, start_time").eq("group_id", s["group_id"]).execute().data or []
            homework = supabase.table("homework_assignments").select("title, description, due_date") \
                .eq("group_id", s["group_id"]).order("due_date", desc=True).limit(10).execute().data or []

        coverage = supabase.table("student_coverage_view").select("covered").eq("student_id", s["id"]).limit(1).execute().data
        covered = coverage[0]["covered"] if coverage else None

        makeup = supabase.table("makeup_lessons").select("*").eq("student_id", s["id"]).in_("status", ["owed", "scheduled"]).execute().data or []

        result.append({
            "id": s["id"],
            "name": s["name"],
            "schedule": schedule,
            "homework": homework,
            "covered": covered,
            "makeup": makeup,
        })

    return {"linked": True, "students": result}
