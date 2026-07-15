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
import uuid
from datetime import datetime, timezone, timedelta
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


def get_caller_user(authorization: str | None):
    """Проверяет, что JWT в заголовке Authorization принадлежит настоящей
    Supabase-сессии. Не проверяет роль — просто "это авторизованный сотрудник
    CRM, а не случайный запрос из интернета"."""
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

    return user


def get_caller_profile(authorization: str | None) -> dict:
    """Проверяет JWT из заголовка Authorization и возвращает profile вызывающего.
    Бросает HTTPException(401/403), если токен отсутствует/невалиден или роль не разрешена."""
    user = get_caller_user(authorization)

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
# Не секрет — тот же ID уже зашит в публичный фронтенд-бандл (VITE_PAYME_MERCHANT_ID).
PAYME_MERCHANT_ID = os.getenv("PAYME_MERCHANT_ID") or "69afcf3bdf9eb25a97935f8e"


def _payme_checkout_url(invoice_id: Optional[str] = None, amount_uzs: Optional[float] = None) -> str:
    """Настоящая ссылка на оплату конкретного счёта. Без invoice_id/суммы
    (или пока нет открытого долга) отдаём fallback-адрес — он не открывает
    форму оплаты, только показывает общую страницу Payme по кассе."""
    if not invoice_id or not amount_uzs:
        return f"https://payme.uz/fallback/merchant/?id={PAYME_MERCHANT_ID}"
    amount_tiyin = int(round(amount_uzs * 100))
    raw = f"m={PAYME_MERCHANT_ID};ac.invoice_id={invoice_id};a={amount_tiyin}"
    encoded = base64.b64encode(raw.encode()).decode()
    return f"https://checkout.paycom.uz/{encoded}"


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


def _current_period() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _fmt_money(value: float) -> str:
    return f"{value:,.0f}".replace(",", " ") + " so'm"


def _billing_due_day() -> int:
    rows = supabase.table("billing_settings").select("due_day").eq("id", 1).limit(1).execute().data
    return (rows[0].get("due_day") if rows else None) or 5


def _student_balance(student_id: str) -> dict:
    """Реальный баланс за текущий месяц: сколько выставлено, сколько уже
    оплачено (через payment_allocations), сколько осталось долга и есть ли
    переплата. Если месяц покрыт активным пакетом (student_packages) —
    счёт не нужен. Если счёт ЕЩЁ не сформирован бухгалтерией (нет строки в
    invoices) — не молчим, а показываем ожидаемую сумму (tuition_amount
    студента) и дату, до которой обычно нужно оплатить (billing_settings)."""
    period = _current_period()

    package_rows = supabase.table("student_packages").select("id") \
        .eq("student_id", student_id).lte("start_period", period).gte("end_period", period).limit(1).execute().data
    covered_by_package = bool(package_rows)

    invoice_rows = supabase.table("invoices").select("id, amount, status, due_date") \
        .eq("student_id", student_id).eq("period", period).limit(1).execute().data
    invoice = invoice_rows[0] if invoice_rows else None

    student_rows = supabase.table("students").select("tuition_amount").eq("id", student_id).limit(1).execute().data
    tuition = (student_rows[0].get("tuition_amount") if student_rows else None) or None

    if not invoice and not covered_by_package and tuition:
        # Бухгалтерия ещё не нажала "Yaratish" в Finance и cron ещё не сработал —
        # без строки в invoices нет invoice_id, а без него оплата через бота
        # невозможна (Payme-ссылке нужен конкретный счёт). Формируем счёт сразу
        # тем же идемпотентным RPC, что и кнопка/cron — так "To'lash" в боте
        # появляется сама, а не только после ручного действия в Finance.
        try:
            supabase.rpc("generate_monthly_invoices", {"p_period": period}).execute()
        except Exception:
            pass
        invoice_rows = supabase.table("invoices").select("id, amount, status, due_date") \
            .eq("student_id", student_id).eq("period", period).limit(1).execute().data
        invoice = invoice_rows[0] if invoice_rows else None

    if not invoice:
        due_date = f"{period}-{_billing_due_day():02d}"
        return {
            "period": period, "invoice_issued": False, "total": float(tuition) if tuition else None,
            "paid": 0.0, "owed": 0.0, "credit": 0.0, "covered_by_package": covered_by_package,
            "invoice_id": None, "due_date": due_date,
        }

    alloc_rows = supabase.table("payment_allocations").select("amount").eq("invoice_id", invoice["id"]).execute().data or []
    paid = sum(float(a["amount"]) for a in alloc_rows)
    total = float(invoice["amount"])
    owed = max(0.0, total - paid)
    credit = max(0.0, paid - total)
    return {
        "period": period, "invoice_issued": True, "total": total, "paid": paid, "owed": owed, "credit": credit,
        "covered_by_package": covered_by_package, "invoice_id": invoice["id"], "due_date": invoice.get("due_date"),
    }


def _lesson_history(student_id: str) -> List[dict]:
    """Последние уроки ученика — то же, что учитель видит в клетках
    GroupAttendancePanel (дата/статус/оценка/комментарий), только на
    просмотр. score хранится 0-100 всегда; grading_scale учителя,
    который вёл конкретный урок, отдаём рядом — форматирует фронтенд
    (formatScore), чтобы не дублировать шкалу на бэкенде."""
    rows = supabase.table("attendance").select("date, status, score, notes, teacher_id") \
        .eq("student_id", student_id).order("date", desc=True).limit(10).execute().data or []
    teacher_ids = list({r["teacher_id"] for r in rows if r.get("teacher_id")})
    scales: dict = {}
    if teacher_ids:
        profs = supabase.table("profiles").select("id, grading_scale").in_("id", teacher_ids).execute().data or []
        scales = {p["id"]: p.get("grading_scale") or "percentage" for p in profs}
    return [
        {
            "date": r["date"],
            "status": r["status"],
            "score": r.get("score"),
            "notes": r.get("notes"),
            "grading_scale": scales.get(r.get("teacher_id"), "percentage"),
        }
        for r in rows
    ]


def _support_info(student_id: str) -> Optional[dict]:
    """Если у ученика есть активный support-case (24/52_support_cases.sql) —
    отдаём историю сессий (дата/тема/результат) родителю. Внутренние note и
    tags (для эскалации между учителями) сюда не идут — только то, что
    показано в OUTCOME_META на фронтенде."""
    assignment_rows = supabase.table("support_assignments").select("id") \
        .eq("student_id", student_id).eq("active", True).limit(1).execute().data
    if not assignment_rows:
        return None
    sessions = supabase.table("support_interventions").select("session_date, topic, outcome") \
        .eq("assignment_id", assignment_rows[0]["id"]).order("session_date", desc=True).limit(10).execute().data or []
    return {"sessions": sessions}


def _student_subject(student_id: str) -> Optional[str]:
    student_rows = supabase.table("students").select("group_id").eq("id", student_id).limit(1).execute().data
    group_id = student_rows[0].get("group_id") if student_rows else None
    if not group_id:
        return None
    group_rows = supabase.table("groups").select("subject").eq("id", group_id).limit(1).execute().data
    return group_rows[0].get("subject") if group_rows else None


WEEKDAY_PY_INDEX = {
    "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
    "friday": 4, "saturday": 5, "sunday": 6,
}


def _month_bounds():
    today = datetime.now(timezone.utc).date()
    start = today.replace(day=1)
    next_month = start.replace(day=28) + timedelta(days=4)
    end = next_month - timedelta(days=next_month.day)
    return start, end


def _monthly_attendance_stats(student_id: str) -> dict:
    """Сколько уроков в этом месяце должно пройти по расписанию группы
    (за весь месяц), сколько студент реально посетил, и конкретные даты
    пропусков — родителю понятнее "5 dan 8 tasiga keldi", чем просто
    список дат."""
    start, end = _month_bounds()
    start_str = start.strftime("%Y-%m-%d")
    end_str = end.strftime("%Y-%m-%d")

    student_rows = supabase.table("students").select("group_id").eq("id", student_id).limit(1).execute().data
    group_id = student_rows[0].get("group_id") if student_rows else None

    expected = 0
    if group_id:
        entries = supabase.table("schedule_entries").select("day_of_week").eq("group_id", group_id).execute().data or []
        weekdays = {WEEKDAY_PY_INDEX[e["day_of_week"]] for e in entries if e.get("day_of_week") in WEEKDAY_PY_INDEX}
        if weekdays:
            d = start
            while d <= end:
                if d.weekday() in weekdays:
                    expected += 1
                d += timedelta(days=1)

    attendance_rows = supabase.table("attendance").select("date, status, notes") \
        .eq("student_id", student_id).gte("date", start_str).lte("date", end_str).execute().data or []
    attended = sum(1 for a in attendance_rows if a["status"] == "present")
    absences = [a for a in attendance_rows if a["status"] == "absent"]

    return {"expected": expected, "attended": attended, "absences": absences}


def _tg_handle_balance(chat_id, student_ids: List[str]):
    lines = []
    if len(student_ids) > 1:
        lines.append(f"📚 Siz {len(student_ids)} ta fan bo'yicha o'qiyapsiz:")

    pay_buttons = []
    for sid in student_ids:
        student_rows = supabase.table("students").select("name").eq("id", sid).limit(1).execute().data
        student_name = student_rows[0]["name"] if student_rows else "?"
        subject = _student_subject(sid)
        title = f"<b>{student_name}</b>" + (f" ({subject})" if subject else "")

        bal = _student_balance(sid)
        due_line = f"\n📆 To'lov sanasi: {bal['due_date']}" if bal.get("due_date") else ""
        if bal["covered_by_package"]:
            money_line = "✅ Paket orqali to'langan"
        elif not bal["invoice_issued"]:
            estimate = f" (taxminan {_fmt_money(bal['total'])})" if bal["total"] else ""
            money_line = f"Bu oy uchun hisob-faktura hali chiqarilmagan{estimate}{due_line}"
        elif bal["owed"] > 0:
            money_line = f"⚠️ To'langan {_fmt_money(bal['paid'])} / Jami {_fmt_money(bal['total'])}\nQarz: <b>{_fmt_money(bal['owed'])}</b>{due_line}"
            pay_buttons.append({"text": f"💳 {student_name} uchun to'lash", "url": _payme_checkout_url(bal["invoice_id"], bal["owed"])})
        elif bal["credit"] > 0:
            money_line = f"✅ To'langan, ortiqcha: <b>{_fmt_money(bal['credit'])}</b>"
        else:
            money_line = f"✅ To'langan ({_fmt_money(bal['paid'])})"

        stats = _monthly_attendance_stats(sid)
        attendance_line = f"📊 Bu oy: {stats['attended']}/{stats['expected']} darsga keldi"
        if stats["absences"]:
            dates = ", ".join(a["date"] for a in stats["absences"][:10])
            attendance_line += f"\n📅 Qoldirgan kunlar: {dates}"

        lines.append(f"{title}\n{money_line}\n{attendance_line}")

    if pay_buttons:
        lines.append("💡 Havola orqali to'lang, so'ng to'lov chekining skrinshotini shu botga yuboring — administratsiya tekshirib tasdiqlaydi.")

    reply_markup = {"inline_keyboard": [[b] for b in pay_buttons]} if pay_buttons else None
    _tg_send(chat_id, "\n\n".join(lines) if lines else "Ma'lumot topilmadi", reply_markup)


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


def _tg_download_and_store_photo(file_id: str, student_id: str) -> Optional[str]:
    """Скачивает файл у Telegram и кладёт в приватный Storage bucket
    payment-screenshots. Возвращает storage_path или None при ошибке."""
    try:
        info = httpx.get(f"{TELEGRAM_API}/getFile", params={"file_id": file_id}, timeout=15).json()
        file_path = (info.get("result") or {}).get("file_path")
        if not file_path:
            print(f"[payment screenshot] getFile vernul bo'sh natija: {info}")
            return None

        file_bytes = httpx.get(f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_path}", timeout=25).content
        ext = file_path.rsplit(".", 1)[-1] if "." in file_path else "jpg"
        storage_path = f"{student_id}/{uuid.uuid4()}.{ext}"

        supabase.storage.from_("payment-screenshots").upload(
            storage_path, file_bytes, {"content-type": "image/jpeg"}
        )
        return storage_path
    except Exception as e:
        print(f"[payment screenshot upload error] {e}")
        return None


def _tg_handle_photo(chat_id, student_ids: List[str], photo: List[dict], caption: Optional[str]):
    if not student_ids:
        return
    # Telegram присылает один и тот же снимок в нескольких разрешениях —
    # берём самое крупное для лучшего качества при просмотре в CRM.
    largest = max(photo, key=lambda p: p.get("file_size") or p.get("width") or 0)
    file_id = largest["file_id"]

    # К какому именно ученику относится чек — неясно, если к одному чату
    # привязано несколько детей; прикрепляем ко всем, бухгалтер разберётся
    # при подтверждении, кому именно засчитать оплату.
    saved_any = False
    for sid in student_ids:
        storage_path = _tg_download_and_store_photo(file_id, sid)
        supabase.table("payment_screenshots").insert({
            "student_id": sid,
            "chat_id": chat_id,
            "telegram_file_id": file_id,
            "storage_path": storage_path,
            "caption": caption,
            "status": "pending",
        }).execute()
        saved_any = saved_any or bool(storage_path)

    if saved_any:
        _tg_send(chat_id, "To'lov cheki qabul qilindi ✅ Administratsiya tekshiradi va tasdiqlaydi.")
    else:
        _tg_send(chat_id, "Chekni saqlab bo'lmadi, birozdan so'ng qayta urinib ko'ring yoki administratorga murojaat qiling.")


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
    photo = message.get("photo")

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

    if photo:
        _tg_handle_photo(chat_id, student_ids, photo, message.get("caption"))
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

    group_ids = [s["group_id"] for s in students if s.get("group_id")]
    groups_by_id = {}
    if group_ids:
        group_rows = supabase.table("groups").select("id, subject").in_("id", group_ids).execute().data or []
        groups_by_id = {g["id"]: g.get("subject") for g in group_rows}

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
        balance = _student_balance(s["id"])
        balance["pay_url"] = _payme_checkout_url(balance["invoice_id"], balance["owed"]) if balance["owed"] > 0 else None

        attendance_stats = _monthly_attendance_stats(s["id"])
        lessons = _lesson_history(s["id"])
        support = _support_info(s["id"])

        result.append({
            "id": s["id"],
            "name": s["name"],
            "subject": groups_by_id.get(s.get("group_id")),
            "schedule": schedule,
            "homework": homework,
            "covered": covered,
            "makeup": makeup,
            "balance": balance,
            "attendance": attendance_stats,
            "lessons": lessons,
            "support": support,
        })

    return {"linked": True, "students": result, "subjectCount": len(result)}


# =========================================================
# Уведомления родителям/студентам из CRM (оплата принята, отметки,
# напоминания и т.п.) — sendTelegramNotification() на фронтенде раньше
# просто писала строку в telegram_notifications, которую никто не читал.
# Теперь фронтенд зовёт этот эндпоинт напрямую, и бот шлёт сообщение сразу.
# =========================================================
class NotifyRequest(BaseModel):
    student_id: Optional[str] = None
    phone: Optional[str] = None
    message: str


@app.post("/telegram/notify")
def telegram_notify(payload: NotifyRequest, authorization: str | None = Header(default=None)):
    get_caller_user(authorization)  # любой авторизованный сотрудник CRM, без ограничения по роли

    chat_ids: set = set()
    if payload.student_id:
        rows = supabase.table("telegram_links").select("chat_id").eq("student_id", payload.student_id).execute().data or []
        chat_ids.update(r["chat_id"] for r in rows)

    if not chat_ids and payload.phone:
        digits = _tg_last_digits(payload.phone)
        if digits:
            students = supabase.table("students").select("id, phone, parent_number").execute().data or []
            matched_ids = [
                s["id"] for s in students
                if (s.get("parent_number") and _tg_last_digits(s["parent_number"]) == digits)
                or (s.get("phone") and _tg_last_digits(s["phone"]) == digits)
            ]
            if matched_ids:
                rows = supabase.table("telegram_links").select("chat_id").in_("student_id", matched_ids).execute().data or []
                chat_ids.update(r["chat_id"] for r in rows)

    for cid in chat_ids:
        _tg_send(cid, payload.message)

    return {"sent": len(chat_ids)}
