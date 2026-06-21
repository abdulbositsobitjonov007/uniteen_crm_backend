from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client, Client
import os
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

# Инициализируем Supabase клиент с правами супер-админа
url: str = os.getenv("SUPABASE_URL") or ""
key: str = os.getenv("SUPABASE_KEY") or ""
supabase: Client = create_client(url, key)

app = FastAPI(title="Uniteen CRM API")

# Настройка CORS: разрешаем твоему React (на порту 5173) делать запросы к Python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Схема данных для валидации запроса от React
class EmployeeCreate(BaseModel):
    email: str
    password: str
    full_name: str
    role: str

@app.get("/")
def read_root():
    return {"message": "Бэкенд Uniteen CRM на Python успешно запущен!"}

@app.post("/api/employees/create", status_code=status.HTTP_201_CREATED)
def create_employee(employee: EmployeeCreate):
    try:
        # Используем встроенный админский метод создания пользователя без отправки подтверждения
        # и без авторизации под этим пользователем
        admin_auth_client = supabase.auth.admin
        
        response = admin_auth_client.create_user({
            "email": employee.email,
            "password": employee.password,
            "email_confirm": True, # Сразу подтверждаем email, чтобы аккаунт был активен
            "user_metadata": {
                "full_name": employee.full_name,
                "role": employee.role
            }
        })
        
        return {"status": "success", "user_id": response.user.id}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Ошибка создания сотрудника: {str(e)}"
        )