# test-auth-service
Auth Service

## Описание

Микросервис аутентификации на FastAPI с JWT токенами и PostgreSQL

## Требования

- Python 3.12
- PostgreSQL
- FastAPI
- SQLAlchemy
- Alembic
- Docker
- uvicorn
- JWT

### Основной функционал
- Регистрация и авторизация
- Аутентификация (JWT)
- Обновление токенов
- Выход из системы
- Управление пользователями (CRUD)
- Проверка токенов
- Ролевая модель (админ\пользователь)

### Как запустить проект:

Клонировать репозиторий и перейти в него в командной строке:

```
git@github.com:dariazueva/test-auth-service.git
```
```
cd app
```
Cоздать и активировать виртуальное окружение:
```
python -m venv env
```
* Если у вас Linux/macOS
    ```
    source env/bin/activate
    ```
* Если у вас windows
    ```
    source env/Scripts/activate
    ```
```
python -m pip install --upgrade pip
```
Создайте файл .env и заполните его своими данными по образцу:
```
ENGINE_URL=postgresql+asyncpg://authservice_user:mysecretpassword@db:5432/authservice
SECRET_KEY=your_secret_key
ALGORITHM=HS256
```
#### Запустите через докер:
```bash
docker-compose up -d --build
```
Приложение доступно: http://localhost:8000
#### Выполните миграции:
```bash
docker-compose exec web alembic upgrade head
```
#### API Документация:
Swagger - http://localhost:8000/docs
Redoc - http://localhost:8000/redoc

#### API Endpoints
* POST /auth/register - Регистрация нового пользователя
* POST /auth/token - Получение JWT токенов
* POST /auth/refresh - Обновление токенов
* POST /auth/logout - Выход из системы
* GET /auth/me - Получение данных текущего пользователя
* GET /auth/check_token - Проверка валидности токена
* PATCH /auth/users/{user_id} - Изменение данных пользователя
* GET /auth/users/{user_id} - Получение данных о конкретном пользователе
* DELETE /auth/users/{user_id} - Деактивация пользователя (мягкое удаление)
* GET /auth/users - Получение списка активных пользователей

## Автор
Зуева Дарья Дмитриевна
Github https://github.com/dariazueva/