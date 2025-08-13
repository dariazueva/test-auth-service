# test-auth-service
FastAPI E-commerce App

## Описание

Этот проект представляет собой backend интернет магазина с системой ролей, управлением товарами, категориями и отзывами.

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
- Регистрация и авторизация (JWT)
- Роли пользователей:
    - Admin - полные права
    - Supplier - управление товарами
    - Customer - просмотр и покупки
- CRUD для:
    - Категорий и подкатегорий
    - Продуктов с поддержкой slug
    - Отзывов с рейтингами
- Логирование всех запросов
- Назначение и снятие статуса поставщика
- Мягкое удаление пользователей, категорий, товаров и отзывов

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
ENGINE_URL=postgresql+asyncpg://authservice_user:mysecretpassword@localhost:5432/authservice
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

## Автор
Зуева Дарья Дмитриевна
Github https://github.com/dariazueva/