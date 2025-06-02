---
id: TASK-2025-001
title: "Налаштування ядра додатку Flask та базових маршрутів"
status: done
priority: high
type: feature
assignee: "@AI-DocArchitect"
created: 2025-06-02
updated: 2025-06-02
arch_refs:
  - ARCH-app-core
audit_log:
  - {date: 2025-06-02, user: "@AI-DocArchitect", action: "created with status done"}
---
## Опис
Було налаштовано основний файл backend-додатку `app_core.py`. Це включало створення фабрики додатку Flask `create_app()`, налаштування CORS, реєстрацію Blueprint-ів для всіх основних модулів (`payload_generator`, `reconnaissance`, `c2_control`, `operational_data`) та визначення тестового маршруту `/api/health`.

## Критерії Приймання
- Файл `CYBER_DASHBOARD_BACKEND/app_core.py` існує та містить функцію `create_app()`.
- Додаток Flask успішно створюється.
- CORS налаштовано для дозволу запитів з frontend.
- Blueprint-и для всіх чотирьох основних модулів зареєстровані в додатку.
- Маршрут `GET /api/health` доступний і повертає JSON з інформацією про статус, версію та час.
- Додаток може бути запущений через `if __name__ == '__main__':` для розробки.
- Ініціалізація стану C2 (симульовані імпланти) перенесена з `app_core.py` до відповідного модуля `c2_control.logic`.

## Визначення Готовності
- Функціональність ядра додатку реалізована та присутня в кодовій базі.
- Додаток запускається без помилок ініціалізації.
- Базовий маршрут `/api/health` працює коректно.

## Нотатки
- Ця задача є основою для функціонування всього backend. 