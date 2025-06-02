---
id: ARCH-app-core
title: "Ядро Додатку та Оркестрація Сервісів"
type: component
layer: application
owner: "@AI-DocArchitect"
version: v1
status: current
created: 2025-06-02
updated: 2025-06-02
tags: [backend, flask, core, orchestration, api]
depends_on:
  - ARCH-module-payload-generator
  - ARCH-module-reconnaissance
  - ARCH-module-c2-control
  - ARCH-module-operational-data
  - ARCH-config
referenced_by: []
---
## Контекст
Компонент `app_core.py` є центральною точкою входу та ініціалізації для backend-додатку CYBER DASHBOARD. Він відповідає за створення екземпляру Flask, налаштування CORS, реєстрацію всіх модульних Blueprint-ів та визначення базових маршрутів, таких як перевірка стану (`/api/health`).

## Структура
Основний файл: `CYBER_DASHBOARD_BACKEND/app_core.py`.

Ключові аспекти структури:
- Функція `create_app()`: Фабрика для створення та конфігурації Flask-додатку.
- Ініціалізація CORS для дозволу крос-доменних запитів (важливо для взаємодії з frontend).
- Динамічна реєстрація Blueprint-ів з окремих модулів:
    - `payload_generator.routes.payload_bp`
    - `reconnaissance.routes.recon_bp`
    - `c2_control.routes.c2_bp`
    - `operational_data.routes.ops_bp`
- Визначення маршруту `/api/health` для моніторингу стану сервісу.
- Блок `if __name__ == '__main__':` для запуску Flask-сервера в режимі розробки, який також виводить інформацію про доступні ендпоінти та версію.

## Поведінка
- При старті `app_core.py` (або через WSGI-сервер, що викликає `create_app()`), створюється та налаштовується екземпляр Flask.
- Усі маршрути, визначені в зареєстрованих Blueprint-ах, стають активними та готовими до обробки HTTP-запитів.
- Запит на `/api/health` повертає JSON з поточним статусом, версією backend та міткою часу.
- Сервер обробляє запити до API, маршрутизуючи їх до відповідних функцій-обробників у модулях.

## Еволюція
### Заплановано
- Можливе додавання централізованої обробки помилок.
- Інтеграція з більш продвинутими інструментами моніторингу та логування на рівні ядра.
### Історичне
- v1: Початкова версія після рефакторингу, винесення логіки модулів у Blueprints, ініціалізація стану C2 перенесена в модуль `c2_control`. 