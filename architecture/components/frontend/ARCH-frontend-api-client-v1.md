---
id: ARCH-frontend-api-client
title: "Frontend: Клієнт API"
type: component
layer: presentation
owner: "@AI-DocArchitect"
version: v1
status: current
created: 2025-06-02
updated: 2025-06-02
tags: [frontend, api, client, configuration]
depends_on: []
referenced_by: []
---
## Контекст
Файл `api.js` визначає базову конфігурацію для взаємодії frontend-додатку з backend API. Його основна мета - надати централізоване місце для визначення URL-адреси API.

## Структура
Основний файл: `CYBER_DASHBOARD_FRONTEND/js/api.js`.

Ключовий елемент:
- `API_BASE_URL`: Константи, що зберігає базову URL-адресу backend API (наприклад, `http://localhost:5000/api`).

У файлі також закоментована потенційна функція `fetchData`, яка могла б слугувати обгорткою для `fetch` запитів, додаючи загальні заголовки (наприклад, `Content-Type: application/json`) та базову обробку помилок. Наразі ця функція не використовується активно, але її наявність вказує на можливий напрямок розвитку.

## Поведінка
- Інші JavaScript модулі frontend (наприклад, `payload_generator_ui.js`, `reconnaissance_ui.js`, `c2_control_ui.js`, `logging_adaptation_ui.js`) використовують константу `API_BASE_URL` для формування повних URL-адрес при виконанні запитів до backend.

## Еволюція
### Заплановано
- Можлива активація та розширення функції `fetchData` для централізації логіки API-запитів, обробки токенів автентифікації (якщо будуть додані) та стандартизації обробки відповідей/помилок.
### Історичне
- v1: Визначення базової URL для API. 