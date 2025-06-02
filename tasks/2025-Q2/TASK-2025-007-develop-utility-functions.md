---
id: TASK-2025-007
title: "Розробка компонента допоміжних функцій (utils)"
status: done
priority: medium
type: tech_debt # Або feature
assignee: "@AI-DocArchitect"
created: 2025-06-02
updated: 2025-06-02
arch_refs:
  - ARCH-utils
audit_log:
  - {date: 2025-06-02, user: "@AI-DocArchitect", action: "created with status done"}
---
## Опис
Було створено файл `utils.py`, що містить набір загальних допоміжних функцій, які використовуються в різних модулях backend. Це включає функції для XOR-шифрування, кодування/декодування Base64, генерації випадкових імен змінних та визначення назв сервісів за портами.

## Критерії Приймання
- Файл `CYBER_DASHBOARD_BACKEND/utils.py` існує.
- Реалізовано функції:
    - `xor_cipher(data_str, key)`
    - `b64_encode_str(data_str)`
    - `b64_decode_str(b64_data_str)`
    - `generate_random_var_name(length, prefix)`
    - `get_service_name_be(port)`
- Функції коректно працюють та використовуються іншими модулями за потреби.

## Визначення Готовності
- Файл `utils.py` створено, функції реалізовано та протестовано (принаймні через використання в інших модулях).

## Нотатки
- Наявність `utils.py` сприяє уникненню дублювання коду та покращує структуру проєкту. 