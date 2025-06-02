---
id: ARCH-module-payload-generator
title: "Модуль: Генератор Пейлоадів"
type: module
layer: application
owner: "@AI-DocArchitect"
version: v1
status: current
created: 2025-06-02
updated: 2025-06-02
tags: [backend, payload, generation, obfuscation, stager, pyinstaller, metamorphism]
depends_on:
  - ARCH-config
  - ARCH-utils
  - ARCH-stager-templates
referenced_by: []
---
## Контекст
Цей модуль відповідає за генерацію різноманітних типів пейлоадів (стейджерів) на основі запиту користувача. Він обробляє параметри, застосовує обфускацію, використовує шаблони стейджерів та може компілювати Python-стейджери у виконувані файли Windows (.EXE).

## Структура
Основна логіка модуля розташована в наступних файлах:
- `CYBER_DASHBOARD_BACKEND/payload_generator/logic.py`: Містить основні функції для:
    - `validate_payload_parameters_logic()`: Валідація вхідних параметрів пейлоада згідно зі схемою з `config.py`.
    - `patch_shellcode_logic()`: Заміна плейсхолдерів LHOST/LPORT у наданому шеллкоді.
    - `obfuscate_string_literals_in_python_code_logic()`: Обфускація рядкових літералів у Python-коді стейджера.
    - `apply_advanced_cfo_logic()`: Застосування технік Control Flow Obfuscation (CFO) до коду стейджера.
    - `handle_payload_generation_logic()`: Головна функція, що оркеструє процес генерації: валідація, обфускація даних для стейджера, виклик генерації коду стейджера, застосування метаморфізму (якщо увімкнено), та компіляція за допомогою PyInstaller (якщо обрано).
- `CYBER_DASHBOARD_BACKEND/payload_generator/routes.py`: Визначає HTTP ендпоінти:
    - `POST /api/payload/generate`: Приймає JSON-запит з параметрами пейлоада, повертає згенерований стейджер.
    - `GET /api/payload/archetypes`: Повертає список доступних архетипів пейлоадів з їх описами (з `config.py`).
- `CYBER_DASHBOARD_BACKEND/payload_generator/stager_templates.py`: Містить функцію `generate_stager_code_logic()`, яка генерує Python-код для різних архетипів стейджерів. (Детальніше в `ARCH-stager-templates`)
- `CYBER_DASHBOARD_BACKEND/payload_generator/__init__.py`: Ініціалізаційний файл модуля.

Залежності:
- `config.py`: Для схем параметрів (`CONCEPTUAL_PARAMS_SCHEMA_BE`) та шаблонів архетипів (`CONCEPTUAL_ARCHETYPE_TEMPLATES_BE`).
- `utils.py`: Для функцій XOR-шифрування, Base64 кодування, генерації випадкових імен.

## Поведінка
1.  **Отримання запиту**: Модуль отримує POST-запит на `/api/payload/generate` з JSON-даними, що містять тип архетипу та специфічні параметри.
2.  **Валідація**: Вхідні параметри валідуються згідно зі схемою, визначеною в `config.CONCEPTUAL_PARAMS_SCHEMA_BE`.
3.  **Підготовка даних**: Дані, специфічні для архетипу (наприклад, URL, команди, шеллкод), обробляються (наприклад, патчинг шеллкоду) та обфускуються (XOR + Base64) для передачі в стейджер.
4.  **Генерація коду стейджера**: Викликається `generate_stager_code_logic()` з `stager_templates.py` для створення Python-коду стейджера.
5.  **Метаморфізм (опціонально)**: Якщо увімкнено (`enable_stager_metamorphism`), до згенерованого Python-коду застосовуються `obfuscate_string_literals_in_python_code_logic()` та `apply_advanced_cfo_logic()`. Також перейменовуються ключові функції часу виконання.
6.  **Форматування виводу**: Залежно від параметра `output_format`:
    - `raw_python_stager`: Повертається сирий Python-код.
    - `base64_encoded_stager`: Python-код кодується в Base64.
    - `pyinstaller_exe_windows`: Python-код компілюється у виконуваний файл .EXE для Windows за допомогою PyInstaller (якщо він доступний в системі). Результат (байти .EXE) кодується в Base64.
7.  **Надання архетипів**: GET-запит на `/api/payload/archetypes` повертає список доступних архетипів пейлоадів.

## Еволюція
### Заплановано
- Розширення підтримки нових архетипів пейлоадів.
- Покращення та додавання нових технік обфускації та метаморфізму.
- Підтримка компіляції для інших ОС (наприклад, Linux ELF).
### Історичне
- v1: Реалізація модуля з підтримкою кількох архетипів, обфускації, метаморфізму та компіляції в EXE. 