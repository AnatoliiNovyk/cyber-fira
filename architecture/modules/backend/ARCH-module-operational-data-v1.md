---
id: ARCH-module-operational-data
title: "Модуль: Оперативні Дані та Адаптація"
type: module
layer: application
owner: "@AI-DocArchitect"
version: v1
status: current
created: 2025-06-02
updated: 2025-06-02
tags: [backend, logging, statistics, adaptation, simulation]
depends_on:
  - ARCH-config
  - ARCH-module-c2-control  # Для отримання даних про імпланти та ексфільтрацію
referenced_by: []
---
## Контекст
Модуль оперативних даних та адаптації відповідає за симуляцію генерації операційних логів, збір статистики ефективності фреймворку та концептуальне оновлення правил адаптації. Він надає дані для вкладки "Логи & Адаптація" у frontend.

## Структура
Основні файли модуля:
- `CYBER_DASHBOARD_BACKEND/operational_data/logic.py`: Містить логіку для генерації даних.
    - `generate_simulated_operational_logs_logic()`: Генерує список симульованих операційних логів з різними рівнями, компонентами та повідомленнями. Включає інформацію про активні процеси ексфільтрації файлів, отриману з модуля C2.
    - `get_simulated_stats_logic()`: Генерує симульовану статистику ефективності, таку як відсоток успіху, час відповіді, найкращий архетип, кількість активних імплантів (дані з модуля C2).
    - `get_operational_data_logic()`: Агрегує логи та статистику для передачі на frontend.
    - `update_framework_rules_logic()`: Симулює оновлення правил фреймворку на основі отриманих даних (наприклад, увімкнення авто-адаптації, зміна пріоритету правила).
- `CYBER_DASHBOARD_BACKEND/operational_data/routes.py`: Визначає HTTP ендпоінти.
    - `/api/data/operational` (GET): Для отримання агрегованих логів та статистики.
    - `/api/data/framework_rules` (POST): Для симуляції оновлення правил фреймворку.
- `CYBER_DASHBOARD_BACKEND/operational_data/__init__.py`: Ініціалізаційний файл модуля.

Залежності:
- `config.py`: Для доступу до `VERSION_BACKEND` та `CONCEPTUAL_PARAMS_SCHEMA_BE` (для генерації реалістичних даних).
- `c2_control.logic`: Для отримання даних про поточні ексфільтрації файлів (`get_exfiltrated_file_chunks`) та список активних імплантів (`get_simulated_implants`) для статистики.

## Поведінка
1.  **Отримання Оперативних Даних**:
    - Frontend надсилає GET-запит на `/api/data/operational`.
    - `get_operational_data_logic` викликає `generate_simulated_operational_logs_logic` та `get_simulated_stats_logic`.
    - Згенеровані логи та статистика повертаються у JSON-відповіді.
2.  **Оновлення Правил Фреймворку (Симуляція)**:
    - Frontend надсилає POST-запит на `/api/data/framework_rules` з даними про правило, яке потрібно оновити, та новим значенням.
    - `update_framework_rules_logic` обробляє запит, логує дію та повертає повідомлення про успішну (симульовану) зміну.

## Еволюція
### Заплановано
- Інтеграція з реальною системою логування.
- Розробка більш складної логіки адаптації правил на основі аналізу ефективності.
### Історичне
- v1: Реалізація симуляції генерації логів, статистики та оновлення правил для демонстраційних цілей. 