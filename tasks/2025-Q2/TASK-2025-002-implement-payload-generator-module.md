---
id: TASK-2025-002
title: "Реалізація модуля генератора пейлоадів"
status: done
priority: high
type: feature
assignee: "@AI-DocArchitect"
created: 2025-06-02
updated: 2025-06-02
arch_refs:
  - ARCH-module-payload-generator
  - ARCH-stager-templates
  - ARCH-config
  - ARCH-utils
audit_log:
  - {date: 2025-06-02, user: "@AI-DocArchitect", action: "created with status done"}
---
## Опис
Було реалізовано модуль генератора пейлоадів для backend. Цей модуль дозволяє створювати різноманітні типи стейджерів на основі обраних користувачем архетипів та параметрів. Функціональність включає валідацію вхідних даних, обфускацію параметрів стейджера, генерацію коду на основі шаблонів, застосування технік метаморфізму (обфускація рядків, CFO), патчинг шеллкодів та опціональну компіляцію Python-стейджерів у виконувані файли Windows (.EXE) за допомогою PyInstaller.

## Критерії Приймання
- Модуль доступний через API ендпоінти:
    - `POST /api/payload/generate`: приймає JSON-запит з параметрами, генерує та повертає стейджер.
    - `GET /api/payload/archetypes`: повертає список доступних архетипів пейлоадів.
- Підтримуються архетипи, визначені в `config.CONCEPTUAL_ARCHETYPE_TEMPLATES_BE` (включаючи `demo_echo_payload`, `demo_file_lister_payload`, `demo_c2_beacon_payload`, `reverse_shell_tcp_shellcode_windows_x64`/`linux_x64`, `powershell_downloader_stager`, `dns_beacon_c2_concept`, `windows_simple_persistence_stager`).
- Параметри пейлоадів валідуються згідно зі схемою `config.CONCEPTUAL_PARAMS_SCHEMA_BE`.
- Ключ обфускації використовується для захисту даних, що передаються в стейджер (XOR + Base64).
- Реалізовано патчинг шеллкоду для LHOST/LPORT (`DEADBEEFCAFE`).
- Реалізовано техніки метаморфізму: обфускація рядкових літералів та Control Flow Obfuscation (CFO).
- Можливість вибору формату виводу: сирий Python, Base64, PyInstaller EXE.
- Логіка генерації коду стейджерів винесена в `payload_generator/stager_templates.py`.
- Використовуються допоміжні функції з `utils.py` та конфігурації з `config.py`.
- Процес генерації, включаючи компіляцію PyInstaller, логується.

## Визначення Готовності
- Код модуля реалізовано (`payload_generator/logic.py`, `payload_generator/routes.py`, `payload_generator/stager_templates.py`) та інтегровано в основний додаток.
- Основна функціональність генерації для всіх заявлених архетипів присутня.
- API ендпоінти функціонують.
- Базове логування процесу генерації присутнє.

## Нотатки
- Поточна реалізація PyInstaller залежить від наявності `pyinstaller` в системному PATH та виконується синхронно, що може блокувати запит на тривалий час.
- Метаморфізм та техніки ухилення є концептуальними та можуть потребувати подальшого вдосконалення для реальних сценаріїв. 