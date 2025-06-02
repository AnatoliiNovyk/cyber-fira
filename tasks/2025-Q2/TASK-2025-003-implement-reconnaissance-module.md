---
id: TASK-2025-003
title: "Реалізація модуля розвідки"
status: done
priority: high
type: feature
assignee: "@AI-DocArchitect"
created: 2025-06-02
updated: 2025-06-02
arch_refs:
  - ARCH-module-reconnaissance
  - ARCH-nvd-integration
  - ARCH-config
  - ARCH-utils
audit_log:
  - {date: 2025-06-02, user: "@AI-DocArchitect", action: "created with status done"}
---
## Опис
Було реалізовано модуль розвідки для backend. Цей модуль надає функціональність для збору інформації про цілі, включаючи симуляцію OSINT-операцій, виконання Nmap-сканувань та пошук CVE-вразливостей для виявлених сервісів.

## Критерії Приймання
- Модуль доступний через API ендпоінти:
    - `POST /api/recon/run`: приймає JSON-запит з ціллю, типом розвідки та опціями Nmap, виконує розвідку та повертає результати.
    - `GET /api/recon/types`: повертає список доступних типів розвідки.
- Підтримуються наступні типи розвідки:
    - Симуляція: `port_scan_basic`, `osint_email_search`, `osint_subdomain_search_concept`.
    - Nmap: `port_scan_nmap_standard` (текстовий вивід), `port_scan_nmap_cve_basic` (XML-вивід, сервіси, ОС, CVE), `port_scan_nmap_vuln_scripts` (використання скриптів Nmap для пошуку вразливостей).
- Реалізовано взаємодію з Nmap через системні виклики, включаючи обробку текстового та XML-виводу (`-oX -`).
- Реалізовано парсинг XML-виводу Nmap для отримання інформації про хости, порти, сервіси, версії, ОС та результати NSE-скриптів.
- Реалізовано пошук CVE:
    - Через NVD API 2.0 (використовуючи CPE або ключові слова).
    - З використанням резервних мок-баз `MOCK_EXTERNAL_CVE_API_DB` та `CONCEPTUAL_CVE_DATABASE_BE` з `config.py`.
- Логіка винесена у файли `reconnaissance/logic.py` та `reconnaissance/routes.py`.
- Процес розвідки та взаємодії з Nmap/NVD API логується.

## Визначення Готовності
- Код модуля реалізовано та інтегровано в основний додаток.
- Всі заявлені типи розвідки функціонують.
- API ендпоінти працюють коректно.

## Нотатки
- Робота Nmap-сканувань залежить від наявності `nmap` в системному PATH.
- Для повноцінної роботи з NVD API потрібен `NVD_API_KEY`. 