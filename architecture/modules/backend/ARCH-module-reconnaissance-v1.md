---
id: ARCH-module-reconnaissance
title: "Модуль: Розвідка"
type: module
layer: application
owner: "@AI-DocArchitect"
version: v1
status: current
created: 2025-06-02
updated: 2025-06-02
tags: [backend, reconnaissance, nmap, osint, cve, vulnerability_scanning]
depends_on:
  - ARCH-config
  - ARCH-utils
  - ARCH-nvd-integration
referenced_by: []
---
## Контекст
Модуль розвідки надає функціональність для збору інформації про цільові системи. Він включає симуляцію базових OSINT-операцій, інтеграцію з інструментом Nmap для сканування портів та визначення сервісів/ОС, а також пошук відомостей про вразливості (CVE) для виявлених сервісів.

## Структура
Основні файли модуля:
- `CYBER_DASHBOARD_BACKEND/reconnaissance/logic.py`: Містить всю основну логіку розвідки.
    - **Симуляція OSINT**:
        - `simulate_port_scan_logic()`: Імітує базове сканування поширених портів.
        - `simulate_osint_email_search_logic()`: Імітує пошук email-адрес для домену.
        - `simulate_osint_subdomain_search_logic()`: Імітує пошук субдоменів.
    - **Інтеграція з Nmap**:
        - `perform_nmap_scan_logic()`: Будує та виконує команду `nmap` з заданими опціями, обробляє її вивід (текстовий або XML). Фільтрує та валідує опції Nmap.
        - `parse_nmap_xml_output_logic()`: Парсить XML-вивід Nmap (`-oX`), витягуючи інформацію про хости, відкриті порти, сервіси, версії, ОС та результати NSE-скриптів.
    - **Пошук CVE**:
        - `fetch_cves_from_nvd_api_logic()`: Взаємодіє з NVD API для отримання даних CVE (детальніше в `ARCH-nvd-integration`).
        - `conceptual_cve_lookup_logic()`: Агрегує пошук CVE, використовуючи `fetch_cves_from_nvd_api_logic` та резервні мок-бази з `config.py` (`MOCK_EXTERNAL_CVE_API_DB`, `CONCEPTUAL_CVE_DATABASE_BE`).
    - `handle_run_recon_logic()`: Головна функція-обробник, яка викликає відповідні функції логіки залежно від обраного типу розвідки (`recon_type`).
- `CYBER_DASHBOARD_BACKEND/reconnaissance/routes.py`: Визначає HTTP ендпоінти.
    - `POST /api/recon/run`: Приймає JSON-запит з ціллю, типом розвідки та опціями Nmap, повертає результати.
    - `GET /api/recon/types`: Повертає список доступних типів розвідки.
- `CYBER_DASHBOARD_BACKEND/reconnaissance/__init__.py`: Ініціалізаційний файл модуля.

Залежності:
- `config.py`: Для URL NVD API, ключів API, мок-баз CVE, таймаутів.
- `utils.py`: Для допоміжних функцій, наприклад, `get_service_name_be`.

## Поведінка
1.  **Отримання запиту**: Модуль отримує POST-запит на `/api/recon/run` з параметрами розвідки.
2.  **Вибір типу розвідки**: `handle_run_recon_logic` аналізує параметр `recon_type`.
3.  **Виконання**:
    - Для OSINT-типів викликаються відповідні функції симуляції.
    - Для Nmap-сканувань викликається `perform_nmap_scan_logic`. Якщо потрібен XML-вивід (наприклад, для пошуку CVE), він парситься за допомогою `parse_nmap_xml_output_logic`.
    - Якщо тип розвідки передбачає пошук CVE (`port_scan_nmap_cve_basic`, `port_scan_nmap_vuln_scripts`), то після отримання даних про сервіси з Nmap викликається `conceptual_cve_lookup_logic`.
4.  **Формування звіту**: Результати розвідки (текстовий вивід, структуровані дані про сервіси/ОС, список CVE) форматуються у звіт.
5.  **Надання типів розвідки**: GET-запит на `/api/recon/types` повертає список доступних операцій розвідки.

## Еволюція
### Заплановано
- Додавання підтримки інших інструментів розвідки.
- Покращення парсингу та аналізу результатів Nmap.
- Більш глибока інтеграція результатів різних типів розвідки.
### Історичне
- v1: Реалізація OSINT-симуляцій, інтеграції з Nmap (текстовий та XML вивід), пошуку CVE через NVD API та мок-бази. 