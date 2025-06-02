---
id: ARCH-frontend-main
title: "Frontend: Основна Структура та UI Модулі"
type: component
layer: presentation
owner: "@AI-DocArchitect"
version: v1
status: current
created: 2025-06-02
updated: 2025-06-02
tags: [frontend, ui, main, initialization, tabs]
depends_on:
  - ARCH-frontend-api-client
  - ARCH-frontend-ui-utils
  - ARCH-frontend-tabs-nav
  # Також залежить від конкретних UI-модулів для кожної вкладки:
  # ARCH-frontend-payload-generator-ui (не створено окремо, логіка в payload_generator_ui.js)
  # ARCH-frontend-reconnaissance-ui (не створено окремо, логіка в reconnaissance_ui.js)
  # ARCH-frontend-c2-control-ui (не створено окремо, логіка в c2_control_ui.js)
  # ARCH-frontend-logging-adaptation-ui (не створено окремо, логіка в logging_adaptation_ui.js)
referenced_by: []
---
## Контекст
Frontend частина CYBER DASHBOARD є односторінковим додатком (SPA), побудованим на HTML, CSS (Tailwind CSS + кастомні стилі) та ванільному JavaScript. Файл `main.js` слугує точкою входу для ініціалізації всієї frontend логіки.

## Структура
Основні файли, що формують архітектуру frontend:
- `CYBER_DASHBOARD_FRONTEND/index.html`: Головний HTML-файл, що містить структуру сторінки, контейнери для вкладок та підключає всі CSS та JS файли.
- `CYBER_DASHBOARD_FRONTEND/css/style.css`: Кастомні CSS стилі, що доповнюють Tailwind CSS.
- `CYBER_DASHBOARD_FRONTEND/js/main.js`: Головний скрипт, що викликає функції ініціалізації для всіх компонентів UI.
- `CYBER_DASHBOARD_FRONTEND/js/tabs_navigation.js`: Логіка перемикання вкладок (див. `ARCH-frontend-tabs-nav`).
- `CYBER_DASHBOARD_FRONTEND/js/api.js`: Конфігурація для взаємодії з backend API (див. `ARCH-frontend-api-client`).
- `CYBER_DASHBOARD_FRONTEND/js/ui_utils.js`: Допоміжні UI функції (див. `ARCH-frontend-ui-utils`).
- Специфічні для вкладок UI-файли:
    - `payload_generator_ui.js`: Логіка для вкладки "Генератор Пейлоадів".
    - `reconnaissance_ui.js`: Логіка для вкладки "Розвідка".
    - `c2_control_ui.js`: Логіка для вкладки "C2 Управління".
    - `logging_adaptation_ui.js`: Логіка для вкладки "Логи & Адаптація".

## Поведінка
- Після завантаження DOM, викликається функція `main()` з `main.js`.
- `main()` послідовно ініціалізує:
    1.  Навігацію по вкладках (`initializeTabs()` з `tabs_navigation.js`).
    2.  Обробники подій та логіку для кожної вкладки, викликаючи відповідні функції `initialize...Events()` з файлів `*_ui.js`.
- Для початково активної вкладки (або першої вкладки за замовчуванням) викликаються функції для завантаження початкових даних (наприклад, список архетипів для генератора пейлоадів, список імплантів для C2).

## Еволюція
### Заплановано
- Можливий перехід на один з JavaScript фреймворків (Vue, React, Angular) для кращої структуризації та управління станом при подальшому ускладненні.
- Впровадження системи збірки (наприклад, Webpack, Vite) для оптимізації ресурсів.
### Історичне
- v1: Реалізація на ванільному JavaScript з розділенням логіки по файлах відповідно до функціональних блоків (вкладок). 