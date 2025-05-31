CYBER_DASHBOARD_PROJECT_ROOT/
├── CYBER_DASHBOARD_BACKEND/        # Коренева директорія Backend
│   ├── app_core.py                 # Головний файл Flask: ініціалізація, реєстрація Blueprints
│   ├── config.py                   # Конфігурації, константи, схеми, статичні дані (CVE бази)
│   ├── utils.py                    # Загальні допоміжні функції (XOR, Base64, генерація імен)
│   │
│   ├── payload_generator/          # Модуль: Генератор Пейлоадів
│   │   ├── __init__.py
│   │   ├── routes.py               # Flask Blueprint, маршрути (/api/payload/*)
│   │   ├── logic.py                # Логіка валідації, обфускації, генерації EXE
│   │   └── stager_templates.py     # Шаблони та логіка генерації коду стейджерів
│   │
│   ├── reconnaissance/             # Модуль: Розвідка
│   │   ├── __init__.py
│   │   ├── routes.py               # Flask Blueprint, маршрути (/api/recon/*)
│   │   └── logic.py                # Логіка Nmap, OSINT, пошуку CVE (включаючи NVD API)
│   │
│   ├── c2_control/                 # Модуль: C2 Управління
│   │   ├── __init__.py
│   │   ├── routes.py               # Flask Blueprint, маршрути (/api/c2/*)
│   │   └── logic.py                # Логіка обробки маячків, завдань, управління імплантами
│   │
│   ├── operational_data/           # Модуль: Оперативні Дані та Адаптація
│   │   ├── __init__.py
│   │   ├── routes.py               # Flask Blueprint, маршрути (/api/data/*)
│   │   └── logic.py                # Логіка генерації логів, статистики, оновлення правил
│   │
│   └── requirements.txt            # Залежності Python для Backend
│
└── CYBER_DASHBOARD_FRONTEND/       # Коренева директорія Frontend
    ├── index.html                  # Основний HTML-файл (раніше gui.html)
    │
    ├── css/                        # Директорія для CSS
    │   └── style.css               # Кастомні CSS стилі (доповнення до Tailwind)
    │
    ├── js/                         # Директорія для JavaScript
    │   ├── main.js                 # Головний скрипт: ініціалізація, координація UI модулів
    │   ├── api.js                  # Конфігурація API (API_BASE_URL), допоміжні функції для fetch
    │   ├── ui_utils.js             # Загальні UI функції (кнопки, помилки, логування в UI)
    │   ├── tabs_navigation.js      # Логіка перемикання вкладок
    │   ├── payload_generator_ui.js # UI логіка для вкладки "Генератор Пейлоадів"
    │   ├── reconnaissance_ui.js    # UI логіка для вкладки "Розвідка"
    │   ├── c2_control_ui.js        # UI логіка для вкладки "C2 Управління"
    │   └── logging_adaptation_ui.js# UI логіка для вкладки "Логи & Адаптація"
    │
    └── assets/                     # Директорія для статичних ресурсів (зображення, шрифти тощо)
        └── (наразі порожньо)