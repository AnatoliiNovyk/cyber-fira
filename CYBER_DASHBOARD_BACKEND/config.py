# config.py
# Конфігураційні змінні, константи, схеми та бази даних для CYBER DASHBOARD

import os

# Версія Backend
VERSION_BACKEND = "1.9.8" # Або нова версія після рефакторингу, наприклад, "2.0.0-refactored"

# Конфігурація NVD API
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("a6348814-07e4-4613-9a2b-ce3dcc311c25") # Завантажуватиметься з os.environ.get("NVD_API_KEY") в app_core.py або reconnaissance/logic.py
NVD_REQUEST_TIMEOUT_SECONDS = 15
NVD_RESULTS_PER_PAGE = 20

# Внутрішня (можливо, застаріла або резервна) база CVE
CONCEPTUAL_CVE_DATABASE_BE = {
    "apache httpd 2.4.53": [{"cve_id": "CVE-2022-22721", "severity": "HIGH", "summary": "Apache HTTP Server 2.4.53 and earlier may not send the X-Frame-Options header..."}],
    "openssh 8.2p1": [{"cve_id": "CVE-2021-41617", "severity": "MEDIUM", "summary": "sshd in OpenSSH 6.2 through 8.8 allows remote attackers to bypass..."}],
    "vsftpd 3.0.3": [{"cve_id": "CVE-2015-1419", "severity": "CRITICAL", "summary": "vsftpd 3.0.3 and earlier allows remote attackers to cause a denial of service..."}],
    # Додайте інші за потреби
}

# Імітація зовнішньої бази даних CVE (залишено для резервного механізму)
MOCK_EXTERNAL_CVE_API_DB = {
    "apache httpd 2.4.53": [
        {"cve_id": "CVE-2022-22721", "severity": "HIGH", "summary": "X-Frame-Options header issue in Apache HTTP Server <=2.4.53 (Mock DB).", "source": "Mock External API"},
        {"cve_id": "CVE-2021-44224", "severity": "MEDIUM", "summary": "Possible NULL pointer dereference in Apache HTTP Server 2.4.52 and earlier (Mock DB).", "source": "Mock External API"}
    ],
    "openssh 8.2p1": [
        {"cve_id": "CVE-2021-41617", "severity": "MEDIUM", "summary": "Remote attacker bypass in sshd OpenSSH 6.2-8.8 (Mock DB).", "source": "Mock External API"}
    ],
    "vsftpd 3.0.3": [
        {"cve_id": "CVE-2015-1419", "severity": "CRITICAL", "summary": "Denial of service in vsftpd <=3.0.3 (Mock DB).", "source": "Mock External API"}
    ],
    "proftpd 1.3.5e": [
        {"cve_id": "CVE-2019-12815", "severity": "HIGH", "summary": "Arbitrary file copy in ProFTPD <=1.3.5e (Mock DB).", "source": "Mock External API"}
    ],
    "mysql 5.7.30": [
        {"cve_id": "CVE-2020-14812", "severity": "HIGH", "summary": "Vulnerability in Oracle MySQL Server DDL (Mock DB).", "source": "Mock External API"},
        {"cve_id": "CVE-2023-21912", "severity": "CRITICAL", "summary": "Remote code execution vulnerability in MySQL Shell (Mock DB).", "source": "Mock External API"}
    ],
    "nginx 1.18.0": [
        {"cve_id": "CVE-2021-23017", "severity": "HIGH", "summary": "Resolver security issue in nginx (Mock DB).", "source": "Mock External API"}
    ],
    "microsoft iis 10.0": [
        {"cve_id": "CVE-2021-31166", "severity": "CRITICAL", "summary": "HTTP Protocol Stack Remote Code Execution Vulnerability in Microsoft IIS (Mock DB).", "source": "Mock External API"}
    ]
    # Додайте інші за потреби
}

# Схема параметрів для генератора пейлоадів
CONCEPTUAL_PARAMS_SCHEMA_BE = {
    "payload_archetype": {
        "type": str, "required": True,
        "allowed_values": [
            "demo_echo_payload",
            "demo_file_lister_payload",
            "demo_c2_beacon_payload",
            "reverse_shell_tcp_shellcode_windows_x64",
            "reverse_shell_tcp_shellcode_linux_x64",
            "powershell_downloader_stager",
            "dns_beacon_c2_concept",
            "windows_simple_persistence_stager"
        ]
    },
    "message_to_echo": {"type": str, "required": lambda params: params.get("payload_archetype") == "demo_echo_payload", "min_length": 1},
    "directory_to_list": {"type": str, "required": lambda params: params.get("payload_archetype") == "demo_file_lister_payload", "default": "."},
    "c2_target_host": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") in [
            "reverse_shell_tcp_shellcode_windows_x64",
            "reverse_shell_tcp_shellcode_linux_x64"
        ],
        "validation_regex": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    },
    "c2_target_port": {
        "type": int,
        "required": lambda params: params.get("payload_archetype") in [
            "reverse_shell_tcp_shellcode_windows_x64",
            "reverse_shell_tcp_shellcode_linux_x64"
        ],
        "allowed_range": (1, 65535)
    },
    "c2_beacon_endpoint": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "demo_c2_beacon_payload",
        "default": "http://localhost:5000/api/c2/beacon_receiver", # Цей URL може потребувати оновлення, якщо зміниться структура API
        "validation_regex": r"^(http|https)://[a-zA-Z0-9\-\.]+(:\d+)?(?:/[^/?#]*)?(?:\?[^#]*)?(?:#.*)?$"
    },
    "c2_dns_zone": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "dns_beacon_c2_concept",
        "default": "syntax-c2.net",
        "validation_regex": r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    },
    "dns_beacon_subdomain_prefix": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "dns_beacon_c2_concept",
        "default": "api",
        "validation_regex": r"^[a-zA-Z0-9][a-zA-Z0-9\-]*$"
    },
    "shellcode_hex_placeholder": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") in [
            "reverse_shell_tcp_shellcode_windows_x64",
            "reverse_shell_tcp_shellcode_linux_x64"
        ],
        "default": "DEADBEEFCAFE"
    },
    "powershell_script_url": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "powershell_downloader_stager",
        "validation_regex": r"^(http|https)://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^/?#]*)?(?:\?[^#]*)?(?:#.*)?$"
    },
    "powershell_execution_args": {
        "type": str,
        "required": False,
        "default": "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass"
    },
    "persistence_method": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "windows_simple_persistence_stager",
        "allowed_values": ["scheduled_task", "registry_run_key"],
        "default": "scheduled_task"
    },
    "command_to_persist": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "windows_simple_persistence_stager",
        "min_length": 1,
        "default": "calc.exe"
    },
    "artifact_name": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "windows_simple_persistence_stager",
        "min_length": 3,
        "default": "SyntaxUpdater",
        "validation_regex": r"^[a-zA-Z0-9_.-]+$"
    },
    "obfuscation_key": {"type": str, "required": True, "min_length": 5, "default": "DefaultFrameworkKey"},
    "output_format": {
        "type": str, "required": False,
        "allowed_values": ["raw_python_stager", "base64_encoded_stager", "pyinstaller_exe_windows"],
        "default": "raw_python_stager"
    },
    "pyinstaller_options": {
        "type": str,
        "required": False,
        "default": "--onefile --noconsole"
    },
    "enable_stager_metamorphism": {"type": bool, "required": False, "default": True},
    "enable_evasion_checks": {"type": bool, "required": False, "default": True},
    "enable_amsi_bypass_concept": {"type": bool, "required": False, "default": True},
    "enable_disk_size_check": {"type": bool, "required": False, "default": True}
}

# Шаблони архетипів пейлоадів
CONCEPTUAL_ARCHETYPE_TEMPLATES_BE = {
    "demo_echo_payload": {"description": "Демо-пейлоад, що друкує повідомлення...", "template_type": "python_stager_echo"},
    "demo_file_lister_payload": {"description": "Демо-пейлоад, що 'перелічує' файли...", "template_type": "python_stager_file_lister"},
    "demo_c2_beacon_payload": {"description": "Демо-пейлоад C2-маячка (HTTP POST з виконанням завдань та ексфільтрацією)", "template_type": "python_stager_http_c2_beacon"},
    "reverse_shell_tcp_shellcode_windows_x64": {
        "description": "Windows x64 TCP Reverse Shell (Ін'єкція шеллкоду через Python Stager з патчингом LHOST/LPORT)",
        "template_type": "python_stager_shellcode_injector_win_x64"
    },
    "reverse_shell_tcp_shellcode_linux_x64": {
        "description": "Linux x64 TCP Reverse Shell (Ін'єкція шеллкоду через Python Stager з патчингом LHOST/LPORT)",
        "template_type": "python_stager_shellcode_injector_linux_x64"
    },
    "powershell_downloader_stager": {
        "description": "Windows PowerShell Downloader (Завантажує та виконує PS1 з URL)",
        "template_type": "python_stager_powershell_downloader"
    },
    "dns_beacon_c2_concept": {
        "description": "Концептуальний C2-маячок через DNS (симуляція передачі завдань)",
        "template_type": "python_stager_dns_c2_beacon"
    },
    "windows_simple_persistence_stager": {
        "description": "Windows Stager для простої персистентності (Scheduled Task або Registry Run Key)",
        "template_type": "python_stager_windows_persistence"
    }
}

# Глобальні змінні для симуляції стану C2 (можуть бути переміщені до c2_control/state_manager.py пізніше)
# Наразі залишаємо їх тут для простоти, але в app_core.py їх потрібно буде імпортувати або передавати
# simulated_implants_be = []
# pending_tasks_for_implants = {}
# exfiltrated_file_chunks_db = {}
# Ці змінні будуть ініціалізовані та керовані в c2_control модулі або в app_core.py.

