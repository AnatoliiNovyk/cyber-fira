# CYBER_DASHBOARD_BACKEND/operational_data/logic.py
# Координатор: Синтаксис
# Опис: Логіка для модуля оперативних даних та адаптації фреймворку.
# Оновлено для використання функцій доступу (getters) з c2_control.logic.

import random
import json # Додано, якщо буде використовуватися для форматування параметрів у логах
from datetime import datetime
import time 

# Імпорти з кореневих файлів проекту
import config # Доступ до VERSION_BACKEND та CONCEPTUAL_PARAMS_SCHEMA_BE

# Замість прямого імпорту змінних, імпортуємо функції доступу
try:
    # Припускаємо, що c2_control.logic знаходиться в батьківській директорії
    # або PYTHONPATH налаштовано відповідним чином для такого імпорту.
    # Якщо c2_control є частиною того ж пакету, імпорт може бути відносним,
    # наприклад, from ..c2_control.logic import ...
    # Для даної структури, де c2_control є сусіднім модулем,
    # і app_core.py реєструє їх, прямий імпорт з пакета має працювати,
    # якщо CYBER_DASHBOARD_BACKEND є в sys.path або є встановленим пакетом.
    from CYBER_DASHBOARD_BACKEND.c2_control.logic import get_simulated_implants_list_c2, get_exfiltrated_files_summary_c2
except ImportError:
    print("[OPS_LOGIC_WARN] Не вдалося імпортувати функції доступу з c2_control.logic. Статистика C2 буде недоступна або обмежена.")
    # Заглушки для функцій, якщо імпорт не вдався
    def get_simulated_implants_list_c2(): 
        print("[OPS_LOGIC_WARN_STUB] Використовується заглушка для get_simulated_implants_list_c2()")
        return []
    def get_exfiltrated_files_summary_c2(): 
        print("[OPS_LOGIC_WARN_STUB] Використовується заглушка для get_exfiltrated_files_summary_c2()")
        return {"active_exfiltrations": 0, "completed_exfiltrations": 0, "files_in_progress": []}


def generate_simulated_operational_logs_logic(log_messages: list) -> list[dict]:
    """
    Генерує список симульованих операційних логів.
    Коментарі українською для кращого розуміння логіки.
    """
    logs = [] # Список для зберігання згенерованих логів
    log_levels = ["INFO", "WARN", "ERROR", "SUCCESS", "DEBUG"] # Можливі рівні логування
    components = ["PayloadGenModule", "ReconModule", "C2ControlModule", "FrameworkCore", "AdaptationEngine", "DataExfilMonitor"] # Компоненти системи
    
    # Шаблони повідомлень для різноманітності логів
    messages_templates = [
        "Операцію '{op}' запущено для цілі '{tgt}'. Параметри: {params}",
        "Сканування порту {port} для {tgt} завершено. Знайдено сервіс: {service}",
        "Виявлено потенційну вразливість: {cve} на {tgt}:{port}. Рівень: {severity}",
        "Пейлоад типу '{ptype}' успішно згенеровано та доставлено на імплант {imp_id}.",
        "Помилка з'єднання з C2 для імпланта {imp_id}. Причина: {reason}",
        "Імплант {imp_id} ({ip}) отримав нове завдання: '{task_type}' ({task_params}). ID: {task_id}",
        "Ексфільтрація даних: '{file}' chunk {c}/{t} з {imp_id}. Статус: {status}",
        "Виявлено підозрілу активність EDR на хості {host_ip}. Застосовано техніку ухилення #{ev_id}.",
        "Правило метаморфізму #{rule_id} оновлено автоматично. Новий пріоритет: {priority}",
        "Імплант {imp_id} перейшов у сплячий режим на {N} хвилин для зменшення помітності.",
        "Невдала спроба підвищення привілеїв на {host_ip} (користувач: {usr}). Метод: {method_privesc}",
        "Успішне виконання команди '{cmd}' на імпланті {imp_id}. Результат: {cmd_res}",
        "NVD API запит для '{query}' повернув {count} результатів.",
        "Застосовано правило адаптації '{adapt_rule}' на основі аналізу ефективності."
    ]
    
    num_logs = random.randint(20, 35) # Кількість логів для генерації
    for _ in range(num_logs):
        # Генерація випадкових даних для заповнення шаблонів
        op_choice = random.choice(["reconnaissance", "payload_deployment", "exfiltration_attempt", "c2_communication", "evasion_maneuver"])
        target_ip = f"{random.randint(10,192)}.{random.randint(0,168)}.{random.randint(1,200)}.{random.randint(1,254)}"
        port_choice = random.choice([21, 22, 80, 443, 3306, 3389, 8080])
        cve_id_choice = f"CVE-202{random.randint(3,5)}-{random.randint(1000,39999)}"
        
        payload_type_choice = "unknown_payload" # Значення за замовчуванням
        # Використання payload_archetype з конфігурації, якщо доступно
        if config.CONCEPTUAL_PARAMS_SCHEMA_BE and \
           "payload_archetype" in config.CONCEPTUAL_PARAMS_SCHEMA_BE and \
           config.CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"].get("allowed_values"):
            payload_type_choice = random.choice(config.CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"]["allowed_values"])
            
        implant_id_choice = f"IMPLNT-{random.randint(100,999)}-{random.choice('ABCDEF')}"
        
        # Створення запису логу
        log_entry = {
            "timestamp": (datetime.now() - datetime.timedelta(seconds=random.randint(0, 7200))).strftime('%Y-%m-%d %H:%M:%S'), # Логи за останні 2 години
            "level": random.choice(log_levels), 
            "component": random.choice(components),
            "message": random.choice(messages_templates).format(
                op=op_choice,
                tgt=target_ip,
                params=json.dumps({"option1": random.choice([True, False]), "timeout": random.randint(10,60)}), # Параметри операції
                port=port_choice,
                service=random.choice(["SSH", "HTTP", "MySQL", "RDP", "FTP"]), # Назва сервісу
                cve=cve_id_choice,
                severity=random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]), # Рівень серйозності CVE
                ptype=payload_type_choice,
                imp_id=implant_id_choice,
                ip=f"10.1.{random.randint(1,10)}.{random.randint(10,50)}", # IP імпланта
                reason=random.choice(["timeout", "connection_refused", "auth_failed", "firewall_block"]), # Причина помилки
                task_type=random.choice(["exec_command", "list_directory", "get_system_info", "exfiltrate_file_chunked"]), # Тип завдання
                task_params=f"param_{random.randint(1,100)}", # Параметри завдання
                task_id=f"TASK-{random.randint(1000,9999)}", # ID завдання
                file=f"secret_data_part_{random.randint(1,10)}.dat.enc", # Ім'я файлу для ексфільтрації
                c=random.randint(1,5), t=random.randint(5,10), # Номер частини та загальна кількість частин
                status=random.choice(["in_progress", "completed", "failed_chunk_read"]), # Статус операції
                host_ip=target_ip, # IP хоста (може бути іншим для EDR)
                ev_id=random.randint(1,20), # ID техніки ухилення
                rule_id=random.randint(100,200), # ID правила
                priority=round(random.uniform(0.1, 0.9), 2), # Пріоритет
                N=random.randint(5,60), # Кількість хвилин
                usr=random.choice(["system","admin","user_limited"]), # Користувач
                method_privesc=random.choice(["kernel_exploit", "service_misconfig", "token_impersonation"]), # Метод підвищення привілеїв
                cmd=random.choice(["whoami /all","ipconfig /all","netstat -an","tasklist /svc"]), # Команда
                cmd_res=random.choice(["SUCCESS", "ERROR_ACCESS_DENIED", "UNKNOWN_COMMAND", "PARTIAL_OUTPUT"]), # Результат команди
                query=f"cpe:/a:apache:http_server:{random.uniform(2.0, 2.4):.2f}", # Запит до NVD
                count=random.randint(0,15), # Кількість результатів
                adapt_rule=f"ADAPT_RULE_ID_{random.randint(1,5)}" # Правило адаптації
            )
        }
        logs.append(log_entry)
    
    # Додавання логів про активні процеси ексфільтрації, використовуючи getter
    exfil_summary = get_exfiltrated_files_summary_c2() # Отримання даних через getter
    for file_in_progress in exfil_summary.get("files_in_progress", []):
        logs.append({
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'), # Або час з file_info, якщо він там є
            "level": "INFO",
            "component": "C2ExfilMonitorLogic", # Компонент, що відповідає за моніторинг ексфільтрації
            "message": f"Exfiltrating '{file_in_progress.get('file_path')}' from {file_in_progress.get('implant_id')}. Progress: {file_in_progress.get('progress_chunks')}. Task ID: {file_in_progress.get('task_id')}."
        })
    
    logs.sort(key=lambda x: x["timestamp"], reverse=True) # Сортування логів за часом (новіші зверху)
    log_messages.append(f"[OPS_LOGIC_LOGS_GENERATED] Згенеровано {len(logs)} симульованих логів.")
    return logs


def get_simulated_stats_logic(log_messages: list) -> dict:
    """
    Генерує симульовану статистику ефективності.
    Коментарі українською для кращого розуміння логіки.
    """
    # Використання getter для отримання списку імплантів
    current_implants = get_simulated_implants_list_c2() # Отримання актуального списку імплантів
    
    # Базова статистика
    success_rate = random.randint(65, 97) # Відсоток успішних операцій
    detection_rate = random.randint(3, 22) # Відсоток виявлення
    
    best_archetype = "N/A" # Найкращий архетип пейлоада за замовчуванням
    # Вибір найкращого архетипу з конфігурації, якщо доступно
    if config.CONCEPTUAL_PARAMS_SCHEMA_BE and \
       "payload_archetype" in config.CONCEPTUAL_PARAMS_SCHEMA_BE and \
       config.CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"].get("allowed_values"):
        best_archetype = random.choice(config.CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"]["allowed_values"])
    
    active_implants_count = len(current_implants) # Кількість активних імплантів

    # Додаткова "просунута" статистика (симуляція)
    avg_dwell_time_hours = round(random.uniform(24, 168), 1) # Середній час перебування в системі (години)
    common_target_os = random.choice(["Windows 10", "Windows Server 2019", "Ubuntu Linux", "CentOS Linux"]) # Поширена цільова ОС
    top_evasion_technique = f"Technique_ID_{random.randint(100,120)}" # Найпопулярніша техніка ухилення

    # Формування словника статистики
    stats = {
        "successRate": success_rate, 
        "detectionRate": detection_rate,
        "bestArchetype": best_archetype,
        "activeImplants": active_implants_count,
        "avgDwellTimeHours": avg_dwell_time_hours,
        "commonTargetOS": common_target_os,
        "topEvasionTechnique": top_evasion_technique,
        "lastUpdated": datetime.now().isoformat() # Час останнього оновлення статистики
    }
    log_messages.append(f"[OPS_LOGIC_STATS_GENERATED] Згенеровано симульовану статистику: {stats}")
    return stats


def get_operational_data_logic(log_messages_main: list) -> tuple[dict, int]:
    """
    Обробляє запит на отримання оперативних даних (логи та статистика).
    Коментарі українською для кращого розуміння логіки.
    """
    log_messages = list(log_messages_main) # Копіювання списку логів для уникнення модифікації оригіналу
    log_messages.append(f"[OPS_LOGIC_GET_DATA] Запит оперативних даних о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")
    try:
        # Генерація симульованих логів та статистики
        sim_logs = generate_simulated_operational_logs_logic(log_messages)
        sim_stats = get_simulated_stats_logic(log_messages)
        
        log_messages.append("[OPS_LOGIC_GET_DATA_SUCCESS] Оперативні дані успішно згенеровано.")
        # Повернення успішної відповіді з даними
        return {
            "success": True, 
            "aggregatedLogs": sim_logs[:50], # Обмеження кількості логів для відповіді
            "statistics": sim_stats,
            "log": "\n".join(log_messages) # Повернення всіх логів обробки запиту
        }, 200
    except Exception as e:
        # Обробка непередбачених помилок
        log_messages.append(f"[OPS_LOGIC_GET_DATA_FATAL_ERROR] {str(e)}")
        return {"success": False, "error": "Server error retrieving operational data", "log": "\n".join(log_messages)}, 500


def update_framework_rules_logic(rules_data: dict, log_messages_main: list) -> tuple[dict, int]:
    """
    Обробляє запит на оновлення правил фреймворку (симуляція).
    Коментарі українською для кращого розуміння логіки.
    """
    log_messages = list(log_messages_main) # Копіювання списку логів
    log_messages.append(f"[OPS_LOGIC_UPDATE_RULES] Запит на оновлення правил о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")

    if not rules_data: # Перевірка наявності даних у запиті
        log_messages.append("[OPS_LOGIC_RULES_ERROR] Не отримано JSON даних для оновлення правил.")
        return {"success": False, "error": "No JSON data for rules update", "log": "\n".join(log_messages)}, 400

    # Отримання параметрів з запиту
    auto_adapt = rules_data.get("auto_adapt_rules", False) # Прапорець автоматичної адаптації
    rule_id_to_update = rules_data.get("rule_id") # ID правила для оновлення
    new_value_for_rule = rules_data.get("new_value") # Нове значення для правила

    log_messages.append(f"[OPS_LOGIC_RULES_INFO] Отримано запит на оновлення. Авто-адаптація: {auto_adapt}, ID правила: '{rule_id_to_update}', Нове значення: '{new_value_for_rule}'.")
    
    # Симуляція логіки оновлення правила
    if rule_id_to_update == "EVASION_TECHNIQUE_XOR_PRIORITY":
        try:
            new_priority = float(new_value_for_rule) # Спроба конвертувати значення в float
            # Тут могла б бути реальна логіка зміни параметра конфігурації фреймворку
            log_messages.append(f"[OPS_LOGIC_RULES_SIM_UPDATE] Пріоритет техніки XOR (симуляція) змінено на {new_priority}.")
        except (ValueError, TypeError):
            log_messages.append(f"[OPS_LOGIC_RULES_SIM_WARN] Не вдалося перетворити '{new_value_for_rule}' на float для пріоритету XOR.")
            # Можна повернути помилку, якщо значення невалідне для цього правила
            # return {"success": False, "error": f"Invalid value for rule {rule_id_to_update}", "log": "\n".join(log_messages)}, 400
    elif rule_id_to_update: # Якщо вказано інше (симульоване) правило
        log_messages.append(f"[OPS_LOGIC_RULES_SIM_UPDATE] Правило '{rule_id_to_update}' (симуляція) оновлено значенням '{new_value_for_rule}'.")
    
    if auto_adapt: # Якщо увімкнено автоматичну адаптацію
        log_messages.append("[OPS_LOGIC_RULES_SIM_AUTO_ADAPT] Режим автоматичної адаптації (симуляція) увімкнено. Фреймворк 'аналізує' дані для майбутніх оптимізацій.")
        # Тут могла б бути логіка запуску процесу автоматичної адаптації на основі зібраних даних

    # Формування повідомлення для користувача
    message_to_user = f"Правила фреймворку (концептуально) оновлено. ID: '{rule_id_to_update}', Нове значення: '{new_value_for_rule}'. Авто-адаптація: {auto_adapt}."
    log_messages.append(f"[OPS_LOGIC_RULES_SUCCESS] {message_to_user}")
    
    # Повернення успішної відповіді
    return {"success": True, "message": message_to_user, "log": "\n".join(log_messages)}, 200
