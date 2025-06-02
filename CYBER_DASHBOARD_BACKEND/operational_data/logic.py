# operational_data/logic.py
# Логіка для модуля оперативних даних та адаптації фреймворку

import random
from datetime import datetime
import time # Для генерації міток часу в логах

# Імпорти з кореневих файлів проекту
import config # Доступ до VERSION_BACKEND та CONCEPTUAL_PARAMS_SCHEMA_BE
# Потрібно отримати доступ до exfiltrated_file_chunks_db_c2 з c2_control.logic
# Це створює залежність між модулями. Можливо, краще передавати ці дані,
# або мати централізований стан, якщо це необхідно.
# Наразі, для простоти, припустимо, що ми можемо імпортувати його,
# але це може потребувати перегляду архітектури стану.
try:
    from c2_control.logic import exfiltrated_file_chunks_db_c2, simulated_implants_c2
except ImportError:
    # Заглушка, якщо c2_control.logic ще не повністю доступний або для уникнення циклічних залежностей
    print("[OPS_LOGIC_WARN] Не вдалося імпортувати exfiltrated_file_chunks_db_c2 або simulated_implants_c2 з c2_control.logic. Статистика файлів та імплантів може бути неповною.")
    exfiltrated_file_chunks_db_c2 = {}
    simulated_implants_c2 = []


def generate_simulated_operational_logs_logic(log_messages: list) -> list[dict]:
    """Генерує список симульованих операційних логів."""
    logs = []
    log_levels = ["INFO", "WARN", "ERROR", "SUCCESS", "DEBUG"]
    components = ["PayloadGenModule", "ReconModule", "C2ControlModule", "FrameworkCore", "AdaptationEngine", "DataExfilMonitor"]
    
    # Шаблони повідомлень (можна розширити)
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
    
    num_logs = random.randint(20, 35) # Більше логів для демонстрації
    for _ in range(num_logs):
        # Випадкові дані для заповнення шаблонів
        op_choice = random.choice(["reconnaissance", "payload_deployment", "exfiltration_attempt", "c2_communication", "evasion_maneuver"])
        target_ip = f"{random.randint(10,192)}.{random.randint(0,168)}.{random.randint(1,200)}.{random.randint(1,254)}"
        port_choice = random.choice([21, 22, 80, 443, 3306, 3389, 8080])
        cve_id_choice = f"CVE-202{random.randint(3,5)}-{random.randint(1000,39999)}"
        payload_type_choice = random.choice(config.CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"]["allowed_values"]) if config.CONCEPTUAL_PARAMS_SCHEMA_BE else "unknown_payload"
        implant_id_choice = f"IMPLNT-{random.randint(100,999)}-{random.choice('ABCDEF')}"
        
        log_entry = {
            "timestamp": (datetime.now() - وقت.timedelta(seconds=random.randint(0, 7200))).strftime('%Y-%m-%d %H:%M:%S'), # Логи за останні 2 години
            "level": random.choice(log_levels), 
            "component": random.choice(components),
            "message": random.choice(messages_templates).format(
                op=op_choice,
                tgt=target_ip,
                params=json.dumps({"option1": random.choice([True, False]), "timeout": random.randint(10,60)}),
                port=port_choice,
                service=random.choice(["SSH", "HTTP", "MySQL", "RDP", "FTP"]),
                cve=cve_id_choice,
                severity=random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
                ptype=payload_type_choice,
                imp_id=implant_id_choice,
                ip=f"10.1.{random.randint(1,10)}.{random.randint(10,50)}",
                reason=random.choice(["timeout", "connection_refused", "auth_failed", "firewall_block"]),
                task_type=random.choice(["exec_command", "list_directory", "get_system_info", "exfiltrate_file_chunked"]),
                task_params=f"param_{random.randint(1,100)}",
                task_id=f"TASK-{random.randint(1000,9999)}",
                file=f"secret_data_part_{random.randint(1,10)}.dat.enc", 
                c=random.randint(1,5), t=random.randint(5,10),
                status=random.choice(["in_progress", "completed", "failed_chunk_read"]),
                host_ip=target_ip, # Може бути інший IP, якщо це про EDR
                ev_id=random.randint(1,20),
                rule_id=random.randint(100,200),
                priority=round(random.uniform(0.1, 0.9), 2),
                N=random.randint(5,60),
                usr=random.choice(["system","admin","user_limited"]),
                method_privesc=random.choice(["kernel_exploit", "service_misconfig", "token_impersonation"]),
                cmd=random.choice(["whoami /all","ipconfig /all","netstat -an","tasklist /svc"]),
                cmd_res=random.choice(["SUCCESS", "ERROR_ACCESS_DENIED", "UNKNOWN_COMMAND", "PARTIAL_OUTPUT"]),
                query=f"cpe:/a:apache:http_server:{random.uniform(2.0, 2.4):.2f}",
                count=random.randint(0,15),
                adapt_rule=f"ADAPT_RULE_ID_{random.randint(1,5)}"
            )
        }
        logs.append(log_entry)
    
    # Додамо лог про активні процеси ексфільтрації, якщо є
    if exfiltrated_file_chunks_db_c2: # Використовуємо імпортовану змінну
        for file_key, file_info in list(exfiltrated_file_chunks_db_c2.items()): 
            num_received = len(file_info.get("received_chunks", {}))
            total_chunks_val = file_info.get("total_chunks", "N/A")
            logs.append({
                "timestamp": file_info.get("first_seen", datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                "level": "INFO",
                "component": "C2ExfilMonitorLogic", # Змінено для відображення, що це з логіки
                "message": f"Exfiltrating '{file_info.get('file_path')}' from {file_info.get('implant_id')}. Received {num_received}/{total_chunks_val} chunks. Task ID: {file_info.get('task_id')}."
            })
    
    logs.sort(key=lambda x: x["timestamp"], reverse=True) # Сортуємо за часом, новіші зверху
    log_messages.append(f"[OPS_LOGIC_LOGS_GENERATED] Згенеровано {len(logs)} симульованих логів.")
    return logs


def get_simulated_stats_logic(log_messages: list) -> dict:
    """Генерує симульовану статистику ефективності."""
    global simulated_implants_c2 # Використовуємо імпортовану змінну
    
    # Базова статистика
    success_rate = random.randint(65, 97) # Трохи оптимістичніше
    detection_rate = random.randint(3, 22) # Трохи реалістичніше
    
    # Вибір найкращого архетипу
    best_archetype = "N/A"
    if config.CONCEPTUAL_PARAMS_SCHEMA_BE and "payload_archetype" in config.CONCEPTUAL_PARAMS_SCHEMA_BE and \
       config.CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"].get("allowed_values"):
        best_archetype = random.choice(config.CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"]["allowed_values"])
    
    # Кількість активних імплантів
    active_implants_count = len(simulated_implants_c2) # Рахуємо з імпортованого списку

    # Додаткова "просунута" статистика (симуляція)
    avg_dwell_time_hours = round(random.uniform(24, 168), 1) # Середній час перебування в годинах
    common_target_os = random.choice(["Windows 10", "Windows Server 2019", "Ubuntu Linux", "CentOS Linux"])
    top_evasion_technique = f"Technique_ID_{random.randint(100,120)}"

    stats = {
        "successRate": success_rate, 
        "detectionRate": detection_rate,
        "bestArchetype": best_archetype,
        "activeImplants": active_implants_count,
        "avgDwellTimeHours": avg_dwell_time_hours,
        "commonTargetOS": common_target_os,
        "topEvasionTechnique": top_evasion_technique,
        "lastUpdated": datetime.now().isoformat()
    }
    log_messages.append(f"[OPS_LOGIC_STATS_GENERATED] Згенеровано симульовану статистику: {stats}")
    return stats


def get_operational_data_logic(log_messages_main: list) -> tuple[dict, int]:
    """Обробляє запит на отримання оперативних даних."""
    log_messages = list(log_messages_main)
    log_messages.append(f"[OPS_LOGIC_GET_DATA] Запит оперативних даних о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")
    try:
        sim_logs = generate_simulated_operational_logs_logic(log_messages)
        sim_stats = get_simulated_stats_logic(log_messages)
        
        log_messages.append("[OPS_LOGIC_GET_DATA_SUCCESS] Оперативні дані успішно згенеровано.")
        return {
            "success": True, 
            "aggregatedLogs": sim_logs[:50], # Повертаємо більше логів
            "statistics": sim_stats,
            "log": "\n".join(log_messages)
        }, 200
    except Exception as e:
        log_messages.append(f"[OPS_LOGIC_GET_DATA_FATAL_ERROR] {str(e)}")
        # import traceback
        # log_messages.append(traceback.format_exc())
        return {"success": False, "error": "Server error retrieving operational data", "log": "\n".join(log_messages)}, 500


def update_framework_rules_logic(rules_data: dict, log_messages_main: list) -> tuple[dict, int]:
    """Обробляє запит на оновлення правил фреймворку (симуляція)."""
    log_messages = list(log_messages_main)
    log_messages.append(f"[OPS_LOGIC_UPDATE_RULES] Запит на оновлення правил о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")

    if not rules_data:
        log_messages.append("[OPS_LOGIC_RULES_ERROR] Не отримано JSON даних для оновлення правил.")
        return {"success": False, "error": "No JSON data for rules update", "log": "\n".join(log_messages)}, 400

    auto_adapt = rules_data.get("auto_adapt_rules", False)
    rule_id_to_update = rules_data.get("rule_id")
    new_value_for_rule = rules_data.get("new_value")

    log_messages.append(f"[OPS_LOGIC_RULES_INFO] Отримано запит на оновлення. Авто-адаптація: {auto_adapt}, ID правила: '{rule_id_to_update}', Нове значення: '{new_value_for_rule}'.")
    
    # Симуляція оновлення правила
    if rule_id_to_update == "EVASION_TECHNIQUE_XOR_PRIORITY":
        try:
            new_priority = float(new_value_for_rule)
            # Тут могла б бути логіка зміни реального параметра конфігурації
            log_messages.append(f"[OPS_LOGIC_RULES_SIM_UPDATE] Пріоритет техніки XOR (симуляція) змінено на {new_priority}.")
        except (ValueError, TypeError):
            log_messages.append(f"[OPS_LOGIC_RULES_SIM_WARN] Не вдалося перетворити '{new_value_for_rule}' на float для пріоритету XOR.")
            # Можна повернути помилку, якщо значення невалідне
            # return {"success": False, "error": f"Invalid value for rule {rule_id_to_update}", "log": "\n".join(log_messages)}, 400
    elif rule_id_to_update: # Якщо вказано інше правило
        log_messages.append(f"[OPS_LOGIC_RULES_SIM_UPDATE] Правило '{rule_id_to_update}' (симуляція) оновлено значенням '{new_value_for_rule}'.")
    
    if auto_adapt:
        log_messages.append("[OPS_LOGIC_RULES_SIM_AUTO_ADAPT] Режим автоматичної адаптації (симуляція) увімкнено. Фреймворк 'аналізує' дані для майбутніх оптимізацій.")
        # Тут могла б бути логіка запуску процесу адаптації

    message_to_user = f"Правила фреймворку (концептуально) оновлено. ID: '{rule_id_to_update}', Нове значення: '{new_value_for_rule}'. Авто-адаптація: {auto_adapt}."
    log_messages.append(f"[OPS_LOGIC_RULES_SUCCESS] {message_to_user}")
    
    return {"success": True, "message": message_to_user, "log": "\n".join(log_messages)}, 200
