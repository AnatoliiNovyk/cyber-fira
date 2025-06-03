# File: CYBER_DASHBOARD_BACKEND/c2_control/logic.py
# Координатор: Синтаксис
# Опис: Додано функції доступу (getters) для стану C2.

import base64 # Забезпечено наявність імпорту згідно з попередніми уточненнями
import json
import random
import string
import time
import uuid
from datetime import datetime

# Імпорти з кореневих файлів проекту
import config # Доступ до VERSION_BACKEND

# Глобальні змінні для симуляції стану C2, тепер керовані цим модулем
simulated_implants_c2 = []
pending_tasks_for_implants_c2 = {}
exfiltrated_file_chunks_db_c2 = {}

def initialize_simulated_implants_c2_logic():
    """
    Ініціалізує або оновлює список симульованих імплантів та очищає пов'язані дані.
    """
    global simulated_implants_c2, pending_tasks_for_implants_c2, exfiltrated_file_chunks_db_c2
    simulated_implants_c2.clear()
    pending_tasks_for_implants_c2.clear()
    exfiltrated_file_chunks_db_c2.clear()
    
    os_types = ["Windows_x64_10.0.22631", "Linux_x64_6.5.0", "Windows_Server_2022_Datacenter", "macOS_sonoma_14.1_arm64"]
    base_ip_prefixes = ["10.30.", "192.168.", "172.22."]
    num_implants = random.randint(4, 7)
    
    for i in range(num_implants):
        implant_id = f"SYNIMPLNT-ADV-{random.randint(10000,99999)}-{random.choice(string.ascii_uppercase)}"
        ip_prefix = random.choice(base_ip_prefixes)
        ip_address = f"{ip_prefix}{random.randint(10,250)}.{random.randint(10,250)}"
        os_type = random.choice(os_types)
        last_seen_timestamp = time.time() - random.randint(600, 12000)
        last_seen_str = datetime.fromtimestamp(last_seen_timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        simulated_implants_c2.append({
            "id": implant_id, "ip": ip_address, "os": os_type,
            "lastSeen": last_seen_str,
            "status": random.choice(["pending_beacon", "idle_monitoring", "task_in_progress", "active_beaconing"]),
            "files": [], "beacon_interval_sec": random.randint(30, 120)
        })
    simulated_implants_c2.sort(key=lambda x: x["id"])
    # Логування ініціалізації може бути додане тут або в app_core.py при виклику
    # print(f"[C2_LOGIC_INIT] Ініціалізовано/Оновлено {len(simulated_implants_c2)} імітованих імплантів.")

# Викликаємо ініціалізацію один раз при завантаженні модуля
initialize_simulated_implants_c2_logic()


def handle_c2_beacon_logic(beacon_data: dict, log_messages: list) -> tuple[dict, int]:
    """Обробляє маячки від імплантів."""
    global pending_tasks_for_implants_c2, simulated_implants_c2, exfiltrated_file_chunks_db_c2
    log_messages.append(f"[C2_LOGIC_BEACON] Обробка маячка о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")
    if not beacon_data:
        log_messages.append("[C2_LOGIC_BEACON_ERROR] Не отримано JSON даних маячка.")
        return {"success": False, "error": "No JSON beacon data", "log": "\n".join(log_messages)}, 400
    
    implant_id_from_beacon = beacon_data.get("implant_id")
    hostname_from_beacon = beacon_data.get("hostname", "N/A") 
    remote_addr_beacon = beacon_data.get("remote_addr", "N/A_from_beacon_data") 
    
    log_messages.append(f"[C2_LOGIC_BEACON_RECEIVED] Отримано маячок від ID: {implant_id_from_beacon}, Hostname: {hostname_from_beacon}, Remote IP (reported): {remote_addr_beacon}")

    last_task_id_received = beacon_data.get("last_task_id")
    last_task_result_received = beacon_data.get("last_task_result")
    task_success_received = beacon_data.get("task_success")
    if last_task_id_received:
        log_messages.append(f"   Результат завдання '{last_task_id_received}' (Успіх: {task_success_received}): {str(last_task_result_received)[:200]}{'...' if len(str(last_task_result_received or '')) > 200 else ''}")

    file_exfil_chunk_data = beacon_data.get("file_exfil_chunk")
    if file_exfil_chunk_data and last_task_id_received:
        file_path = file_exfil_chunk_data.get("file_path")
        chunk_num = file_exfil_chunk_data.get("chunk_num")
        total_chunks = file_exfil_chunk_data.get("total_chunks")
        data_b64 = file_exfil_chunk_data.get("data_b64")
        is_final_chunk = file_exfil_chunk_data.get("is_final", False)

        file_key = f"{implant_id_from_beacon}_{last_task_id_received}_{file_path}"
        if file_key not in exfiltrated_file_chunks_db_c2:
            exfiltrated_file_chunks_db_c2[file_key] = {"file_path": file_path, "task_id": last_task_id_received, "total_chunks": total_chunks, "received_chunks": {}, "implant_id": implant_id_from_beacon, "first_seen": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        if data_b64:
             exfiltrated_file_chunks_db_c2[file_key]["received_chunks"][chunk_num] = data_b64
             log_messages.append(f"   [EXFIL_CHUNK_LOGIC] Отримано чанк #{chunk_num}/{total_chunks} для '{file_path}' (ID завдання: {last_task_id_received}).")

        if is_final_chunk or (total_chunks is not None and len(exfiltrated_file_chunks_db_c2[file_key]["received_chunks"]) == total_chunks):
            log_messages.append(f"   [EXFIL_COMPLETE_LOGIC] Всі {total_chunks} чанків для '{file_path}' (ID завдання: {last_task_id_received}) отримано від {implant_id_from_beacon}.")
            # Розглянути можливість не видаляти, а позначати як завершене для статистики
            # if file_key in exfiltrated_file_chunks_db_c2: del exfiltrated_file_chunks_db_c2[file_key] 
            if file_key in exfiltrated_file_chunks_db_c2:
                exfiltrated_file_chunks_db_c2[file_key]['status'] = 'completed'
                exfiltrated_file_chunks_db_c2[file_key]['completed_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')


    elif beacon_data.get("file_exfil_error"):
        log_messages.append(f"   [EXFIL_ERROR_REPORTED_LOGIC] Імплант повідомив про помилку ексфільтрації: {beacon_data['file_exfil_error']}")

    implant_found_in_list = False
    for implant in simulated_implants_c2:
        if implant["id"] == implant_id_from_beacon:
            implant["lastSeen"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            implant["status"] = "active_beaconing"
            implant["ip"] = remote_addr_beacon if remote_addr_beacon != "N/A_from_beacon_data" else implant.get("ip", "N/A_updated")
            implant_found_in_list = True
            log_messages.append(f"[C2_LOGIC_BEACON_UPDATE] Оновлено lastSeen, статус та IP для імпланта {implant_id_from_beacon}.")
            break
    if not implant_found_in_list and implant_id_from_beacon: 
        log_messages.append(f"[C2_LOGIC_BEACON_WARN] Маячок від невідомого ID імпланта: {implant_id_from_beacon}. Додавання до списку.")
        new_implant_data = {
            "id": implant_id_from_beacon, 
            "ip": remote_addr_beacon if remote_addr_beacon != "N/A_from_beacon_data" else "N/A_new_implant", 
            "os": beacon_data.get("os_type", "Unknown from beacon"), 
            "lastSeen": datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
            "status": "active_beaconing_new", "files": [], 
            "beacon_interval_sec": beacon_data.get("beacon_interval_sec", 60)
        }
        simulated_implants_c2.append(new_implant_data)
        simulated_implants_c2.sort(key=lambda x: x["id"])

    next_task_to_assign = None
    if implant_id_from_beacon in pending_tasks_for_implants_c2 and pending_tasks_for_implants_c2[implant_id_from_beacon]:
        next_task_to_assign = pending_tasks_for_implants_c2[implant_id_from_beacon].pop(0)
        if not pending_tasks_for_implants_c2[implant_id_from_beacon]:
            del pending_tasks_for_implants_c2[implant_id_from_beacon]
        log_messages.append(f"[C2_LOGIC_TASK_ISSUED] Видано завдання '{next_task_to_assign.get('task_id')}' ({next_task_to_assign.get('task_type')}) для імпланта {implant_id_from_beacon}.")
    
    c2_response_to_implant = {"status": "OK", "next_task": next_task_to_assign, "message": "Beacon received by Syntax C2."}
    if next_task_to_assign: c2_response_to_implant["message"] += f" Task '{next_task_to_assign.get('task_id')}' issued."
    
    log_messages.append(f"[C2_LOGIC_BEACON_RESPONSE] Відповідь на маячок: {json.dumps(c2_response_to_implant)}")
    return {"success": True, "c2_response": c2_response_to_implant, "log": "\n".join(log_messages)}, 200


def handle_dns_resolver_sim_logic(request_args: dict, log_messages: list) -> tuple[dict, int]:
    """Симулює DNS-резолвер для DNS C2."""
    global pending_tasks_for_implants_c2
    log_messages.append(f"[C2_LOGIC_DNS_SIM] Обробка DNS-симуляції о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")
    query_hostname = request_args.get('q')
    implant_id_from_dns_req = request_args.get('id')
    log_messages.append(f"[C2_LOGIC_DNS_SIM_RECEIVED] Отримано DNS-запит (симуляція): q='{query_hostname}', id='{implant_id_from_dns_req}'.")

    if not query_hostname or not implant_id_from_dns_req:
        log_messages.append("[C2_LOGIC_DNS_SIM_ERROR] Відсутній query або implant ID.")
        return {"success": False, "error": "Missing query or implant ID in DNS sim request", "log": "\n".join(log_messages)}, 400
    
    next_task_dns = None
    if implant_id_from_dns_req in pending_tasks_for_implants_c2 and pending_tasks_for_implants_c2[implant_id_from_dns_req]:
        next_task_dns = pending_tasks_for_implants_c2[implant_id_from_dns_req].pop(0)
        if not pending_tasks_for_implants_c2[implant_id_from_dns_req]:
            del pending_tasks_for_implants_c2[implant_id_from_dns_req]
        log_messages.append(f"[C2_LOGIC_DNS_SIM_TASK_FOUND] Знайдено завдання для {implant_id_from_dns_req}: {next_task_dns.get('task_id')}")
    
    response_payload = {"message": "DNS query processed by Syntax C2 Simulator."}
    if next_task_dns:
        task_json_str = json.dumps(next_task_dns)
        task_b64_str = base64.b64encode(task_json_str.encode('utf-8')).decode('utf-8')
        response_payload["dns_txt_response_payload"] = task_b64_str
        response_payload["task_data"] = next_task_dns # Для зручності логування на сервері
        log_messages.append(f"[C2_LOGIC_DNS_SIM_RESPONSE_WITH_TASK] Відповідь з завданням (B64): {task_b64_str[:50]}...")
    else:
        log_messages.append("[C2_LOGIC_DNS_SIM_RESPONSE_NO_TASK] Відповідь без нового завдання.")

    return {"success": True, **response_payload, "log": "\n".join(log_messages)}, 200


def get_c2_implants_logic(log_messages: list) -> tuple[dict, int]:
    """Повертає список симульованих імплантів."""
    global simulated_implants_c2 # Явно вказуємо, що використовуємо глобальну змінну
    log_messages.append(f"[C2_LOGIC_GET_IMPLANTS] Запит списку імплантів о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")
    current_time = time.time()
    # Створюємо копію для ітерації, якщо плануємо змінювати статус
    # або просто оновлюємо статус в оригінальному списку
    for implant in simulated_implants_c2:
        try:
            last_seen_dt = datetime.strptime(implant["lastSeen"], '%Y-%m-%d %H:%M:%S')
            if current_time - last_seen_dt.timestamp() > (implant.get("beacon_interval_sec", 60) * 5): # 5 інтервалів маячка
                implant["status"] = "offline_timeout"
        except ValueError:
             implant["status"] = "offline_unknown_lastseen" # Якщо формат дати невірний

    log_messages.append(f"[C2_LOGIC_GET_IMPLANTS_INFO] Повернення {len(simulated_implants_c2)} імітованих імплантів.")
    return {"success": True, "implants": simulated_implants_c2, "log": "\n".join(log_messages)}, 200


def handle_c2_task_logic(task_data: dict, log_messages: list) -> tuple[dict, int]:
    """Обробляє запит на постановку завдання імпланту."""
    global pending_tasks_for_implants_c2, simulated_implants_c2
    log_messages.append(f"[C2_LOGIC_TASK_HANDLER] Обробка завдання о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")
    if not task_data:
        log_messages.append("[C2_LOGIC_TASK_ERROR] Не отримано JSON даних завдання.")
        return {"success": False, "error": "No JSON task data", "log": "\n".join(log_messages)}, 400

    implant_id = task_data.get("implant_id")
    task_type = task_data.get("task_type")
    task_params = task_data.get("task_params", "")
    queue_task_flag = task_data.get("queue_task", True)

    log_messages.append(f"[C2_LOGIC_TASK_RECEIVED] Отримано завдання для ID: {implant_id}, Тип: {task_type}, Параметри: {str(task_params)[:100]}..., Черга: {queue_task_flag}")

    if not implant_id or not task_type:
        log_messages.append("[C2_LOGIC_TASK_ERROR] Відсутній ID імпланта або тип завдання.")
        return {"success": False, "error": "Missing implant_id or task_type", "log": "\n".join(log_messages)}, 400

    # Перевірка, чи існує імплант (опціонально, але добре для цілісності)
    if not any(imp['id'] == implant_id for imp in simulated_implants_c2):
        log_messages.append(f"[C2_LOGIC_TASK_WARN] Спроба поставити завдання для невідомого імпланта ID: {implant_id}.")
        # Можна повернути помилку, або додати до черги, якщо імплант може з'явитися
        # return {"success": False, "error": f"Implant ID {implant_id} not found.", "log": "\n".join(log_messages)}, 404


    new_task_id = f"TASK-{uuid.uuid4().hex[:8].upper()}"
    task_to_queue = {
        "task_id": new_task_id,
        "task_type": task_type,
        "task_params": task_params,
        "timestamp_created": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    if implant_id not in pending_tasks_for_implants_c2:
        pending_tasks_for_implants_c2[implant_id] = []
    
    pending_tasks_for_implants_c2[implant_id].append(task_to_queue)
    log_messages.append(f"[C2_LOGIC_TASK_QUEUED] Завдання {new_task_id} ({task_type}) додано до черги для імпланта {implant_id}.")
    
    # Оновлення статусу імпланта (якщо він відомий)
    for implant_entry in simulated_implants_c2:
        if implant_entry["id"] == implant_id:
            implant_entry["status"] = "task_pending" # Або інший відповідний статус
            break
    
    return {
        "success": True, 
        "message": f"Task {new_task_id} ({task_type}) queued for implant {implant_id}.",
        "queued_task": task_to_queue,
        "log": "\n".join(log_messages)
    }, 200

# --- Нові функції доступу (Getters) ---
def get_simulated_implants_list_c2() -> list:
    """
    Повертає копію списку симульованих імплантів.
    Це запобігає прямому доступу та модифікації оригінального списку ззовні.
    """
    global simulated_implants_c2
    return list(simulated_implants_c2) # Повертаємо копію

def get_exfiltrated_files_summary_c2() -> dict:
    """
    Повертає зведену інформацію про файли, що ексфільтруються.
    """
    global exfiltrated_file_chunks_db_c2
    summary = {
        "active_exfiltrations": 0,
        "completed_exfiltrations": 0,
        "files_in_progress": [] # Список файлів, що зараз ексфільтруються
    }
    for file_key, file_info in exfiltrated_file_chunks_db_c2.items():
        if file_info.get('status') == 'completed':
            summary["completed_exfiltrations"] += 1
        else: # Вважаємо активним, якщо не позначено як завершене
            summary["active_exfiltrations"] += 1
            summary["files_in_progress"].append({
                "file_path": file_info.get("file_path"),
                "implant_id": file_info.get("implant_id"),
                "task_id": file_info.get("task_id"),
                "progress_chunks": f"{len(file_info.get('received_chunks', {}))}/{file_info.get('total_chunks', 'N/A')}"
            })
    return summary

# --- Кінець нових функцій доступу ---

# Інші функції логіки C2...
```python
# File: CYBER_DASHBOARD_BACKEND/operational_data/logic.py
# Координатор: Синтаксис
# Опис: Оновлено для використання функцій доступу (getters) з c2_control.logic.

import random
import json # Додано, якщо буде використовуватися для форматування параметрів у логах
from datetime import datetime
import time 

# Імпорти з кореневих файлів проекту
import config 

# Замість прямого імпорту змінних, імпортуємо функції доступу
try:
    from c2_control.logic import get_simulated_implants_list_c2, get_exfiltrated_files_summary_c2
except ImportError:
    print("[OPS_LOGIC_WARN] Не вдалося імпортувати функції доступу з c2_control.logic. Статистика C2 буде недоступна або обмежена.")
    # Заглушки для функцій, якщо імпорт не вдався
    def get_simulated_implants_list_c2(): return []
    def get_exfiltrated_files_summary_c2(): return {"active_exfiltrations": 0, "completed_exfiltrations": 0, "files_in_progress": []}


def generate_simulated_operational_logs_logic(log_messages: list) -> list[dict]:
    """Генерує список симульованих операційних логів."""
    logs = []
    log_levels = ["INFO", "WARN", "ERROR", "SUCCESS", "DEBUG"]
    components = ["PayloadGenModule", "ReconModule", "C2ControlModule", "FrameworkCore", "AdaptationEngine", "DataExfilMonitor"]
    
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
    
    num_logs = random.randint(20, 35)
    for _ in range(num_logs):
        op_choice = random.choice(["reconnaissance", "payload_deployment", "exfiltration_attempt", "c2_communication", "evasion_maneuver"])
        target_ip = f"{random.randint(10,192)}.{random.randint(0,168)}.{random.randint(1,200)}.{random.randint(1,254)}"
        port_choice = random.choice([21, 22, 80, 443, 3306, 3389, 8080])
        cve_id_choice = f"CVE-202{random.randint(3,5)}-{random.randint(1000,39999)}"
        
        # Використовуємо payload_archetype з конфігурації, якщо доступно
        payload_type_choice = "unknown_payload"
        if config.CONCEPTUAL_PARAMS_SCHEMA_BE and "payload_archetype" in config.CONCEPTUAL_PARAMS_SCHEMA_BE and \
           config.CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"].get("allowed_values"):
            payload_type_choice = random.choice(config.CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"]["allowed_values"])
            
        implant_id_choice = f"IMPLNT-{random.randint(100,999)}-{random.choice('ABCDEF')}"
        
        log_entry = {
            "timestamp": (datetime.now() - datetime.timedelta(seconds=random.randint(0, 7200))).strftime('%Y-%m-%d %H:%M:%S'),
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
                host_ip=target_ip,
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
    
    # Додамо лог про активні процеси ексфільтрації, використовуючи getter
    exfil_summary = get_exfiltrated_files_summary_c2()
    for file_in_progress in exfil_summary.get("files_in_progress", []):
        logs.append({
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'), # Або час з file_info, якщо є
            "level": "INFO",
            "component": "C2ExfilMonitorLogic",
            "message": f"Exfiltrating '{file_in_progress.get('file_path')}' from {file_in_progress.get('implant_id')}. Progress: {file_in_progress.get('progress_chunks')}. Task ID: {file_in_progress.get('task_id')}."
        })
    
    logs.sort(key=lambda x: x["timestamp"], reverse=True)
    log_messages.append(f"[OPS_LOGIC_LOGS_GENERATED] Згенеровано {len(logs)} симульованих логів.")
    return logs


def get_simulated_stats_logic(log_messages: list) -> dict:
    """Генерує симульовану статистику ефективності."""
    # Використовуємо getter для отримання списку імплантів
    current_implants = get_simulated_implants_list_c2()
    
    success_rate = random.randint(65, 97)
    detection_rate = random.randint(3, 22)
    
    best_archetype = "N/A"
    if config.CONCEPTUAL_PARAMS_SCHEMA_BE and "payload_archetype" in config.CONCEPTUAL_PARAMS_SCHEMA_BE and \
       config.CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"].get("allowed_values"):
        best_archetype = random.choice(config.CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"]["allowed_values"])
    
    active_implants_count = len(current_implants) 

    avg_dwell_time_hours = round(random.uniform(24, 168), 1)
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
            "aggregatedLogs": sim_logs[:50], 
            "statistics": sim_stats,
            "log": "\n".join(log_messages)
        }, 200
    except Exception as e:
        log_messages.append(f"[OPS_LOGIC_GET_DATA_FATAL_ERROR] {str(e)}")
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
    
    if rule_id_to_update == "EVASION_TECHNIQUE_XOR_PRIORITY":
        try:
            new_priority = float(new_value_for_rule)
            log_messages.append(f"[OPS_LOGIC_RULES_SIM_UPDATE] Пріоритет техніки XOR (симуляція) змінено на {new_priority}.")
        except (ValueError, TypeError):
            log_messages.append(f"[OPS_LOGIC_RULES_SIM_WARN] Не вдалося перетворити '{new_value_for_rule}' на float для пріоритету XOR.")
    elif rule_id_to_update: 
        log_messages.append(f"[OPS_LOGIC_RULES_SIM_UPDATE] Правило '{rule_id_to_update}' (симуляція) оновлено значенням '{new_value_for_rule}'.")
    
    if auto_adapt:
        log_messages.append("[OPS_LOGIC_RULES_SIM_AUTO_ADAPT] Режим автоматичної адаптації (симуляція) увімкнено. Фреймворк 'аналізує' дані для майбутніх оптимізацій.")

    message_to_user = f"Правила фреймворку (концептуально) оновлено. ID: '{rule_id_to_update}', Нове значення: '{new_value_for_rule}'. Авто-адаптація: {auto_adapt}."
    log_messages.append(f"[OPS_LOGIC_RULES_SUCCESS] {message_to_user}")
    
    return {"success": True, "message": message_to_user, "log": "\n".join(log_messages)}, 200
