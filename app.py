# Syntax Flask Backend - Segment SFB-CORE-1.3.0
# Призначення: Фінальний концептуальний backend на Flask, що охоплює генерацію пейлоадів,
#             розвідку, C2-взаємодію та логування/адаптацію.

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import base64
import re
import random
import string
import time
from datetime import datetime

VERSION_BACKEND = "1.3.0" # Оновлена версія backend

# --- Дані для Імітації C2 (з версії 1.2.0) ---
simulated_implants_be = []
implant_task_results_be = {} 

def initialize_simulated_implants_be():
    """Ініціалізує або оновлює список імітованих імплантів."""
    global simulated_implants_be
    simulated_implants_be = []
    os_types = ["Windows_x64_10.0.19045", "Linux_x64_5.15.0", "Windows_x86_7_SP1", "macOS_arm64_13.2"]
    base_ip_prefixes = ["10.0.", "192.168.", "172.16."]
    num_implants = random.randint(3, 6)
    for i in range(num_implants):
        implant_id = f"SYNIMPLNT-{random.randint(1000,9999)}-{random.choice(string.ascii_uppercase)}{random.choice(string.ascii_uppercase)}"
        ip_prefix = random.choice(base_ip_prefixes)
        ip_address = f"{ip_prefix}{random.randint(1,254)}.{random.randint(2,253)}"
        os_type = random.choice(os_types)
        last_seen_timestamp = time.time() - random.randint(0, 7200) 
        last_seen_str = datetime.fromtimestamp(last_seen_timestamp).strftime('%Y-%m-%d %H:%M:%S')
        simulated_implants_be.append({
            "id": implant_id, "ip": ip_address, "os": os_type,
            "lastSeen": last_seen_str, "status": random.choice(["active", "idle", "tasking_pending"]),
            "files": []
        })
    simulated_implants_be.sort(key=lambda x: x["id"])
    print(f"[C2_SIM_INFO] Ініціалізовано/Оновлено {len(simulated_implants_be)} імітованих імплантів.")

# --- Логіка для Генератора Пейлоадів (з версії 1.2.0, без змін) ---
CONCEPTUAL_PARAMS_SCHEMA_BE = {
    "payload_archetype": {"type": str, "required": True, "allowed_values": ["demo_echo_payload", "demo_file_lister_payload", "demo_c2_beacon_payload"]},
    "message_to_echo": {"type": str, "required": lambda params: params.get("payload_archetype") == "demo_echo_payload", "min_length": 1},
    "directory_to_list": {"type": str, "required": lambda params: params.get("payload_archetype") == "demo_file_lister_payload", "default": "."},
    "c2_target_host": {"type": str, "required": lambda params: params.get("payload_archetype") == "demo_c2_beacon_payload", "validation_regex": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"},
    "c2_target_port": {"type": int, "required": lambda params: params.get("payload_archetype") == "demo_c2_beacon_payload", "allowed_range": (1, 65535)},
    "obfuscation_key": {"type": str, "required": True, "min_length": 5, "default": "DefaultFrameworkKey"},
    "output_format": {"type": str, "required": False, "allowed_values": ["raw_python_stager", "base64_encoded_stager"], "default": "raw_python_stager"},
    "enable_stager_metamorphism": {"type": bool, "required": False, "default": True},
    "enable_evasion_checks": {"type": bool, "required": False, "default": True}
}
CONCEPTUAL_ARCHETYPE_TEMPLATES_BE = {
    "demo_echo_payload": {"description": "Демо-пейлоад, що друкує повідомлення...", "template_type": "python_stager_echo"},
    "demo_file_lister_payload": {"description": "Демо-пейлоад, що 'перелічує' файли...", "template_type": "python_stager_file_lister"},
    "demo_c2_beacon_payload": {"description": "Демо-пейлоад C2-маячка...", "template_type": "python_stager_c2_beacon"}
}
def conceptual_validate_parameters_be(input_params: dict, schema: dict) -> tuple[bool, dict, list[str]]:
    validated_params = {}
    errors = []
    for param_name, rules in schema.items():
        if param_name in input_params:
            value_to_validate = input_params[param_name]
            if rules.get("type") == int and not isinstance(value_to_validate, int):
                try: value_to_validate = int(value_to_validate)
                except (ValueError, TypeError): pass 
            elif rules.get("type") == bool and not isinstance(value_to_validate, bool):
                 if isinstance(value_to_validate, str):
                    if value_to_validate.lower() == 'true': value_to_validate = True
                    elif value_to_validate.lower() == 'false': value_to_validate = False
            validated_params[param_name] = value_to_validate
        elif "default" in rules:
            is_cond_req_missing = False
            if callable(rules.get("required")):
                if rules["required"](input_params) and param_name not in input_params: 
                    is_cond_req_missing = True
            if not is_cond_req_missing: validated_params[param_name] = rules["default"]
    for param_name, rules in schema.items():
        is_required_directly = rules.get("required") is True
        is_conditionally_required = callable(rules.get("required")) and rules["required"](validated_params)
        if (is_required_directly or is_conditionally_required) and param_name not in validated_params:
            errors.append(f"Відсутній обов'язковий параметр: '{param_name}'.")
            continue
        if param_name in validated_params:
            value = validated_params[param_name]
            if "type" in rules and not isinstance(value, rules["type"]):
                errors.append(f"Параметр '{param_name}' має невірний тип. Очікується {rules['type'].__name__}, отримано {type(value).__name__}.")
                continue 
            if "allowed_values" in rules and value not in rules["allowed_values"]:
                errors.append(f"Значення '{value}' для параметра '{param_name}' не є дозволеним. Дозволені: {rules['allowed_values']}.")
            if "min_length" in rules and isinstance(value, str) and len(value) < rules["min_length"]:
                 errors.append(f"Параметр '{param_name}' закороткий. Мін. довжина: {rules['min_length']}.")
            if "allowed_range" in rules and rules.get("type") in [int, float]:
                min_val, max_val = rules["allowed_range"]
                if not (min_val <= value <= max_val):
                    errors.append(f"Значення '{value}' для параметра '{param_name}' виходить за межі ({min_val}-{max_val}).")
            if "validation_regex" in rules and rules.get("type") is str:
                if not re.match(rules["validation_regex"], value):
                    errors.append(f"Значення '{value}' для параметра '{param_name}' не відповідає формату.")
    return not errors, validated_params, errors
def conceptual_xor_string_be(input_string: str, key: str) -> str:
    if not key: key = "DefaultFallbackKeyForXOR" 
    output_chars = []
    for i in range(len(input_string)):
        key_char = key[i % len(key)]
        xor_char_code = ord(input_string[i]) ^ ord(key_char)
        output_chars.append(chr(xor_char_code))
    return "".join(output_chars)
def generate_random_name_be(length=8, prefix="var_"):
    return prefix + ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(length))
def apply_cfo_be(code_lines: list) -> str:
    cfo_applied_code_list = []
    cfo_patterns = [
        lambda indent, r1, r2: f"{indent}if {r1} < {r1 + random.randint(1,5)}: # CFO: True\n{indent}    pass # CFO Block 1\n{indent}else:\n{indent}    pass # Dead Code",
        lambda indent, r1, r2: f"{indent}if ({r1} * {r2}) == ({r1 * r2 -1}): # CFO: False\n{indent}    pass # Dead Code\n{indent}else:\n{indent}    pass # CFO Block 2",
        lambda indent, r1, r2: f"{indent}for _ in range({random.randint(0,1)}):\n{indent}    pass # Junk Loop",
        lambda indent, r1, r2: f"{indent}{generate_random_name_be(length=4)} = {r1} // {r2 if r2 != 0 else 1}\n{indent}if {generate_random_name_be(length=4)} != {r1 + r2}: # CFO True (likely)\n{indent}    pass # CFO Block 3"
    ]
    for line_idx, line in enumerate(code_lines):
        cfo_applied_code_list.append(line)
        if random.random() < 0.15 and line.strip() and not line.strip().startswith("#") and "def " not in line and "class " not in line:
            indent = line[:len(line) - len(line.lstrip())]
            r1, r2 = random.randint(1,100), random.randint(1,100)
            selected_pattern = random.choice(cfo_patterns)
            cfo_applied_code_list.append(selected_pattern(indent, r1, r2))
            cfo_applied_code_list.append(f"{indent}# CFO_COMMENT_{generate_random_name_be(5,'')}")
    return "\n".join(cfo_applied_code_list)
# --- Кінець логіки для Генератора Пейлоадів ---

# --- Логіка для Модуля Розвідки (з версії 1.2.0, без змін) ---
def get_service_name_be(port: int) -> str:
    services = { 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 443: "HTTPS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt" }
    return services.get(port, "Unknown")
def simulate_port_scan_be(target: str) -> tuple[list[str], str]:
    log = [f"[RECON_BE_INFO] Імітація сканування портів для цілі: {target}"]
    results_text_lines = [f"Результати сканування портів для: {target}"]
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 8000, 8080, 8443]
    open_ports_found = []
    for port in common_ports:
        time.sleep(random.uniform(0.01, 0.05)) 
        if random.random() < 0.3: 
            service_name = get_service_name_be(port)
            banner = ""
            if random.random() < 0.6: 
                banner_version = f"v{random.randint(1,5)}.{random.randint(0,9)}"
                possible_banners = [f"OpenSSH_{banner_version}", f"Apache httpd {banner_version}", f"Microsoft-IIS/{banner_version}", "nginx", f"ProFTPD {banner_version}", f"vsftpd {banner_version}", f"MySQL {banner_version}", f"PostgreSQL {banner_version}"]
                banner = f" (Banner: {random.choice(possible_banners)})"
            open_ports_found.append(f"  Порт {port} ({service_name}): ВІДКРИТО{banner}")
    if open_ports_found: results_text_lines.extend(open_ports_found)
    else: results_text_lines.append("  Відкритих поширених портів не знайдено (імітація).")
    log.append("[RECON_BE_SUCCESS] Імітацію сканування портів завершено.")
    return log, "\n".join(results_text_lines)
def simulate_osint_email_search_be(target_domain: str) -> tuple[list[str], str]:
    log = [f"[RECON_BE_INFO] Імітація OSINT пошуку email для домену: {target_domain}"]
    results_text_lines = [f"Результати OSINT пошуку Email для домену: {target_domain}"]
    domain_parts = target_domain.split('.')
    main_domain = ".".join(domain_parts[-2:]) if len(domain_parts) > 2 else target_domain
    common_names = ["info", "support", "admin", "contact", "sales", "hr", "abuse", "webmaster"]
    first_names = ["john.doe", "jane.smith", "peter.jones", "susan.lee", "michael.brown"]
    found_emails = []
    for _ in range(random.randint(1, 5)): 
        email = f"{random.choice(common_names)}@{main_domain}" if random.random() < 0.7 else f"{random.choice(first_names)}@{main_domain}"
        if email not in found_emails: found_emails.append(email)
    if found_emails: results_text_lines.extend([f"  Знайдено Email: {email}" for email in found_emails])
    else: results_text_lines.append("  Email-адрес не знайдено (імітація).")
    log.append("[RECON_BE_SUCCESS] Імітацію OSINT пошуку email завершено.")
    return log, "\n".join(results_text_lines)
# --- Кінець логіки для Модуля Розвідки ---

# --- Початок: Логіка для Логування та Адаптації ---
def generate_simulated_operational_logs_be() -> list[dict]:
    """Генерує список імітованих операційних логів."""
    logs = []
    log_levels = ["INFO", "WARN", "ERROR", "SUCCESS"]
    components = ["PayloadGen_BE", "Recon_BE", "C2_Implant_Alpha_BE", "C2_Implant_Beta_BE", "FrameworkCore_BE", "AdaptationEngine_BE"]
    messages_templates = [
        "Операцію '{op}' запущено для цілі '{tgt}'.", 
        "Сканування порту {port} для {tgt} завершено.", 
        "Виявлено потенційну вразливість: {cve} на {tgt}.",
        "Пейлоад типу '{ptype}' успішно доставлено на {imp_id}.", 
        "Помилка з'єднання з C2 для імпланта {imp_id}.", 
        "Імплант {imp_id} отримав нове завдання: '{task}'.",
        "Ексфільтрація даних: '{file}' chunk {c}/{t} з {imp_id}.", 
        "Виявлено підозрілу активність EDR на хості {host_ip}.",
        "Правило метаморфізму #{rule_id} оновлено автоматично через низьку ефективність.", 
        "Імплант {imp_id} перейшов у сплячий режим на {N} хвилин.",
        "Невдала спроба підвищення привілеїв на {host_ip} (користувач: {usr}).", 
        "Успішне виконання '{cmd}' на імпланті {imp_id}."
    ]
    for _ in range(random.randint(15, 25)): # Генеруємо 15-25 записів
        log_entry = {
            "timestamp": datetime.fromtimestamp(time.time() - random.randint(0, 3600 * 2)).strftime('%Y-%m-%d %H:%M:%S'), # Останні 2 години
            "level": random.choice(log_levels),
            "component": random.choice(components),
            "message": random.choice(messages_templates).format(
                op=random.choice(["recon", "deploy", "exfil"]),
                tgt=f"{random.randint(10,192)}.{random.randint(0,168)}.{random.randint(1,200)}.{random.randint(1,254)}",
                port=random.choice([80, 443, 22, 3389]),
                cve=f"CVE-202{random.randint(3,5)}-{random.randint(1000,29999)}",
                ptype=random.choice(CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"]["allowed_values"]),
                imp_id=f"IMPLNT-{random.randint(100,999)}",
                task=random.choice(["listdir /tmp", "getsysinfo", "upload report.docx"]),
                file=f"secret_{random.randint(1,10)}.dat",
                c=random.randint(1,5), t=5,
                host_ip=f"10.1.1.{random.randint(10,50)}",
                rule_id=random.randint(100,200),
                N=random.randint(5,60),
                usr=random.choice(["system", "admin", "user"]),
                cmd=random.choice(["whoami", "ipconfig", "ps aux"])
            )
        }
        logs.append(log_entry)
    logs.sort(key=lambda x: x["timestamp"])
    return logs

def get_simulated_stats_be() -> dict:
    """Генерує імітовану статистику ефективності."""
    global simulated_implants_be # Використовуємо глобальний список для кількості
    return {
        "successRate": random.randint(60, 95), # Успішних проникнень у %
        "detectionRate": random.randint(5, 25), # Частота виявлення у %
        "bestArchetype": random.choice(CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"]["allowed_values"]),
        "activeImplants": len(simulated_implants_be) # Кількість з C2 модуля
    }
# --- Кінець логіки для Логування та Адаптації ---


app = Flask(__name__)
CORS(app) 
initialize_simulated_implants_be()

@app.route('/api/generate_payload', methods=['POST'])
def handle_generate_payload():
    log_messages = [f"[BACKEND v{VERSION_BACKEND}] Запит /api/generate_payload о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        data = request.get_json()
        if not data:
            log_messages.append("[BACKEND_ERROR] Не отримано JSON.")
            return jsonify({"success": False, "error": "No JSON", "generationLog": "\n".join(log_messages)}), 400
        log_messages.append(f"[BACKEND_INFO] Параметри: {json.dumps(data, indent=2, ensure_ascii=False)}")
        is_valid, validated_params, errors = conceptual_validate_parameters_be(data, CONCEPTUAL_PARAMS_SCHEMA_BE)
        if not is_valid:
            log_messages.append(f"[BACKEND_VALIDATION_FAILURE] Помилки: {errors}")
            return jsonify({"success": False, "error": "Validation failed", "errors": errors, "generationLog": "\n".join(log_messages)}), 400
        log_messages.append("[BACKEND_VALIDATION_SUCCESS] Валідація успішна.")
        archetype_name = validated_params.get("payload_archetype")
        archetype_details = CONCEPTUAL_ARCHETYPE_TEMPLATES_BE.get(archetype_name)
        log_messages.append(f"[BACKEND_ARCHETYPE_INFO] Архетип: {archetype_name} - {archetype_details['description']}")
        data_to_obfuscate = ""
        if archetype_name == "demo_echo_payload": data_to_obfuscate = validated_params.get("message_to_echo", "Default")
        elif archetype_name == "demo_file_lister_payload": data_to_obfuscate = validated_params.get("directory_to_list", ".")
        elif archetype_name == "demo_c2_beacon_payload": data_to_obfuscate = f"{validated_params.get('c2_target_host', 'localhost')}:{validated_params.get('c2_target_port', 8080)}"
        key = validated_params.get("obfuscation_key", "DefaultKey")
        log_messages.append(f"[BACKEND_OBF_INFO] Обфускація: '{data_to_obfuscate[:20]}...' з ключем '{key}'.")
        obfuscated_data_raw = conceptual_xor_string_be(data_to_obfuscate, key)
        obfuscated_data_b64 = base64.b64encode(obfuscated_data_raw.encode('latin-1')).decode('utf-8')
        log_messages.append(f"[BACKEND_OBF_SUCCESS] Обфусковано: {obfuscated_data_b64[:30]}...")
        log_messages.append(f"[BACKEND_STAGER_GEN_INFO] Генерація стейджера...")
        stager_code_lines = [
            f"# SYNTAX Stager (BE Gen v{VERSION_BACKEND}) @ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Archetype: {archetype_name}",
            f"OBF_DATA = \"{obfuscated_data_b64}\"", f"OBF_KEY = \"{key}\"",
            f"META_ON = {validated_params.get('enable_stager_metamorphism', False)}",
            f"EVADE_ON = {validated_params.get('enable_evasion_checks', False)}",
            "import base64, random, os, time",
            "def dx(d,k): o=[];[o.append(chr(ord(d[i])^ord(k[i%len(k)]))) for i in range(len(d))];return \"\".join(o)",
            "def ec(): print(\"[EVADE_SIM] Env check...\"); return random.random()<0.1",
            "def ex(c,a): print(f\"[PAYLOAD ({{a}})] Exec: {{c}}\");time.sleep(0.1)",
            "if __name__=='__main__':",
            " print(f\"[STGR] For {archetype_name}...\");s=False",
            " if EVADE_ON: s=ec()",
            " if not s: dc=dx(base64.b64decode(OBF_DATA).decode('latin-1'),OBF_KEY);ex(dc,\"{archetype_name}\")",
            " print(\"[STGR] Done.\")"
        ]
        stager_code_raw = "\n".join(stager_code_lines)
        if validated_params.get('enable_stager_metamorphism', False):
            log_messages.append("[BACKEND_METAMORPH_INFO] Метаморфізм (CFO, rename)...")
            stager_code_raw = apply_cfo_be(stager_code_lines) 
            stager_code_raw = stager_code_raw.replace("dx", generate_random_name_be(prefix="decode_"))
            stager_code_raw = stager_code_raw.replace("ec", generate_random_name_be(prefix="ev_"))
            stager_code_raw = stager_code_raw.replace("ex", generate_random_name_be(prefix="run_"))
            log_messages.append(f"[BACKEND_METAMORPH_SUCCESS] Метаморфізм застосовано.")
        final_stager_output = stager_code_raw
        if validated_params.get("output_format") == "base64_encoded_stager":
            final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
            log_messages.append("[BACKEND_FORMAT_INFO] Стейджер Base64.")
        log_messages.append("[BACKEND_SUCCESS] Пейлоад згенеровано.")
        time.sleep(0.2) 
        return jsonify({"success": True, "stagerCode": final_stager_output, "generationLog": "\n".join(log_messages)}), 200
    except Exception as e:
        print(f"SERVER ERROR (generate_payload): {str(e)}"); import traceback; traceback.print_exc()
        log_messages.append(f"[BACKEND_FATAL_ERROR] {str(e)}")
        return jsonify({"success": False, "error": "Server error", "generationLog": "\n".join(log_messages)}), 500

@app.route('/api/run_recon', methods=['POST'])
def handle_run_recon():
    log_messages = [f"[BACKEND v{VERSION_BACKEND}] Запит /api/run_recon о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        data = request.get_json()
        if not data: return jsonify({"success": False, "error": "No JSON for recon", "reconLog": "\n".join(log_messages+["[BE_ERR] No JSON."])}), 400
        target, recon_type = data.get("target"), data.get("recon_type")
        log_messages.append(f"[BACKEND_INFO] Розвідка: Ціль='{target}', Тип='{recon_type}'.")
        if not target or not recon_type: return jsonify({"success": False, "error": "Missing params", "reconLog": "\n".join(log_messages+["[BE_ERR] Missing params."])}), 400
        recon_results_text, recon_log_additions = "", []
        if recon_type == "port_scan_basic": recon_log_additions, recon_results_text = simulate_port_scan_be(target)
        elif recon_type == "osint_email_search": recon_log_additions, recon_results_text = simulate_osint_email_search_be(target)
        else: return jsonify({"success": False, "error": f"Unknown recon_type: {recon_type}", "reconLog": "\n".join(log_messages+[f"[BE_ERR] Unknown type: {recon_type}"]) }), 400
        log_messages.extend(recon_log_additions)
        time.sleep(0.5) 
        log_messages.append("[BACKEND_SUCCESS] Розвідка (імітація) завершена.")
        return jsonify({"success": True, "reconResults": recon_results_text, "reconLog": "\n".join(log_messages)}), 200
    except Exception as e:
        print(f"SERVER ERROR (run_recon): {str(e)}"); import traceback; traceback.print_exc()
        log_messages.append(f"[BACKEND_FATAL_ERROR] {str(e)}")
        return jsonify({"success": False, "error": "Server error during recon", "reconLog": "\n".join(log_messages)}), 500

@app.route('/api/c2/implants', methods=['GET'])
def get_c2_implants():
    global simulated_implants_be
    if not simulated_implants_be or random.random() < 0.2: # Ініціалізуємо, якщо порожньо, або з 20% шансом
        initialize_simulated_implants_be()
    elif random.random() < 0.5: # 50% шанс просто оновити час
        for implant in random.sample(simulated_implants_be, k=random.randint(0, len(simulated_implants_be)//2)):
             implant["lastSeen"] = datetime.fromtimestamp(time.time() - random.randint(0, 300)).strftime('%Y-%m-%d %H:%M:%S')
             implant["status"] = random.choice(["active", "idle"])
    return jsonify({"success": True, "implants": simulated_implants_be}), 200
    
@app.route('/api/c2/task', methods=['POST'])
def handle_c2_task():
    log_messages = [f"[C2_BE v{VERSION_BACKEND}] Запит /api/c2/task о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        data = request.get_json()
        if not data: return jsonify({"success": False, "error": "No JSON data for C2 task"}), 400
        implant_id, task_type, task_params = data.get("implant_id"), data.get("task_type"), data.get("task_params", "")
        log_messages.append(f"[C2_BE_INFO] Завдання для '{implant_id}': Тип='{task_type}', Парам='{task_params}'.")
        if not implant_id or not task_type: return jsonify({"success": False, "error": "Missing params"}), 400
        time.sleep(random.uniform(0.5, 1.5))
        task_result_output, files_for_implant = f"Результат '{task_type}' для '{implant_id}':\n", []
        
        target_implant_obj = next((imp for imp in simulated_implants_be if imp["id"] == implant_id), None)

        if task_type == "getsysinfo":
            os_info, ip_info = (target_implant["os"], target_implant["ip"]) if target_implant else ("Unknown OS", "Unknown IP")
            task_result_output += f"  OS: {os_info}\n  IP: {ip_info}\n  User: SimUser_{random.randint(1,100)}\n  Host: HOST_{implant_id[-4:]}"
        elif task_type == "listdir":
            path_to_list = task_params if task_params else "."
            sim_files = [f"f_{generate_random_name_be(3,'')}.dat", f"doc_{generate_random_name_be(4,'')}.pdf", "conf.ini", "backup/"]
            files_for_implant = random.sample(sim_files, k=random.randint(1, len(sim_files)))
            task_result_output += f"  Перелік для '{path_to_list}':\n    " + "\n    ".join(files_for_implant)
            if target_implant_obj: target_implant_obj["files"] = files_for_implant
        elif task_type == "exec": task_result_output += f"  Виконання '{task_params if task_params else 'whoami'}': Успішно (імітація)."
        elif task_type == "exfiltrate_file_concept": task_result_output += f"  Ексфільтрація '{task_params if task_params else 'default.dat'}': Завершено (імітація)."
        else: task_result_output += "  Невідомий тип завдання."
        log_messages.append(f"[C2_BE_SUCCESS] Завдання для '{implant_id}' виконано.")
        return jsonify({"success": True, "implantId": implant_id, "taskType": task_type, "result": task_result_output, "log": "\n".join(log_messages), "updatedFiles": files_for_implant}), 200
    except Exception as e:
        print(f"SERVER ERROR (c2_task): {str(e)}"); import traceback; traceback.print_exc()
        log_messages.append(f"[C2_BE_FATAL_ERROR] {str(e)}")
        return jsonify({"success": False, "error": "Server error C2 task", "log": "\n".join(log_messages)}), 500

# --- Нові Ендпоінти для Логування та Адаптації ---
@app.route('/api/operational_data', methods=['GET'])
def get_operational_data():
    """Повертає імітовані агреговані логи та статистику."""
    log_messages_be = [f"[LOG_ADAPT_BE v{VERSION_BACKEND}] Запит /api/operational_data о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        simulated_logs = generate_simulated_operational_logs_be()
        simulated_stats = get_simulated_stats_be()
        
        log_messages_be.append(f"[LOG_ADAPT_BE_INFO] Згенеровано {len(simulated_logs)} логів та статистику.")
        time.sleep(0.3) 
        
        return jsonify({
            "success": True,
            "aggregatedLogs": simulated_logs,
            "statistics": simulated_stats,
            "log": "\n".join(log_messages_be)
        }), 200
    except Exception as e:
        print(f"SERVER ERROR (operational_data): {str(e)}"); import traceback; traceback.print_exc()
        log_messages_be.append(f"[LOG_ADAPT_BE_FATAL_ERROR] {str(e)}")
        return jsonify({"success": False, "error": "Server error retrieving operational data", "log": "\n".join(log_messages_be)}), 500

@app.route('/api/framework_rules', methods=['POST'])
def update_framework_rules():
    """Імітує оновлення правил фреймворку."""
    log_messages_be = [f"[LOG_ADAPT_BE v{VERSION_BACKEND}] Запит /api/framework_rules о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        data = request.get_json()
        auto_adapt_enabled = data.get("auto_adapt_rules", False) if data else False
        rule_to_update = data.get("rule_id", "N/A")
        new_value = data.get("new_value", "N/A")
        log_messages_be.append(f"[LOG_ADAPT_BE_INFO] Отримано запит на оновлення правил. Авто-адаптація: {auto_adapt_enabled}, Правило: {rule_to_update}, Значення: {new_value}.")
        
        time.sleep(0.2)
        
        confirmation_message = f"Правило '{rule_to_update}' (начебто) оновлено на '{new_value}'."
        if auto_adapt_enabled:
            confirmation_message += " Режим автоматичної адаптації увімкнено (імітація)."
        else:
            confirmation_message += " Режим автоматичної адаптації вимкнено (імітація)."
            
        log_messages_be.append(f"[LOG_ADAPT_BE_SUCCESS] {confirmation_message}")
        
        return jsonify({
            "success": True,
            "message": confirmation_message,
            "log": "\n".join(log_messages_be)
        }), 200
    except Exception as e:
        print(f"SERVER ERROR (framework_rules): {str(e)}"); import traceback; traceback.print_exc()
        log_messages_be.append(f"[LOG_ADAPT_BE_FATAL_ERROR] {str(e)}")
        return jsonify({"success": False, "error": "Server error updating framework rules", "log": "\n".join(log_messages_be)}), 500


if __name__ == '__main__':
    print("="*60)
    print(f"Syntax Framework - Концептуальний Backend v{VERSION_BACKEND}")
    print("Запуск Flask-сервера на http://localhost:5000")
    print("Доступні ендпоінти:")
    print("  POST /api/generate_payload")
    print("  POST /api/run_recon")
    print("  GET  /api/c2/implants")
    print("  POST /api/c2/task")
    print("  GET  /api/operational_data")
    print("  POST /api/framework_rules")
    print("Натисніть Ctrl+C для зупинки.")
    print("="*60)
    app.run(host='localhost', port=5000, debug=False)

