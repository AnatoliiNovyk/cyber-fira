# Syntax Flask Backend - Segment SFB-CORE-1.4.0
# Призначення: Розширений концептуальний backend на Flask з поглибленою
#             імітацією метаморфних технік при генерації пейлоадів.

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import base64
import re
import random
import string
import time
from datetime import datetime

VERSION_BACKEND = "1.4.0" # Оновлена версія backend

# --- Дані для Імітації C2 (без змін) ---
simulated_implants_be = []
implant_task_results_be = {} 

def initialize_simulated_implants_be():
    global simulated_implants_be
    simulated_implants_be = []
    os_types = ["Windows_x64_10.0.22000", "Linux_x64_6.1.0", "Windows_x64_11_Pro", "macOS_ventura_arm64"]
    base_ip_prefixes = ["10.10.", "192.168.", "172.20."]
    num_implants = random.randint(4, 7)
    for i in range(num_implants):
        implant_id = f"SYNIMPLNT-PRO-{random.randint(10000,99999)}-{random.choice(string.ascii_uppercase)}"
        ip_prefix = random.choice(base_ip_prefixes)
        ip_address = f"{ip_prefix}{random.randint(10,250)}.{random.randint(10,250)}"
        os_type = random.choice(os_types)
        last_seen_timestamp = time.time() - random.randint(0, 3600) 
        last_seen_str = datetime.fromtimestamp(last_seen_timestamp).strftime('%Y-%m-%d %H:%M:%S')
        simulated_implants_be.append({
            "id": implant_id, "ip": ip_address, "os": os_type,
            "lastSeen": last_seen_str, "status": random.choice(["active_beacon", "idle_low_power", "task_running"]),
            "files": []
        })
    simulated_implants_be.sort(key=lambda x: x["id"])
    print(f"[C2_SIM_INFO] Ініціалізовано/Оновлено {len(simulated_implants_be)} імітованих імплантів.")

# --- Логіка для Генератора Пейлоадів (валідація та архетипи без змін від v1.3.0) ---
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

# --- Розширена Логіка Метаморфізму та Обфускації ---
def xor_cipher(data_str: str, key: str) -> str:
    if not key: key = "DefaultXOR"
    return "".join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data_str)])

def b64_encode_str(data_str: str) -> str:
    return base64.b64encode(data_str.encode('latin-1')).decode('utf-8')

def b64_decode_str(b64_str: str) -> str:
    return base64.b64decode(b64_str.encode('utf-8')).decode('latin-1')

def generate_random_var_name(length=7, prefix="var_"):
    return prefix + ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def obfuscate_string_literals_in_stager(stager_code: str, key: str) -> str:
    """Знаходить та обфускує ключові рядкові літерали в коді стейджера."""
    # Список рядків, які потенційно є сигнатурами
    sensitive_strings = [
        "EVADE_SIM", "SIM_STAGER_EVASION", "Sandbox-like environment detected", "Evasion checks passed",
        "SIM_PAYLOAD", "Payload executed with content", "simulating beacon to", "get_system_id",
        "simulating listing directory", "SIM_STAGER", "Stager for", "starting...", "Stager finished."
    ]
    
    # Сортуємо за довжиною, щоб уникнути часткових замін
    sensitive_strings.sort(key=len, reverse=True)
    
    decoder_func_name = generate_random_name_be(prefix="resolve_")
    decoder_func_code = f"""
def {decoder_func_name}(s_b64, k_s):
    d_b = base64.b64decode(s_b64.encode('utf-8')).decode('latin-1')
    return "".join([chr(ord(c) ^ ord(k_s[i % len(k_s)])) for i, c in enumerate(d_b)])
"""
    # Вставляємо функцію декодера на початку (після імпортів)
    import_line_match = re.search(r"import .*?\n", stager_code)
    if import_line_match:
        insert_pos = import_line_match.end()
        stager_code = stager_code[:insert_pos] + "\n" + decoder_func_code + "\n" + stager_code[insert_pos:]
    else: # Якщо немає імпортів, вставляємо на самий початок
        stager_code = decoder_func_code + "\n" + stager_code

    for s_literal in sensitive_strings:
        if s_literal in stager_code:
            obfuscated_s = b64_encode_str(xor_cipher(s_literal, key))
            stager_code = stager_code.replace(f"\"{s_literal}\"", f"{decoder_func_name}(\"{obfuscated_s}\", OBFUSCATION_KEY_EMBEDDED)")
            stager_code = stager_code.replace(f"'{s_literal}'", f"{decoder_func_name}(\"{obfuscated_s}\", OBFUSCATION_KEY_EMBEDDED)")
    return stager_code

def apply_advanced_cfo_be(code_lines: list) -> str:
    """Застосовує більш різноманітні техніки CFO."""
    transformed_code = []
    for line in code_lines:
        transformed_code.append(line)
        if random.random() < 0.20 and line.strip() and not line.strip().startswith("#") and "def " not in line: # 20% шанс
            indent = line[:len(line) - len(line.lstrip())]
            cfo_type = random.randint(1, 4)
            junk_var = generate_random_name_be()
            
            if cfo_type == 1: # Завжди істинний if
                transformed_code.append(f"{indent}if {random.randint(1,10)} + {random.randint(1,10)} > 0: # CFO Type 1 (True)")
                transformed_code.append(f"{indent}    {junk_var} = '{generate_random_name_be(5, '')}' # Junk op")
                transformed_code.append(f"{indent}    pass")
                transformed_code.append(f"{indent}else:")
                transformed_code.append(f"{indent}    pass # Dead code")
            elif cfo_type == 2: # Завжди хибний if (виконується else)
                transformed_code.append(f"{indent}if '{generate_random_name_be(3, '')}' == '{generate_random_name_be(3, '')}X': # CFO Type 2 (False)")
                transformed_code.append(f"{indent}    pass # Dead code")
                transformed_code.append(f"{indent}else:")
                transformed_code.append(f"{indent}    {junk_var} = {random.randint(100,200)} # Junk op")
                transformed_code.append(f"{indent}    pass")
            elif cfo_type == 3: # Невеликий цикл
                loop_var = generate_random_name_be(1, '_j')
                transformed_code.append(f"{indent}for {loop_var} in range({random.randint(0,2)}): # CFO Type 3 (Junk Loop)")
                transformed_code.append(f"{indent}    {junk_var} = {loop_var} * {random.randint(1,5)}")
                transformed_code.append(f"{indent}    pass")
            elif cfo_type == 4: # Присвоєння та порівняння
                val1, val2 = random.randint(1,50), random.randint(1,50)
                transformed_code.append(f"{indent}{junk_var}_a = {val1}")
                transformed_code.append(f"{indent}{junk_var}_b = {val2}")
                transformed_code.append(f"{indent}if {junk_var}_a + {junk_var}_b == {val1+val2}: # CFO Type 4 (True by calc)")
                transformed_code.append(f"{indent}    pass")
            transformed_code.append(f"{indent}# ---- End CFO Block ----")
    return "\n".join(transformed_code)

# --- Кінець Розширеної Логіки Метаморфізму ---


# --- Логіка для Модуля Розвідки (без змін від v1.2.0) ---
# ... (код simulate_port_scan_be та simulate_osint_email_search_be залишається тут) ...
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

# --- Логіка для Логування та Адаптації (з версії 1.3.0, без змін) ---
def generate_simulated_operational_logs_be() -> list[dict]:
    logs = []
    log_levels = ["INFO", "WARN", "ERROR", "SUCCESS"]
    components = ["PayloadGen_BE", "Recon_BE", "C2_Implant_Alpha_BE", "C2_Implant_Beta_BE", "FrameworkCore_BE", "AdaptationEngine_BE"]
    messages_templates = [
        "Операцію '{op}' запущено для цілі '{tgt}'.", "Сканування порту {port} для {tgt} завершено.", 
        "Виявлено потенційну вразливість: {cve} на {tgt}.", "Пейлоад типу '{ptype}' успішно доставлено на {imp_id}.", 
        "Помилка з'єднання з C2 для імпланта {imp_id}.", "Імплант {imp_id} отримав нове завдання: '{task}'.",
        "Ексфільтрація даних: '{file}' chunk {c}/{t} з {imp_id}.", "Виявлено підозрілу активність EDR на хості {host_ip}.",
        "Правило метаморфізму #{rule_id} оновлено автоматично.", "Імплант {imp_id} перейшов у сплячий режим на {N} хвилин.",
        "Невдала спроба підвищення привілеїв на {host_ip} (користувач: {usr}).", "Успішне виконання '{cmd}' на імпланті {imp_id}."
    ]
    for _ in range(random.randint(15, 25)):
        log_entry = {
            "timestamp": datetime.fromtimestamp(time.time() - random.randint(0, 3600 * 2)).strftime('%Y-%m-%d %H:%M:%S'),
            "level": random.choice(log_levels), "component": random.choice(components),
            "message": random.choice(messages_templates).format(
                op=random.choice(["recon", "deploy", "exfil"]),
                tgt=f"{random.randint(10,192)}.{random.randint(0,168)}.{random.randint(1,200)}.{random.randint(1,254)}",
                port=random.choice([80,443,22,3389]), cve=f"CVE-202{random.randint(3,5)}-{random.randint(1000,29999)}",
                ptype=random.choice(CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"]["allowed_values"]), imp_id=f"IMPLNT-{random.randint(100,999)}",
                task=random.choice(["listdir /tmp","getsysinfo"]), file=f"secret_{random.randint(1,10)}.dat", c=random.randint(1,5),t=5,
                host_ip=f"10.1.1.{random.randint(10,50)}", rule_id=random.randint(100,200), N=random.randint(5,60),
                usr=random.choice(["system","admin","user"]), cmd=random.choice(["whoami","ipconfig"])
            )
        }
        logs.append(log_entry)
    logs.sort(key=lambda x: x["timestamp"])
    return logs
def get_simulated_stats_be() -> dict:
    global simulated_implants_be
    return {
        "successRate": random.randint(60, 95), "detectionRate": random.randint(5, 25),
        "bestArchetype": random.choice(CONCEPTUAL_PARAMS_SCHEMA_BE["payload_archetype"]["allowed_values"]),
        "activeImplants": len(simulated_implants_be)
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
            # ... (обробка помилки як у v1.3.0) ...
            log_messages.append("[BACKEND_ERROR] Не отримано JSON.")
            return jsonify({"success": False, "error": "No JSON", "generationLog": "\n".join(log_messages)}), 400
        
        log_messages.append(f"[BACKEND_INFO] Параметри: {json.dumps(data, indent=2, ensure_ascii=False)}")
        is_valid, validated_params, errors = conceptual_validate_parameters_be(data, CONCEPTUAL_PARAMS_SCHEMA_BE)
        if not is_valid:
            # ... (обробка помилки валідації як у v1.3.0) ...
            log_messages.append(f"[BACKEND_VALIDATION_FAILURE] Помилки: {errors}")
            return jsonify({"success": False, "error": "Validation failed", "errors": errors, "generationLog": "\n".join(log_messages)}), 400
        log_messages.append("[BACKEND_VALIDATION_SUCCESS] Валідація успішна.")
        
        archetype_name = validated_params.get("payload_archetype")
        archetype_details = CONCEPTUAL_ARCHETYPE_TEMPLATES_BE.get(archetype_name)
        log_messages.append(f"[BACKEND_ARCHETYPE_INFO] Архетип: {archetype_name} - {archetype_details['description']}")
        
        data_to_obfuscate = ""
        if archetype_name == "demo_echo_payload": data_to_obfuscate = validated_params.get("message_to_echo", "Default Echo Message")
        elif archetype_name == "demo_file_lister_payload": data_to_obfuscate = validated_params.get("directory_to_list", ".")
        elif archetype_name == "demo_c2_beacon_payload": 
            host = validated_params.get("c2_target_host", "localhost")
            port = validated_params.get("c2_target_port", 8080)
            data_to_obfuscate = f"{host}:{port}"
        
        key = validated_params.get("obfuscation_key", "DefaultFrameworkKey")
        log_messages.append(f"[BACKEND_OBF_INFO] Обфускація даних ('{data_to_obfuscate[:20]}...') з ключем '{key}'.")
        obfuscated_data_raw = conceptual_xor_string_be(data_to_obfuscate, key)
        obfuscated_data_b64 = b64_encode_str(obfuscated_data_raw) # Використання нової функції
        log_messages.append(f"[BACKEND_OBF_SUCCESS] Дані обфусковано: {obfuscated_data_b64[:30]}...")

        log_messages.append(f"[BACKEND_STAGER_GEN_INFO] Генерація стейджера...")
        
        # Базовий шаблон стейджера (імітація Python)
        stager_code_lines = [
            f"# SYNTAX Conceptual Python Stager (Backend Generated v{VERSION_BACKEND})",
            f"# Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Archetype: {archetype_name}",
            f"OBF_DATA_B64 = \"{obfuscated_data_b64}\"", # Дані вже в Base64
            f"OBFUSCATION_KEY_EMBEDDED = \"{key}\"",
            f"METAMORPHISM_APPLIED = {validated_params.get('enable_stager_metamorphism', False)}",
            f"EVASION_CHECKS_APPLIED = {validated_params.get('enable_evasion_checks', False)}",
            "", "import base64", "import os", "import time", "import random", ""
        ]
        
        # Функції декодування та виконання (можуть бути перейменовані метаморфізмом)
        decode_func_name_runtime = "dx_runtime"
        evasion_func_name_runtime = "ec_runtime"
        execute_func_name_runtime = "ex_runtime"

        stager_code_lines.extend([
            f"def {decode_func_name_runtime}(b64_data, key_str):",
            "    # У реальному Python: base64.b64decode(b64_data).decode('latin-1')",
            "    # Потім XOR. Тут спрощена імітація.",
            "    try:",
            "        temp_decoded_bytes = base64.b64decode(b64_data.encode('utf-8'))",
            "        temp_decoded_str = temp_decoded_bytes.decode('latin-1')",
            "    except Exception as e_b64: return f\"B64_DECODE_ERROR: {{e_b64}}\"",
            "    o_chars = []",
            "    for i_char_idx in range(len(temp_decoded_str)):",
            "        o_chars.append(chr(ord(temp_decoded_str[i_char_idx]) ^ ord(key_str[i_char_idx % len(key_str)])))",
            "    return \"\".join(o_chars)",
            "",
            f"def {evasion_func_name_runtime}():",
            "    print(\"[SIM_STAGER_EVASION] Performing simulated evasion checks...\")",
            "    # Більш просунуті перевірки можна додати сюди",
            "    if os.name == 'nt' and 'SANDBOX_USER' in os.environ:",
            "        print(\"[SIM_STAGER_EVASION] SANDBOX_USER environment variable found!\")",
            "        return True",
            "    if random.random() < 0.15: # 15% шанс на інший індикатор",
            "        print(\"[SIM_STAGER_EVASION] Another sandbox-like indicator detected (simulated)!\")",
            "        return True",
            "    print(\"[SIM_STAGER_EVASION] Evasion checks passed (simulated).\")",
            "    return False",
            "",
            f"def {execute_func_name_runtime}(content, arch_type):",
            "    print(f\"[SIM_PAYLOAD ({{arch_type}})] Payload logic initiated with: {{content}}\")",
            "    if arch_type == 'demo_c2_beacon_payload':",
            "        print(f\"[SIM_PAYLOAD ({{arch_type}})] ...simulating beacon to {{content}} and C2 task 'scan_local_network'.\")",
            "    elif arch_type == 'demo_file_lister_payload':",
            "        print(f\"[SIM_PAYLOAD ({{arch_type}})] ...simulating listing directory: {{content}} -> ['report.docx', 'config.sys', 'tools/']\")",
            "    elif arch_type == 'demo_echo_payload':",
            "        print(f\"[SIM_PAYLOAD ({{arch_type}})] Echoing: {{content}}\")",
            "",
            "if __name__ == '__main__':",
            "    print(f\"[SIM_STAGER] Stager for {archetype_name} starting...\")",
            "    sandbox_detected_flag = False",
            "    if EVASION_CHECKS_APPLIED:",
            f"        sandbox_detected_flag = {evasion_func_name_runtime}()",
            "    if not sandbox_detected_flag:",
            f"        decoded_payload_content = {decode_func_name_runtime}(OBF_DATA_B64, OBFUSCATION_KEY_EMBEDDED)",
            f"        {execute_func_name_runtime}(decoded_payload_content, \"{archetype_name}\")",
            "    else:",
            "        print(\"[SIM_STAGER] Sandbox detected, altering behavior or exiting.\")",
            "    print(\"[SIM_STAGER] Stager finished.\")"
        ])
        
        stager_code_raw = "\n".join(stager_code_lines)

        if validated_params.get('enable_stager_metamorphism', False):
            log_messages.append("[BACKEND_METAMORPH_INFO] Застосування розширеного метаморфізму...")
            stager_code_raw_list = stager_code_raw.splitlines() # Для apply_cfo_be
            stager_code_raw = apply_advanced_cfo_be(stager_code_raw_list) # Використовуємо нову CFO
            
            # Перейменування функцій (після CFO, щоб не зламати плейсхолдери)
            new_decode_name = generate_random_name_be(prefix="unveil_")
            new_evasion_name = generate_random_name_be(prefix="audit_env_")
            new_execute_name = generate_random_name_be(prefix="dispatch_core_")
            stager_code_raw = stager_code_raw.replace(decode_func_name_runtime, new_decode_name)
            stager_code_raw = stager_code_raw.replace(evasion_func_name_runtime, new_evasion_name)
            stager_code_raw = stager_code_raw.replace(execute_func_name_runtime, new_execute_name)
            
            # Обфускація рядкових літералів
            stager_code_raw = obfuscate_string_literals_in_stager(stager_code_raw, key) # Використовуємо основний ключ для простоти

            log_messages.append(f"[BACKEND_METAMORPH_SUCCESS] Метаморфізм застосовано (функції: {new_decode_name}, {new_evasion_name}, {new_execute_name}).")

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
    # ... (код з версії 1.3.0 без змін) ...
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
    # ... (код з версії 1.3.0 без змін) ...
    global simulated_implants_be
    if not simulated_implants_be or random.random() < 0.2: 
        initialize_simulated_implants_be()
    elif random.random() < 0.5: 
        for implant in random.sample(simulated_implants_be, k=random.randint(0, len(simulated_implants_be)//2)):
             implant["lastSeen"] = datetime.fromtimestamp(time.time() - random.randint(0, 300)).strftime('%Y-%m-%d %H:%M:%S')
             implant["status"] = random.choice(["active", "idle"])
    return jsonify({"success": True, "implants": simulated_implants_be}), 200
    
@app.route('/api/c2/task', methods=['POST'])
def handle_c2_task():
    # ... (код з версії 1.3.0 без змін) ...
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
            os_info, ip_info = (target_implant_obj["os"], target_implant_obj["ip"]) if target_implant_obj else ("Unknown OS", "Unknown IP")
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

@app.route('/api/operational_data', methods=['GET'])
def get_operational_data():
    # ... (код з версії 1.3.0 без змін) ...
    log_messages_be = [f"[LOG_ADAPT_BE v{VERSION_BACKEND}] Запит /api/operational_data о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        simulated_logs = generate_simulated_operational_logs_be()
        simulated_stats = get_simulated_stats_be()
        log_messages_be.append(f"[LOG_ADAPT_BE_INFO] Згенеровано {len(simulated_logs)} логів та статистику.")
        time.sleep(0.3) 
        return jsonify({"success": True, "aggregatedLogs": simulated_logs, "statistics": simulated_stats, "log": "\n".join(log_messages_be)}), 200
    except Exception as e:
        print(f"SERVER ERROR (operational_data): {str(e)}"); import traceback; traceback.print_exc()
        log_messages_be.append(f"[LOG_ADAPT_BE_FATAL_ERROR] {str(e)}")
        return jsonify({"success": False, "error": "Server error retrieving operational data", "log": "\n".join(log_messages_be)}), 500

@app.route('/api/framework_rules', methods=['POST'])
def update_framework_rules():
    # ... (код з версії 1.3.0 без змін) ...
    log_messages_be = [f"[LOG_ADAPT_BE v{VERSION_BACKEND}] Запит /api/framework_rules о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        data = request.get_json()
        auto_adapt_enabled = data.get("auto_adapt_rules", False) if data else False
        rule_to_update = data.get("rule_id", "N/A")
        new_value = data.get("new_value", "N/A")
        log_messages_be.append(f"[LOG_ADAPT_BE_INFO] Запит на оновлення правил. Авто-адаптація: {auto_adapt_enabled}, Правило: {rule_to_update}, Значення: {new_value}.")
        time.sleep(0.2)
        confirmation_message = f"Правило '{rule_to_update}' (начебто) оновлено на '{new_value}'."
        if auto_adapt_enabled: confirmation_message += " Режим автоматичної адаптації увімкнено (імітація)."
        else: confirmation_message += " Режим автоматичної адаптації вимкнено (імітація)."
        log_messages_be.append(f"[LOG_ADAPT_BE_SUCCESS] {confirmation_message}")
        return jsonify({"success": True, "message": confirmation_message, "log": "\n".join(log_messages_be)}), 200
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

