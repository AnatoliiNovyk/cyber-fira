# Syntax Flask Backend - Segment SFB-CORE-1.5.0
# Призначення: Backend на Flask з поглибленою імітацією метаморфних технік
#             (розширена CFO, обфускація рядків, вставка "сміттєвого" коду).

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import base64
import re
import random
import string
import time
from datetime import datetime

VERSION_BACKEND = "1.5.0" # Оновлена версія backend

# --- Дані для Імітації C2 (без змін) ---
simulated_implants_be = []
implant_task_results_be = {} 

def initialize_simulated_implants_be():
    global simulated_implants_be
    simulated_implants_be = []
    os_types = ["Windows_x64_10.0.22621", "Linux_x64_6.2.0", "Windows_Server_2022", "macOS_sonoma_arm64"]
    base_ip_prefixes = ["10.20.", "192.168.", "172.18."]
    num_implants = random.randint(4, 8)
    for i in range(num_implants):
        implant_id = f"SYNIMPLNT-ADV-{random.randint(10000,99999)}-{random.choice(string.ascii_uppercase)}"
        ip_prefix = random.choice(base_ip_prefixes)
        ip_address = f"{ip_prefix}{random.randint(1,254)}.{random.randint(2,253)}"
        os_type = random.choice(os_types)
        last_seen_timestamp = time.time() - random.randint(0, 1800) # Останні 30 хв
        last_seen_str = datetime.fromtimestamp(last_seen_timestamp).strftime('%Y-%m-%d %H:%M:%S')
        simulated_implants_be.append({
            "id": implant_id, "ip": ip_address, "os": os_type,
            "lastSeen": last_seen_str, "status": random.choice(["active_tasked", "idle_beaconing", "error_comms"]),
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

# --- Розширена Логіка Метаморфізму та Обфускації v1.5.0 ---
def xor_cipher(data_str: str, key: str) -> str: 
    if not key: key = "DefaultXOR_Key_v2" # Оновлений ключ за замовчуванням
    return "".join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data_str)])

def b64_encode_str(data_str: str) -> str:
    return base64.b64encode(data_str.encode('latin-1')).decode('utf-8')

def generate_random_name_be(length=10, prefix="syn_"): # Збільшено довжину, змінено префікс
    return prefix + ''.join(random.choice(string.ascii_lowercase + '_') for i in range(length)) # Додано '_'

def obfuscate_string_literals_in_python_code(code: str, key: str) -> tuple[str, str]:
    """Знаходить та обфускує рядкові літерали в Python коді, вставляє функцію-декодер."""
    
    # Знаходимо всі рядкові літерали (в одинарних або подвійних лапках)
    # Цей regex може бути не ідеальним для складних випадків (напр., багаторядкові рядки, екрановані лапки)
    # але для демонстрації він підійде.
    string_literals = list(set(re.findall(r'\"([^\"\\]*(?:\\.[^\"\\]*)*)\"|\'([^\'\\]*(?:\\.[^\'\\]*)*)\'', code)))
    
    # Фільтруємо порожні рядки та ті, що вже є викликами функції
    # Також не обфускуємо дуже короткі рядки або ті, що схожі на імена змінних/ключові слова Python
    python_keywords = ["False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield"]
    
    processed_literals = {} # Щоб уникнути повторної обфускації того самого рядка
    decoder_func_name = generate_random_name_be(prefix="unveil_str_")
    
    modified_code = code

    for match_tuple in string_literals:
        s_literal = match_tuple[0] if match_tuple[0] else match_tuple[1] # Отримуємо рядок з кортежу
        if not s_literal or len(s_literal) < 3 or s_literal in python_keywords or s_literal.isidentifier():
            continue
        if s_literal in processed_literals: # Якщо вже оброблено
            # Замінюємо на виклик з вже згенерованою змінною
            var_name = processed_literals[s_literal]
            modified_code = modified_code.replace(f"\"{s_literal}\"", var_name)
            modified_code = modified_code.replace(f"'{s_literal}'", var_name)
            continue

        obfuscated_s_xor = xor_cipher(s_literal, key)
        obfuscated_s_b64 = b64_encode_str(obfuscated_s_xor)
        
        # Генеруємо унікальне ім'я змінної для цього обфускованого рядка
        var_name = generate_random_name_be(prefix="obf_str_")
        processed_literals[s_literal] = var_name # Зберігаємо ім'я змінної

        # Додаємо визначення змінної на початку коду (спрощено, після імпортів)
        # У реальності, потрібно було б знайти краще місце або зібрати всі визначення разом
        var_definition = f"{var_name} = {decoder_func_name}(\"{obfuscated_s_b64}\", OBFUSCATION_KEY_EMBEDDED)\n" # Припускаємо, що OBFUSCATION_KEY_EMBEDDED буде визначено
        
        import_line_match = re.search(r"import .*?\n", modified_code)
        if import_line_match:
            insert_pos = import_line_match.end()
            modified_code = modified_code[:insert_pos] + var_definition + modified_code[insert_pos:]
        else:
            modified_code = var_definition + modified_code
            
        # Замінюємо рядок у коді на ім'я змінної
        modified_code = modified_code.replace(f"\"{s_literal}\"", var_name)
        modified_code = modified_code.replace(f"'{s_literal}'", var_name)

    # Вставляємо саму функцію декодера, якщо були обфусковані рядки
    if processed_literals:
        decoder_func_code = f"""
def {decoder_func_name}(s_b64, k_s):
    # Ця функція деобфускує рядок, який був обфускований XOR та закодований в Base64
    try:
        d_b = base64.b64decode(s_b64.encode('utf-8')).decode('latin-1')
        return "".join([chr(ord(c) ^ ord(k_s[i % len(k_s)])) for i, c in enumerate(d_b)])
    except Exception: return s_b64 # Повертаємо оригінал у разі помилки
"""
        import_line_match = re.search(r"import .*?\n", modified_code) # Шукаємо знову, бо код змінився
        if import_line_match:
            insert_pos = import_line_match.end()
            modified_code = modified_code[:insert_pos] + "\n" + decoder_func_code + "\n" + modified_code[insert_pos:]
        else:
            modified_code = decoder_func_code + "\n" + modified_code
        print(f"[METAMORPH_INFO] Обфусковано {len(processed_literals)} рядкових літералів. Функція-декодер: {decoder_func_name}")

    return modified_code


def apply_advanced_cfo_be(code_lines: list) -> str:
    """Застосовує більш різноманітні техніки CFO та вставку "сміттєвого" коду."""
    transformed_code_list = []
    for line_idx, line in enumerate(code_lines):
        transformed_code_list.append(line)
        
        # Вставка "сміттєвого" коду (з певною ймовірністю)
        if random.random() < 0.10 and line.strip() and not line.strip().startswith("#"): # 10% шанс
            indent = line[:len(line) - len(line.lstrip())]
            junk_var1 = generate_random_name_be(prefix="junk_val_")
            junk_var2 = generate_random_name_be(prefix="temp_calc_")
            junk_ops = [
                f"{indent}{junk_var1} = {random.randint(1000, 9999)} * {random.randint(1,10)} # Junk calculation",
                f"{indent}{junk_var2} = \"{''.join(random.choices(string.ascii_letters + string.digits, k=10))}\" # Junk string assignment",
                f"{indent}# Simple junk comment: {datetime.now().microsecond}"
            ]
            transformed_code_list.append(random.choice(junk_ops))

        # Вставка CFO (з певною ймовірністю)
        if random.random() < 0.20 and line.strip() and not line.strip().startswith("#") and "def " not in line and "class " not in line and "if __name__" not in line:
            indent = line[:len(line) - len(line.lstrip())]
            r1, r2 = random.randint(1,100), random.randint(1,100)
            
            cfo_type = random.randint(1, 5) # Додано більше патернів
            cfo_block = f"{indent}# --- CFO Block Type {cfo_type} Start --- \n"
            
            if cfo_type == 1: # Завжди істинний if
                cfo_block += f"{indent}if {r1} + {r2} != {r1 + r2 + 1}: # Opaque True\n"
                cfo_block += f"{indent}    pass # Actual logic path\n"
                cfo_block += f"{indent}else:\n"
                cfo_block += f"{indent}    {generate_random_name_be(prefix='dead_')} = {r1}*{r2} # Dead code\n"
            elif cfo_type == 2: # Завжди хибний if
                cfo_block += f"{indent}if {r1} == {r1 + 1}: # Opaque False\n"
                cfo_block += f"{indent}    {generate_random_name_be(prefix='never_')} = {r1}-{r2} # Dead code\n"
                cfo_block += f"{indent}else:\n"
                cfo_block += f"{indent}    pass # Actual logic path\n"
            elif cfo_type == 3: # Невеликий "сміттєвий" цикл
                loop_var = generate_random_name_be(1, '_lp')
                cfo_block += f"{indent}for {loop_var} in range({random.randint(0,2)}):\n"
                cfo_block += f"{indent}    {generate_random_name_be(prefix='junk_iter_')} = {loop_var} + {r1}\n"
                cfo_block += f"{indent}    pass\n"
                cfo_block += f"{indent}pass # Actual logic follows loop"
            elif cfo_type == 4: # Присвоєння та порівняння
                var_a = generate_random_name_be(prefix="cfa_")
                var_b = generate_random_name_be(prefix="cfb_")
                cfo_block += f"{indent}{var_a} = {r1} * {random.randint(1,3)}\n"
                cfo_block += f"{indent}{var_b} = {var_a} // {random.randint(1,3) if r1 > 0 else 1}\n"
                cfo_block += f"{indent}if {var_a} >= {var_b}: # Likely True\n"
                cfo_block += f"{indent}    pass\n"
            elif cfo_type == 5: # Вкладений блок
                cfo_block += f"{indent}if True: # Outer always true\n"
                cfo_block += f"{indent}    if {r1} < 0: # Inner likely false\n"
                cfo_block += f"{indent}        pass # Dead path\n"
                cfo_block += f"{indent}    else:\n"
                cfo_block += f"{indent}        pass # Real path\n"

            cfo_block += f"\n{indent}# --- CFO Block End ---"
            transformed_code_list.append(cfo_block)
            
    return "\n".join(transformed_code_list)
# --- Кінець Розширеної Логіки Метаморфізму ---


# --- Логіка для Модуля Розвідки (без змін від v1.3.0) ---
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

# --- Логіка для Логування та Адаптації (без змін від v1.3.0) ---
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
        if archetype_name == "demo_echo_payload": data_to_obfuscate = validated_params.get("message_to_echo", "Default Echo Message")
        elif archetype_name == "demo_file_lister_payload": data_to_obfuscate = validated_params.get("directory_to_list", ".")
        elif archetype_name == "demo_c2_beacon_payload": 
            host = validated_params.get("c2_target_host", "localhost")
            port = validated_params.get("c2_target_port", 8080)
            data_to_obfuscate = f"{host}:{port}"
        
        key = validated_params.get("obfuscation_key", "DefaultFrameworkKey")
        log_messages.append(f"[BACKEND_OBF_INFO] Обфускація даних ('{data_to_obfuscate[:20]}...') з ключем '{key}'.")
        obfuscated_data_raw = xor_cipher(data_to_obfuscate, key)
        obfuscated_data_b64 = b64_encode_str(obfuscated_data_raw)
        log_messages.append(f"[BACKEND_OBF_SUCCESS] Дані обфусковано: {obfuscated_data_b64[:30]}...")

        log_messages.append(f"[BACKEND_STAGER_GEN_INFO] Генерація стейджера...")
        
        # Базовий шаблон стейджера (імітація Python)
        # Будемо використовувати більш гнучкий підхід до формування коду
        stager_code_parts = [
            f"# SYNTAX Conceptual Python Stager (Backend Generated v{VERSION_BACKEND})",
            f"# Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Archetype: {archetype_name}",
            f"OBF_DATA_B64 = \"{obfuscated_data_b64}\"", 
            f"OBFUSCATION_KEY_EMBEDDED = \"{key}\"", # Ключ для даних пейлоада
            f"METAMORPHISM_APPLIED = {validated_params.get('enable_stager_metamorphism', False)}",
            f"EVASION_CHECKS_APPLIED = {validated_params.get('enable_evasion_checks', False)}",
            "", "import base64", "import os", "import time", "import random", "import string", "" # Додано string
        ]
        
        # Функції, що будуть вбудовані (їхні назви можуть бути обфусковані)
        decode_func_name_runtime = "dx_runtime"
        evasion_func_name_runtime = "ec_runtime"
        execute_func_name_runtime = "ex_runtime"

        # Додаємо функції до списку рядків
        stager_code_parts.extend([
            f"def {decode_func_name_runtime}(b64_data, key_str):",
            "    # Імітація XOR + Base64 декодування",
            "    try:",
            "        temp_decoded_bytes = base64.b64decode(b64_data.encode('utf-8'))",
            "        temp_decoded_str = temp_decoded_bytes.decode('latin-1')",
            "    except Exception: return \"DECODE_ERROR\"", # Проста обробка помилки
            "    o_chars = []",
            "    for i_char_idx in range(len(temp_decoded_str)):",
            "        o_chars.append(chr(ord(temp_decoded_str[i_char_idx]) ^ ord(key_str[i_char_idx % len(key_str)])))",
            "    return \"\".join(o_chars)",
            "",
            f"def {evasion_func_name_runtime}():",
            "    print(\"[SIM_STAGER_EVASION] Performing simulated evasion checks...\")",
            "    # Розширені перевірки",
            "    indicators = []",
            "    common_sandbox_users = [\"sandbox\", \"test\", \"admin\", \"user\", \"vagrant\", \"wdagutilityaccount\", \"maltest\"]",
            "    try: current_user = os.getlogin().lower()",
            "    except Exception: current_user = 'unknown_user'", # Обробка помилки, якщо getlogin не спрацює
            "    if current_user in common_sandbox_users: indicators.append('common_username')",
            "    if random.random() < 0.1: indicators.append('suspicious_file_found_sim')",
            "    if random.random() < 0.15: indicators.append('low_disk_space_sim')",
            "    if indicators:",
            "        print(f\"[SIM_STAGER_EVASION] Sandbox-like indicators: {{', '.join(indicators)}}! Altering behavior.\")",
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
            "        print(\"[SIM_STAGER] Sandbox detected, normal execution path skipped.\")",
            "    print(\"[SIM_STAGER] Stager finished.\")"
        ])
        
        stager_code_raw = "\n".join(stager_code_lines)

        if validated_params.get('enable_stager_metamorphism', False):
            log_messages.append("[BACKEND_METAMORPH_INFO] Застосування розширеного метаморфізму...")
            
            # 1. Обфускація рядкових літералів (використовуємо ключ пейлоада для простоти)
            stager_code_raw = obfuscate_string_literals_in_stager(stager_code_raw, key)
            log_messages.append("[BACKEND_METAMORPH_INFO] Обфускацію рядків завершено.")

            # 2. Обфускація керуючого потоку
            stager_code_raw_list_for_cfo = stager_code_raw.splitlines() 
            stager_code_raw = apply_advanced_cfo_be(stager_code_raw_list_for_cfo) 
            log_messages.append("[BACKEND_METAMORPH_INFO] Обфускацію керуючого потоку завершено.")
            
            # 3. Перейменування функцій (після CFO, щоб не зламати плейсхолдери, якщо вони були)
            # Назви функцій вже визначені як decode_func_name_runtime і т.д.
            # Тепер ми їх перейменовуємо на випадкові
            final_decode_name = generate_random_name_be(prefix="unveil_data_")
            final_evasion_name = generate_random_name_be(prefix="verify_runtime_")
            final_execute_name = generate_random_name_be(prefix="dispatch_payload_")
            
            stager_code_raw = stager_code_raw.replace(decode_func_name_runtime, final_decode_name)
            stager_code_raw = stager_code_raw.replace(evasion_func_name_runtime, final_evasion_name)
            stager_code_raw = stager_code_raw.replace(execute_func_name_runtime, final_execute_name)
            log_messages.append(f"[BACKEND_METAMORPH_SUCCESS] Метаморфізм застосовано (функції: {final_decode_name}, {final_evasion_name}, {final_execute_name}).")

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
    if not simulated_implants_be or random.random() < 0.2: 
        initialize_simulated_implants_be()
    elif random.random() < 0.5: 
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
            os_info, ip_info = (target_implant_obj["os"], target_implant_obj["ip"]) if target_implant_obj else ("Unknown OS", "Unknown IP")
            task_result_output += f"  OS: {os_info}\n  IP: {ip_info}\n  User: SimUser_{random.randint(1,100)}\n  Host: HOST_{implant_id[-4:]}"
        elif task_type == "listdir":
            path_to_list = task_params if task_params else "."
            sim_files = [
                f"f_{generate_random_name_be(3,'')}.dat", 
                f"doc_{generate_random_name_be(4,'')}.pdf", 
                "conf.ini", 
                "backup/"
            ]
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

