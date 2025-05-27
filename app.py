# Syntax Flask Backend - Segment SFB-CORE-1.1.0
# Призначення: Розширений концептуальний backend на Flask для генерації пейлоадів
#             та виконання завдань розвідки, що взаємодіє з GUI.

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import base64
import re
import random
import string
import time
from datetime import datetime

VERSION_BACKEND = "1.1.0" # Оновлена версія backend

# --- Логіка для Генератора Пейлоадів (з SFB-PAYGEN-1.0.0) ---
CONCEPTUAL_PARAMS_SCHEMA_BE = {
    "payload_archetype": {
        "type": str,
        "required": True,
        "allowed_values": ["demo_echo_payload", "demo_file_lister_payload", "demo_c2_beacon_payload"]
    },
    "message_to_echo": { 
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "demo_echo_payload",
        "min_length": 1
    },
    "directory_to_list": { 
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "demo_file_lister_payload",
        "default": "." 
    },
    "c2_target_host": { 
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "demo_c2_beacon_payload",
        "validation_regex": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$" 
    },
    "c2_target_port": { 
        "type": int,
        "required": lambda params: params.get("payload_archetype") == "demo_c2_beacon_payload",
        "allowed_range": (1, 65535)
    },
    "obfuscation_key": {
        "type": str,
        "required": True,
        "min_length": 5, 
        "default": "DefaultFrameworkKey"
    },
    "output_format": {
        "type": str,
        "required": False,
        "allowed_values": ["raw_python_stager", "base64_encoded_stager"],
        "default": "raw_python_stager"
    },
    "enable_stager_metamorphism": { 
        "type": bool,
        "required": False,
        "default": True 
    },
    "enable_evasion_checks": { 
        "type": bool,
        "required": False,
        "default": True
    }
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
            # Типова конвертація для параметрів, що надходять з JSON
            if rules.get("type") == int and not isinstance(value_to_validate, int):
                try:
                    value_to_validate = int(value_to_validate)
                except (ValueError, TypeError):
                    pass # Помилка типу буде виявлена нижче
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
            if not is_cond_req_missing:
                validated_params[param_name] = rules["default"]
    
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

# --- Початок: Логіка для Модуля Розвідки ---
def get_service_name_be(port: int) -> str:
    services = { 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 443: "HTTPS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt" }
    return services.get(port, "Unknown")

def simulate_port_scan_be(target: str) -> tuple[list[str], str]:
    """Імітує сканування портів на сервері."""
    log = [f"[RECON_BE_INFO] Імітація сканування портів для цілі: {target}"]
    results_text_lines = [f"Результати сканування портів для: {target}"]
    
    # Імітація TCP connect scan до поширених портів
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 8000, 8080, 8443]
    open_ports_found = []

    for port in common_ports:
        time.sleep(random.uniform(0.01, 0.05)) # Імітація затримки сканування
        if random.random() < 0.3: # 30% шанс, що порт "відкритий"
            service_name = get_service_name_be(port)
            banner = ""
            if random.random() < 0.6: # 60% шанс отримати "банер"
                banner_version = f"v{random.randint(1,5)}.{random.randint(0,9)}"
                possible_banners = [
                    f"OpenSSH_{banner_version}", f"Apache httpd {banner_version}", 
                    f"Microsoft-IIS/{banner_version}", "nginx", 
                    f"ProFTPD {banner_version}", f"vsftpd {banner_version}",
                    f"MySQL {banner_version}", f"PostgreSQL {banner_version}"
                ]
                banner = f" (Banner: {random.choice(possible_banners)})"
            open_ports_found.append(f"  Порт {port} ({service_name}): ВІДКРИТО{banner}")
    
    if open_ports_found:
        results_text_lines.extend(open_ports_found)
    else:
        results_text_lines.append("  Відкритих поширених портів не знайдено (імітація).")
    
    log.append("[RECON_BE_SUCCESS] Імітацію сканування портів завершено.")
    return log, "\n".join(results_text_lines)

def simulate_osint_email_search_be(target_domain: str) -> tuple[list[str], str]:
    """Імітує OSINT пошук email-адрес."""
    log = [f"[RECON_BE_INFO] Імітація OSINT пошуку email для домену: {target_domain}"]
    results_text_lines = [f"Результати OSINT пошуку Email для домену: {target_domain}"]
    
    # Проста логіка для виділення основного домену, якщо введено субдомен
    domain_parts = target_domain.split('.')
    if len(domain_parts) > 2:
        main_domain = ".".join(domain_parts[-2:])
    else:
        main_domain = target_domain

    common_names = ["info", "support", "admin", "contact", "sales", "hr", "abuse", "webmaster"]
    first_names = ["john.doe", "jane.smith", "peter.jones", "susan.lee", "michael.brown"]
    
    found_emails = []
    for _ in range(random.randint(1, 5)): # Знайти 1-5 імейлів
        if random.random() < 0.7:
            email = f"{random.choice(common_names)}@{main_domain}"
        else:
            email = f"{random.choice(first_names)}@{main_domain}"
        if email not in found_emails:
            found_emails.append(email)
            
    if found_emails:
        results_text_lines.extend([f"  Знайдено Email: {email}" for email in found_emails])
    else:
        results_text_lines.append("  Email-адрес не знайдено (імітація).")
        
    log.append("[RECON_BE_SUCCESS] Імітацію OSINT пошуку email завершено.")
    return log, "\n".join(results_text_lines)

# --- Кінець логіки для Модуля Розвідки ---


app = Flask(__name__)
CORS(app) 

@app.route('/api/generate_payload', methods=['POST'])
def handle_generate_payload():
    log_messages = [f"[BACKEND v{VERSION_BACKEND}] Отримано запит на /api/generate_payload о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        data = request.get_json()
        if not data:
            log_messages.append("[BACKEND_ERROR] Не отримано JSON даних.")
            return jsonify({"success": False, "error": "No JSON data received", "generationLog": "\n".join(log_messages)}), 400
        
        log_messages.append(f"[BACKEND_INFO] Отримані параметри: {json.dumps(data, indent=2, ensure_ascii=False)}")

        is_valid, validated_params, errors = conceptual_validate_parameters_be(data, CONCEPTUAL_PARAMS_SCHEMA_BE)
        if not is_valid:
            log_messages.append(f"[BACKEND_VALIDATION_FAILURE] Помилки валідації: {errors}")
            return jsonify({"success": False, "error": "Parameter validation failed", "errors": errors, "generationLog": "\n".join(log_messages)}), 400
        log_messages.append("[BACKEND_VALIDATION_SUCCESS] Параметри успішно валідовані.")

        archetype_name = validated_params.get("payload_archetype")
        archetype_details = CONCEPTUAL_ARCHETYPE_TEMPLATES_BE.get(archetype_name)
        log_messages.append(f"[BACKEND_ARCHETYPE_INFO] Обрано архетип: {archetype_name} - {archetype_details['description']}")

        data_to_obfuscate = ""
        if archetype_name == "demo_echo_payload":
            data_to_obfuscate = validated_params.get("message_to_echo", "Default Echo Message")
        elif archetype_name == "demo_file_lister_payload":
            data_to_obfuscate = validated_params.get("directory_to_list", ".")
        elif archetype_name == "demo_c2_beacon_payload":
            host = validated_params.get("c2_target_host", "localhost")
            port = validated_params.get("c2_target_port", 8080)
            data_to_obfuscate = f"{host}:{port}"
        
        key = validated_params.get("obfuscation_key", "DefaultFrameworkKey")
        log_messages.append(f"[BACKEND_OBFUSCATION_INFO] Обфускація даних ('{data_to_obfuscate[:20]}...') з ключем '{key}'.")
        obfuscated_data_raw = conceptual_xor_string_be(data_to_obfuscate, key)
        obfuscated_data_b64 = base64.b64encode(obfuscated_data_raw.encode('latin-1')).decode('utf-8')
        log_messages.append(f"[BACKEND_OBFUSCATION_SUCCESS] Дані обфусковано: {obfuscated_data_b64[:30]}...")

        log_messages.append(f"[BACKEND_STAGER_GEN_INFO] Генерація стейджера...")
        
        stager_code_lines = [
            f"# SYNTAX Conceptual Python Stager (Backend Generated v{VERSION_BACKEND})",
            f"# Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Archetype: {archetype_name}",
            f"OBFUSCATED_PAYLOAD_B64 = \"{obfuscated_data_b64}\"",
            f"OBFUSCATION_KEY_EMBEDDED = \"{key}\"",
            f"METAMORPHISM_APPLIED = {validated_params.get('enable_stager_metamorphism', False)}",
            f"EVASION_CHECKS_APPLIED = {validated_params.get('enable_evasion_checks', False)}",
            "", "import base64", "import os", "import time", "import random", "",
            "def xor_decode_runtime(b64_data, key_str):",
            "    decoded_data = base64.b64decode(b64_data).decode('latin-1')",
            "    original_chars = []",
            "    for i in range(len(decoded_data)): original_chars.append(chr(ord(decoded_data[i]) ^ ord(key_str[i % len(key_str)])))",
            "    return \"\".join(original_chars)", "",
            "def perform_simulated_evasion_checks():",
            "    print(\"[SIM_STAGER_EVASION] Performing simulated evasion checks...\")",
            "    if random.random() < 0.2: print(\"[SIM_STAGER_EVASION] Sandbox-like environment detected (simulated)! Aborting...\"); return True",
            "    print(\"[SIM_STAGER_EVASION] Evasion checks passed (simulated).\"); return False", "",
            "def execute_simulated_payload(content, arch_type):",
            "    print(f\"[SIM_PAYLOAD ({{arch_type}})] Payload executed with content: {{content}}\")",
            "    if arch_type == 'demo_c2_beacon_payload': print(f\"[SIM_PAYLOAD ({{arch_type}})] ...simulating beacon to {{content}} and task 'get_system_id'.\")",
            "    elif arch_type == 'demo_file_lister_payload': print(f\"[SIM_PAYLOAD ({{arch_type}})] ...simulating listing directory: {{content}} -> ['file1.txt', 'file2.doc']\")",
            "",
            "if __name__ == '__main__':",
            "    print(f\"[SIM_STAGER] Stager for {archetype_name} starting...\")",
            "    sandbox_detected = False",
            "    if EVASION_CHECKS_APPLIED: sandbox_detected = perform_simulated_evasion_checks()",
            "    if not sandbox_detected: decoded_content = xor_decode_runtime(OBFUSCATED_PAYLOAD_B64, OBFUSCATION_KEY_EMBEDDED); execute_simulated_payload(decoded_content, \"{archetype_name}\")",
            "    print(\"[SIM_STAGER] Stager finished.\")"
        ]
        stager_code_raw = "\n".join(stager_code_lines)

        if validated_params.get('enable_stager_metamorphism', False):
            log_messages.append("[BACKEND_METAMORPH_INFO] Застосування метаморфізму (CFO, перейменування)...")
            stager_code_raw = apply_cfo_be(stager_code_lines) 
            new_decode_name = generate_random_name_be(prefix="decode_")
            new_evasion_name = generate_random_name_be(prefix="check_")
            new_execute_name = generate_random_name_be(prefix="run_")
            stager_code_raw = stager_code_raw.replace("xor_decode_runtime", new_decode_name)
            stager_code_raw = stager_code_raw.replace("perform_simulated_evasion_checks", new_evasion_name)
            stager_code_raw = stager_code_raw.replace("execute_simulated_payload", new_execute_name)
            log_messages.append(f"[BACKEND_METAMORPH_SUCCESS] Метаморфізм застосовано (функції: {new_decode_name}, {new_evasion_name}, {new_execute_name}).")

        final_stager_output = stager_code_raw
        if validated_params.get("output_format") == "base64_encoded_stager":
            final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
            log_messages.append("[BACKEND_FORMAT_INFO] Стейджер закодовано в Base64.")
        
        log_messages.append("[BACKEND_SUCCESS] Генерацію пейлоада завершено.")
        time.sleep(0.3) # Імітація затримки роботи сервера
        return jsonify({"success": True, "stagerCode": final_stager_output, "generationLog": "\n".join(log_messages)}), 200
    except Exception as e:
        print(f"SERVER ERROR (generate_payload): {str(e)}")
        import traceback
        traceback.print_exc()
        log_messages.append(f"[BACKEND_FATAL_ERROR] Неочікувана помилка: {str(e)}")
        return jsonify({"success": False, "error": "An unexpected server error occurred", "generationLog": "\n".join(log_messages)}), 500

@app.route('/api/run_recon', methods=['POST'])
def handle_run_recon():
    log_messages = [f"[BACKEND v{VERSION_BACKEND}] Отримано запит на /api/run_recon о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        data = request.get_json()
        if not data:
            log_messages.append("[BACKEND_ERROR] Не отримано JSON даних для розвідки.")
            return jsonify({"success": False, "error": "No JSON data received for recon", "reconLog": "\n".join(log_messages)}), 400

        target = data.get("target")
        recon_type = data.get("recon_type")
        log_messages.append(f"[BACKEND_INFO] Параметри розвідки: Ціль='{target}', Тип='{recon_type}'.")

        if not target or not recon_type:
            log_messages.append("[BACKEND_ERROR] Відсутні параметри 'target' або 'recon_type'.")
            return jsonify({"success": False, "error": "Missing target or recon_type parameters", "reconLog": "\n".join(log_messages)}), 400

        recon_results_text = ""
        recon_log_additions = []

        if recon_type == "port_scan_basic":
            recon_log_additions, recon_results_text = simulate_port_scan_be(target)
        elif recon_type == "osint_email_search":
            recon_log_additions, recon_results_text = simulate_osint_email_search_be(target)
        else:
            log_messages.append(f"[BACKEND_ERROR] Невідомий тип розвідки: {recon_type}")
            return jsonify({"success": False, "error": f"Unknown recon_type: {recon_type}", "reconLog": "\n".join(log_messages)}), 400
        
        log_messages.extend(recon_log_additions)
        time.sleep(0.7) # Імітація тривалості розвідки
        log_messages.append("[BACKEND_SUCCESS] Завдання розвідки (імітація) завершено.")

        return jsonify({
            "success": True,
            "reconResults": recon_results_text,
            "reconLog": "\n".join(log_messages)
        }), 200

    except Exception as e:
        print(f"SERVER ERROR (run_recon): {str(e)}")
        import traceback
        traceback.print_exc()
        log_messages.append(f"[BACKEND_FATAL_ERROR] Неочікувана помилка розвідки: {str(e)}")
        return jsonify({"success": False, "error": "An unexpected server error occurred during recon", "reconLog": "\n".join(log_messages)}), 500


if __name__ == '__main__':
    print("="*60)
    print(f"Syntax Framework - Концептуальний Backend v{VERSION_BACKEND}")
    print("Запуск Flask-сервера на http://localhost:5000")
    print("Доступні ендпоінти:")
    print("  POST /api/generate_payload")
    print("  POST /api/run_recon")
    print("Натисніть Ctrl+C для зупинки.")
    print("="*60)
    app.run(host='localhost', port=5000, debug=False)
