# Syntax Integrated Workflow Demonstration - Segment SIWD-MULTIARCH-1.8.0
# Призначення: Демонстрація розширеного, інтегрованого робочого процесу
#             з реалізацією різних форматів виводу для згенерованого стейджера.
#             Генерує та "виконує" різні демонстраційні пейлоади.

import json
import base64
import re
from datetime import datetime
import time 
import random 
import string 
import os 

VERSION = "1.8.0" # Оновлена версія

# --- Початок: Розширена Імітація Блоку 1 Модуля 2: Валідація Параметрів ---
# (Без змін від версії 1.7.0)
CONCEPTUAL_PARAMS_SCHEMA = {
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

def conceptual_validate_parameters(input_params: dict, schema: dict) -> tuple[bool, dict, list[str]]:
    """Розширена валідація параметрів."""
    validated_params = {}
    errors = []

    for param_name, rules in schema.items():
        if param_name in input_params:
            validated_params[param_name] = input_params[param_name]
        elif "default" in rules:
            is_conditionally_required_and_missing = callable(rules.get("required")) and \
                                                  rules["required"](input_params) and \
                                                  param_name not in input_params
            if not is_conditionally_required_and_missing:
                 validated_params[param_name] = rules["default"]

    for param_name, rules in schema.items():
        is_required_directly = rules.get("required") is True
        is_conditionally_required = callable(rules.get("required")) and rules["required"](validated_params)

        if (is_required_directly or is_conditionally_required) and param_name not in validated_params:
            errors.append(f"Відсутній обов'язковий параметр: '{param_name}' (виходячи з поточного набору параметрів).")
            continue

    for param_name, value in validated_params.items():
        if param_name not in schema: 
            continue
        rules = schema[param_name]
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
                errors.append(f"Значення '{value}' для параметра '{param_name}' не відповідає формату (regex: {rules['validation_regex']}).")
    
    return not errors, validated_params, errors
# --- Кінець: Розширена Імітація Блоку 1 Модуля 2 ---

# --- Початок: Розширена Імітація Блоку 2 Модуля 2: Вибір Архетипу ---
# (Без змін від версії 1.7.0)
CONCEPTUAL_ARCHETYPE_TEMPLATES = {
    "demo_echo_payload": {
        "description": "Демо-пейлоад, що друкує повідомлення, з розширеними перевірками на пісочницю.",
        "template_type": "python_stager_echo",
        "required_engine_params": ["message_to_echo", "obfuscation_key", "enable_evasion_checks"]
    },
    "demo_file_lister_payload": {
        "description": "Демо-пейлоад, що 'перелічує' файли, з опціональною інтеграцією перевірок ухилення.",
        "template_type": "python_stager_file_lister",
        "required_engine_params": ["directory_to_list", "obfuscation_key", "enable_evasion_checks"]
    },
    "demo_c2_beacon_payload": {
        "description": "Демо-пейлоад C2-маячка з отриманням завдань та опціональними перевірками ухилення.",
        "template_type": "python_stager_c2_beacon",
        "required_engine_params": ["c2_target_host", "c2_target_port", "obfuscation_key", "enable_evasion_checks"]
    }
}

def conceptual_select_archetype(archetype_name: str, library: dict) -> dict | None:
    """Розширений вибір архетипу."""
    if archetype_name in library:
        return library[archetype_name]
    else:
        print(f"[ARCHETYPE_SELECTOR_FAILURE] Архетип '{archetype_name}' не знайдено.")
        return None
# --- Кінець: Розширена Імітація Блоку 2 Модуля 2 ---

# --- Початок: Імітація частини Блоку 3 Модуля 2: Обфускація Даних ---
# (Без змін від версії 1.7.0)
def conceptual_xor_string(input_string: str, key: str) -> str:
    """Спрощена XOR обфускація."""
    if not key:
        raise ValueError("XOR ключ не може бути порожнім")
    output_chars = []
    for i in range(len(input_string)):
        key_char = key[i % len(key)]
        xor_char_code = ord(input_string[i]) ^ ord(key_char)
        output_chars.append(chr(xor_char_code))
    return "".join(output_chars)
# --- Кінець: Імітація частини Блоку 3 Модуля 2 ---

# --- Початок: Імітація Блоку 7 Модуля 2: Генерація Стейджера з Розширеним Метаморфізмом та Ухиленням ---
# (Шаблони та більшість логіки без змін від версії 1.7.0, зміни в apply_stager_metamorphism_and_evasion та conceptual_generate_stager)

DEFAULT_DECODE_FUNCTION_NAME = "xor_decode_generic"
EVASION_CHECK_FUNCTION_NAME = "perform_evasion_checks" 
STRING_OBFUSCATION_DECODE_FUNC_NAME = "resolve_str" 

STRINGS_TO_OBFUSCATE_IN_STAGER = [
    "sandbox", "test", "admin", "user", "vagrant", "wdagutilityaccount", "maltest", "currentuser",
    "Типове ім'я користувача пісочниці", "Виявлено підозрілий файл (імітація)",
    "Низький загальний розмір диска (імітація)", "ЙМОВІРНО ПІСОЧНИЦЯ! Виявлені індикатори:",
    "Зміна поведінки...", "Перевірка середовища: Ознак пісочниці не виявлено (розширені перевірки).",
    "ПІСОЧНИЦЯ ВИЯВЛЕНА СТЕЙДЖЕРОМ. Виведення безпечного повідомлення.",
    "Усі системи функціонують у штатному режимі. Перевірки безпеки пройдено.",
    "ПІСОЧНИЦЯ ВИЯВЛЕНА. Припинення нормальної роботи.",
    "ПІСОЧНИЦЯ ВИЯВЛЕНА. Робота в обмеженому режимі або завершення.",
    "EVASION_CHECK_TAG", "EVASION_CHECK_TAG_GENERIC", # Теги для логування
    "evasion_msg_username", "evasion_msg_susp_file", "evasion_msg_disk_size",
    "evasion_msg_sandbox_likely", "evasion_msg_behavior_change", "evasion_msg_no_sandbox",
    "evasion_msg_no_sandbox_generic", "evasion_msg_other_indicator",
    "evasion_msg_sandbox_detected_stager", "evasion_msg_safe_message",
    "evasion_msg_sandbox_detected_fl", "evasion_msg_sandbox_detected_c2"
]

CONCEPTUAL_PYTHON_ECHO_STAGER_TEMPLATE = """
# --- Початок Концептуального Ехо-Стейджера (v1.8) ---
import base64
import os 
import time 
import random 

OBFUSCATED_DATA_B64 = "{obfuscated_data_b64}" 
OBFUSCATION_KEY = "{obfuscation_key}"
PAYLOAD_TYPE = "ECHO" 
ENABLE_EVASION_CHECKS_PLACEHOLDER = {enable_evasion_checks_placeholder} 

{string_obfuscation_decoder_placeholder}

def {evasion_check_function_name}(): 
    # {random_comment_placeholder_1}
    print(f"[{STRING_OBFUSCATION_DECODE_FUNC_NAME}('EVASION_CHECK_TAG')] ({PAYLOAD_TYPE}) Виконується розширена перевірка середовища...") 
    detected_sandbox_indicators = []
    # {control_flow_obfuscation_placeholder_A1}
    try:
        common_sandbox_users = [{STRING_OBFUSCATION_DECODE_FUNC_NAME}('sandbox_user_list_item_1'), {STRING_OBFUSCATION_DECODE_FUNC_NAME}('sandbox_user_list_item_2'), {STRING_OBFUSCATION_DECODE_FUNC_NAME}('admin'), {STRING_OBFUSCATION_DECODE_FUNC_NAME}('user'), {STRING_OBFUSCATION_DECODE_FUNC_NAME}('vagrant'), {STRING_OBFUSCATION_DECODE_FUNC_NAME}('wdagutilityaccount'), {STRING_OBFUSCATION_DECODE_FUNC_NAME}('maltest'), {STRING_OBFUSCATION_DECODE_FUNC_NAME}('currentuser')] 
        current_user = os.getlogin().lower()
        # {control_flow_obfuscation_placeholder_A2}
        if current_user in common_sandbox_users:
            detected_sandbox_indicators.append(f"{{ {STRING_OBFUSCATION_DECODE_FUNC_NAME}('evasion_msg_username') }}: '{{current_user}}'")
        
        if random.random() < 0.1: 
             detected_sandbox_indicators.append({STRING_OBFUSCATION_DECODE_FUNC_NAME}('evasion_msg_susp_file'))
        # {random_comment_placeholder_2}
        if random.random() < 0.15: 
            simulated_disk_gb = random.randint(20, 55)
            detected_sandbox_indicators.append(f"{{ {STRING_OBFUSCATION_DECODE_FUNC_NAME}('evasion_msg_disk_size') }}: {{simulated_disk_gb}}GB")

    except Exception as e:
        print(f"[EVASION_CHECK_ERROR ({PAYLOAD_TYPE})] Помилка під час перевірки середовища: {{e}}")

    if detected_sandbox_indicators:
        print(f"[{STRING_OBFUSCATION_DECODE_FUNC_NAME}('EVASION_CHECK_TAG')] ({PAYLOAD_TYPE}) {{ {STRING_OBFUSCATION_DECODE_FUNC_NAME}('evasion_msg_sandbox_likely') }}")
        for indicator in detected_sandbox_indicators:
            print(f"  - {{indicator}}")
        print(f"{{ {STRING_OBFUSCATION_DECODE_FUNC_NAME}('evasion_msg_behavior_change') }}")
        return True 
    else:
        # {control_flow_obfuscation_placeholder_A3}
        print(f"[{STRING_OBFUSCATION_DECODE_FUNC_NAME}('EVASION_CHECK_TAG')] ({PAYLOAD_TYPE}) {{ {STRING_OBFUSCATION_DECODE_FUNC_NAME}('evasion_msg_no_sandbox') }}")
    return False 

def {decode_function_name}(data_b64: str, key: str) -> str: 
    # {random_comment_placeholder_3}
    decoded_data_bytes = base64.b64decode(data_b64)
    data_to_xor = decoded_data_bytes.decode('latin-1') 
    output_chars = []
    # {control_flow_obfuscation_placeholder_B1}
    for i in range(len(data_to_xor)):
        key_char = key[i % len(key)]
        xor_char_code = ord(data_to_xor[i]) ^ ord(key_char)
        output_chars.append(chr(xor_char_code))
    # {control_flow_obfuscation_placeholder_B2}
    return "".join(output_chars)

def run_payload():
    print(f"\\n[PAYLOAD_STAGER ({PAYLOAD_TYPE})] Стейджер пейлоада запущено.")
    
    sandbox_detected_by_stager = False
    # {control_flow_obfuscation_placeholder_C1}
    if ENABLE_EVASION_CHECKS_PLACEHOLDER: 
        sandbox_detected_by_stager = {evasion_check_function_name}() 
    # {control_flow_obfuscation_placeholder_C2}

    if sandbox_detected_by_stager:
        # {random_comment_placeholder_4}
        print(f"[PAYLOAD_STAGER ({PAYLOAD_TYPE})] {{ {STRING_OBFUSCATION_DECODE_FUNC_NAME}('evasion_msg_sandbox_detected_stager') }}")
        print("==================================================")
        print(f">>> Повідомлення від Пейлоада ({PAYLOAD_TYPE}): ")
        print(f">>> {{ {STRING_OBFUSCATION_DECODE_FUNC_NAME}('evasion_msg_safe_message') }}") 
        print("==================================================")
    else:
        # {control_flow_obfuscation_placeholder_C3}
        try:
            deobfuscated_content = {decode_function_name}(OBFUSCATED_DATA_B64, OBFUSCATION_KEY) 
            print(f"[PAYLOAD_STAGER ({PAYLOAD_TYPE})] Дані успішно деобфусковано.")
            print("==================================================")
            print(f">>> Повідомлення від Пейлоада ({PAYLOAD_TYPE}): ")
            print(f">>> {{deobfuscated_content}}")
            print("==================================================")
        except Exception as e:
            print(f"[PAYLOAD_STAGER_ERROR ({PAYLOAD_TYPE})] Помилка: {{e}}")
            
    print(f"[PAYLOAD_STAGER ({PAYLOAD_TYPE})] Роботу пейлоада завершено.")

if __name__ == "__main__":
    # {random_comment_placeholder_5}
    run_payload()
# --- Кінець Концептуального Ехо-Стейджера (v1.8) ---
"""

GENERIC_EVASION_FUNCTION_TEMPLATE = """
{string_obfuscation_decoder_placeholder}

def {evasion_check_function_name}(): 
    # {random_comment_placeholder_1}
    print(f"[{STRING_OBFUSCATION_DECODE_FUNC_NAME}('EVASION_CHECK_TAG_GENERIC')] Виконується загальна перевірка середовища...")
    detected_sandbox_indicators = []
    # {control_flow_obfuscation_placeholder_A1}
    try:
        common_sandbox_users = [{STRING_OBFUSCATION_DECODE_FUNC_NAME}('sandbox_user_list_item_1'), {STRING_OBFUSCATION_DECODE_FUNC_NAME}('sandbox_user_list_item_2'), {STRING_OBFUSCATION_DECODE_FUNC_NAME}('admin'), {STRING_OBFUSCATION_DECODE_FUNC_NAME}('user'), {STRING_OBFUSCATION_DECODE_FUNC_NAME}('vagrant'), {STRING_OBFUSCATION_DECODE_FUNC_NAME}('wdagutilityaccount'), {STRING_OBFUSCATION_DECODE_FUNC_NAME}('maltest'), {STRING_OBFUSCATION_DECODE_FUNC_NAME}('currentuser')]
        current_user = os.getlogin().lower()
        # {control_flow_obfuscation_placeholder_A2}
        if current_user in common_sandbox_users:
            detected_sandbox_indicators.append(f"{{ {STRING_OBFUSCATION_DECODE_FUNC_NAME}('evasion_msg_username') }}: '{{current_user}}'")
        if random.random() < 0.05: 
             detected_sandbox_indicators.append({STRING_OBFUSCATION_DECODE_FUNC_NAME}('evasion_msg_other_indicator'))
    except Exception as e:
        print(f"[EVASION_CHECK_ERROR (GENERIC)] Помилка під час перевірки середовища: {{e}}")

    if detected_sandbox_indicators:
        print(f"[{STRING_OBFUSCATION_DECODE_FUNC_NAME}('EVASION_CHECK_TAG_GENERIC')] {{ {STRING_OBFUSCATION_DECODE_FUNC_NAME}('evasion_msg_sandbox_likely') }}")
        for indicator in detected_sandbox_indicators:
            print(f"  - {{indicator}}")
        return True 
    else:
        # {control_flow_obfuscation_placeholder_A3}
        print(f"[{STRING_OBFUSCATION_DECODE_FUNC_NAME}('EVASION_CHECK_TAG_GENERIC')] {{ {STRING_OBFUSCATION_DECODE_FUNC_NAME}('evasion_msg_no_sandbox_generic') }}")
    return False
"""

CONCEPTUAL_PYTHON_FILE_LISTER_STAGER_TEMPLATE = """
# --- Початок Концептуального Стейджера для Переліку Файлів (v1.8) ---
import base64
import os 
OBFUSCATED_DATA_B64 = "{obfuscated_data_b64}"
OBFUSCATION_KEY = "{obfuscation_key}"
PAYLOAD_TYPE = "FILE_LISTER" 
ENABLE_EVASION_CHECKS_PLACEHOLDER = {enable_evasion_checks_placeholder} 

{generic_evasion_function_placeholder}
{string_obfuscation_decoder_placeholder}


def {decode_function_name}(data_b64: str, key: str) -> str: 
    # {random_comment_placeholder_1}
    decoded_data_bytes = base64.b64decode(data_b64)
    data_to_xor = decoded_data_bytes.decode('latin-1') 
    output_chars = []
    # {control_flow_obfuscation_placeholder_B1}
    for i in range(len(data_to_xor)):
        key_char = key[i % len(key)]
        xor_char_code = ord(data_to_xor[i]) ^ ord(key_char)
        output_chars.append(chr(xor_char_code))
    # {control_flow_obfuscation_placeholder_B2}
    return "".join(output_chars)

def run_payload():
    print(f"\\n[PAYLOAD_STAGER ({PAYLOAD_TYPE})] Стейджер пейлоада запущено.")
    sandbox_detected_by_stager = False
    # {control_flow_obfuscation_placeholder_C1}
    if ENABLE_EVASION_CHECKS_PLACEHOLDER:
        sandbox_detected_by_stager = {evasion_check_function_name}()
    # {control_flow_obfuscation_placeholder_C2}

    if sandbox_detected_by_stager:
        print(f"[PAYLOAD_STAGER ({PAYLOAD_TYPE})] {{ {STRING_OBFUSCATION_DECODE_FUNC_NAME}('evasion_msg_sandbox_detected_fl') }}")
    else:
        # {control_flow_obfuscation_placeholder_C3}
        try:
            target_path = {decode_function_name}(OBFUSCATED_DATA_B64, OBFUSCATION_KEY) 
            print(f"[PAYLOAD_STAGER ({PAYLOAD_TYPE})] Цільовий шлях деобфусковано: '{{target_path}}'")
            print("==================================================")
            print(f">>> Імітація переліку файлів для шляху: '{{target_path}}'")
            if target_path == ".":
                listing = ["demo_file1.txt", "demo_subdir (DIR)", "script.py"]
            elif target_path == "/tmp":
                listing = ["temp_file_abc", "session_xyz"]
            else:
                listing = ["(не вдалося отримати лістинг для цього шляху в демо)"]
            print(f">>> Лістинг: {{listing}}")
            print("==================================================")
        except Exception as e:
            print(f"[PAYLOAD_STAGER_ERROR ({PAYLOAD_TYPE})] Помилка: {{e}}")
    print(f"[PAYLOAD_STAGER ({PAYLOAD_TYPE})] Роботу пейлоада завершено.")

if __name__ == "__main__":
    # {random_comment_placeholder_5}
    run_payload()
# --- Кінець Концептуального Стейджера для Переліку Файлів (v1.8) ---
"""

CONCEPTUAL_PYTHON_C2_BEACON_STAGER_TEMPLATE = """
# --- Початок Концептуального Стейджера для C2 Маячка (v1.8) ---
import base64
import time 
import random 
import os 

OBFUSCATED_DATA_B64 = "{obfuscated_data_b64}" 
OBFUSCATION_KEY = "{obfuscation_key}"
PAYLOAD_TYPE = "C2_BEACON" 
ENABLE_EVASION_CHECKS_PLACEHOLDER = {enable_evasion_checks_placeholder}

{generic_evasion_function_placeholder}
{string_obfuscation_decoder_placeholder}

def {decode_function_name}(data_b64: str, key: str) -> str: 
    # {random_comment_placeholder_1}
    decoded_data_bytes = base64.b64decode(data_b64)
    data_to_xor = decoded_data_bytes.decode('latin-1') 
    output_chars = []
    # {control_flow_obfuscation_placeholder_B1}
    for i in range(len(data_to_xor)):
        key_char = key[i % len(key)]
        xor_char_code = ord(data_to_xor[i]) ^ ord(key_char)
        output_chars.append(chr(xor_char_code))
    # {control_flow_obfuscation_placeholder_B2}
    return "".join(output_chars)

def simulate_get_task_from_c2():
    # {random_comment_placeholder_2}
    tasks = ["run_calc", "collect_sysinfo", "download_file /etc/passwd", "sleep_300"]
    chosen_task = random.choice(tasks)
    print(f"[PAYLOAD_STAGER ({PAYLOAD_TYPE})] Імітація: Отримано завдання від C2: '{{chosen_task}}'")
    return chosen_task

def simulate_execute_task(task_string: str):
    # {random_comment_placeholder_3}
    print(f"[PAYLOAD_STAGER ({PAYLOAD_TYPE})] Імітація: Виконання завдання: '{{task_string}}'...")
    time.sleep(0.05) 
    print(f"[PAYLOAD_STAGER ({PAYLOAD_TYPE})] Імітація: Завдання '{{task_string}}' (начебто) виконано.")

def run_payload():
    print(f"\\n[PAYLOAD_STAGER ({PAYLOAD_TYPE})] Стейджер пейлоада запущено.")
    sandbox_detected_by_stager = False
    # {control_flow_obfuscation_placeholder_C1}
    if ENABLE_EVASION_CHECKS_PLACEHOLDER:
        sandbox_detected_by_stager = {evasion_check_function_name}()
    # {control_flow_obfuscation_placeholder_C2}

    if sandbox_detected_by_stager:
        print(f"[PAYLOAD_STAGER ({PAYLOAD_TYPE})] {{ {STRING_OBFUSCATION_DECODE_FUNC_NAME}('evasion_msg_sandbox_detected_c2') }}")
    else:
        # {control_flow_obfuscation_placeholder_C3}
        try:
            c2_config_str = {decode_function_name}(OBFUSCATED_DATA_B64, OBFUSCATION_KEY) 
            print(f"[PAYLOAD_STAGER ({PAYLOAD_TYPE})] Конфігурація C2 деобфускована: '{{c2_config_str}}'")
            
            print("==================================================")
            print(f">>> Імітація надсилання маячка на C2: {{c2_config_str}}")
            for i in range(1, 3): 
                print(f">>> ... Маячок #{i} надіслано (імітація) ... час: {{time.time()}}")
                if i == 1: 
                    task = simulate_get_task_from_c2()
                    simulate_execute_task(task)
                time.sleep(0.05) 
            print("==================================================")
        except Exception as e:
            print(f"[PAYLOAD_STAGER_ERROR ({PAYLOAD_TYPE})] Помилка: {{e}}")
    print(f"[PAYLOAD_STAGER ({PAYLOAD_TYPE})] Роботу пейлоада завершено.")

if __name__ == "__main__":
    # {random_comment_placeholder_5}
    run_payload()
# --- Кінець Концептуального Стейджера для C2 Маячка (v1.8) ---
"""

STAGER_TEMPLATES_BY_TYPE = {
    "python_stager_echo": CONCEPTUAL_PYTHON_ECHO_STAGER_TEMPLATE,
    "python_stager_file_lister": CONCEPTUAL_PYTHON_FILE_LISTER_STAGER_TEMPLATE,
    "python_stager_c2_beacon": CONCEPTUAL_PYTHON_C2_BEACON_STAGER_TEMPLATE
}

def generate_random_name(length=10, prefix="syn_"): 
    letters = string.ascii_lowercase + string.digits
    return prefix + ''.join(random.choice(letters) for i in range(length))

OBFUSCATED_STRINGS_MAP = {} 
_current_string_obfuscation_decode_func_name = STRING_OBFUSCATION_DECODE_FUNC_NAME # Для збереження перейменованої назви

def generate_string_obfuscation_decoder(key_for_strings: str, desired_func_name: str) -> str:
    decoder_func_code = f"""
def {desired_func_name}(obf_str_b64: str) -> str:
    key = "{key_for_strings.replace("\"", "\\\"")}" 
    try:
        decoded_bytes = base64.b64decode(obf_str_b64.encode('utf-8'))
        original_chars = []
        for i in range(len(decoded_bytes)):
            key_char_val = ord(key[i % len(key)])
            original_char_val = decoded_bytes[i] ^ key_char_val
            original_chars.append(chr(original_char_val))
        return "".join(original_chars)
    except Exception:
        return obf_str_b64 
"""
    return decoder_func_code

def obfuscate_literal_strings_in_code(code: str, strings_to_obfuscate: list, key: str, str_decode_func_name_to_use: str) -> str:
    global OBFUSCATED_STRINGS_MAP
    OBFUSCATED_STRINGS_MAP.clear() 
    
    modified_code = code
    sorted_strings = sorted(strings_to_obfuscate, key=len, reverse=True)

    for s_literal in sorted_strings:
        s_literal_escaped = re.escape(s_literal)
        
        # Обробка рядків у подвійних лапках
        pattern_double = r'(?<!{str_decode_func_name_to_use}\s*\(\s*)("{s_literal_escaped}")(?!\s*\))'
        # Обробка рядків у одинарних лапках
        pattern_single = r"(?<!{str_decode_func_name_to_use}\s*\(\s*)('{s_literal_escaped}')(?!\s*\))"

        def replace_match(match):
            original_quoted_string = match.group(1)
            original_unquoted_string = original_quoted_string[1:-1] # Видаляємо лапки
            
            obfuscated_s_xor = conceptual_xor_string(original_unquoted_string, key) 
            obfuscated_s_b64 = base64.b64encode(obfuscated_s_xor.encode('latin-1')).decode('utf-8')
            return f"{str_decode_func_name_to_use}(\"{obfuscated_s_b64}\")"

        modified_code = re.sub(pattern_double, replace_match, modified_code)
        modified_code = re.sub(pattern_single, replace_match, modified_code)
        
        # Логування, якщо заміна відбулася (перевіряємо, чи змінився код)
        # if original_code_len != len(modified_code): # Ненадійний спосіб
        # print(f"[METAMORPH_INFO] Рядок '{s_literal}' потенційно обфусковано та замінено на виклик {str_decode_func_name_to_use}.")
            
    return modified_code


def apply_stager_metamorphism_and_evasion(stager_code: str, enable_metamorphism: bool, enable_evasion: bool, obfuscation_key_for_strings: str) -> str:
    """Застосовує метаморфізм та/або ухилення до коду стейджера."""
    global _current_string_obfuscation_decode_func_name
    
    final_stager_code = stager_code
    new_evasion_func_name = EVASION_CHECK_FUNCTION_NAME 
    new_decode_func_name = DEFAULT_DECODE_FUNCTION_NAME 
    
    # 0. Встановлюємо ім'я функції деобфускації рядків (може бути перейменовано пізніше)
    _current_string_obfuscation_decode_func_name = generate_random_name(prefix="resolve_") if enable_metamorphism else STRING_OBFUSCATION_DECODE_FUNC_NAME
    
    # 1. Обробка функції деобфускації рядків
    string_decoder_code_insertion = ""
    if enable_metamorphism: 
        string_decoder_code_insertion = generate_string_obfuscation_decoder(obfuscation_key_for_strings, _current_string_obfuscation_decode_func_name)
        print(f"[METAMORPH_INFO] Функцію деобфускації рядків '{_current_string_obfuscation_decode_func_name}' підготовлено.")
    
    final_stager_code = final_stager_code.replace("{string_obfuscation_decoder_placeholder}", string_decoder_code_insertion)
    # Замінюємо плейсхолдер виклику на актуальне ім'я функції
    final_stager_code = final_stager_code.replace("STRING_OBFUSCATION_DECODE_FUNC_NAME", _current_string_obfuscation_decode_func_name)


    # 2. Обробка функції ухилення
    final_stager_code = final_stager_code.replace(
        "ENABLE_EVASION_CHECKS_PLACEHOLDER = {enable_evasion_checks_placeholder}",
        f"ENABLE_EVASION_CHECKS_PLACEHOLDER = {enable_evasion}"
    )

    if "{generic_evasion_function_placeholder}" in final_stager_code:
        if enable_evasion:
            new_evasion_func_name = generate_random_name(prefix="check_env_") if enable_metamorphism else EVASION_CHECK_FUNCTION_NAME
            
            evasion_function_code_formatted = GENERIC_EVASION_FUNCTION_TEMPLATE.replace(
                "{evasion_check_function_name}", new_evasion_func_name
            )
            # Важливо: вставляємо декодер рядків (якщо є) ТАКОЖ всередину generic evasion template, якщо він там потрібен
            evasion_function_code_formatted = evasion_function_code_formatted.replace(
                "{string_obfuscation_decoder_placeholder}", string_decoder_code_insertion # Використовуємо вже згенерований
            )
            evasion_function_code_formatted = evasion_function_code_formatted.replace("STRING_OBFUSCATION_DECODE_FUNC_NAME", _current_string_obfuscation_decode_func_name)


            for i in range(1, 4): 
                 evasion_function_code_formatted = evasion_function_code_formatted.replace(f"{{control_flow_obfuscation_placeholder_A{i}}}", f"{{control_flow_obfuscation_placeholder_A{i}}}")
            evasion_function_code_formatted = evasion_function_code_formatted.replace(f"{{random_comment_placeholder_1}}", f"{{random_comment_placeholder_1}}")

            final_stager_code = final_stager_code.replace(
                "{generic_evasion_function_placeholder}",
                evasion_function_code_formatted
            )
            print(f"[EVASION_INTEGRATION_INFO] Загальну функцію ухилення '{new_evasion_func_name}' інтегровано.")
        else:
            final_stager_code = final_stager_code.replace("{generic_evasion_function_placeholder}", "# Evasion function disabled by config")
            print(f"[EVASION_INTEGRATION_INFO] Загальну функцію ухилення видалено (вимкнено).")
    
    # Замінюємо плейсхолдери для імен функцій у всьому коді
    final_stager_code = final_stager_code.replace("{decode_function_name}", new_decode_func_name)
    final_stager_code = final_stager_code.replace("{evasion_check_function_name}", new_evasion_func_name)


    if enable_metamorphism:
        print(f"[METAMORPH_INFO] Застосування розширеного метаморфізму до стейджера...")
        
        # Обфускація рядкових літералів ДО інших перетворень, що можуть змінити їх
        final_stager_code = obfuscate_literal_strings_in_code(final_stager_code, STRINGS_TO_OBFUSCATE_IN_STAGER, obfuscation_key_for_strings, _current_string_obfuscation_decode_func_name)

        # Перейменування функцій (якщо вони ще не були перейменовані або якщо це перше перейменування)
        if f"def {new_decode_func_name}" in final_stager_code: 
            temp_new_decode_name = generate_random_name(prefix="core_decode_")
            final_stager_code = final_stager_code.replace(f"def {new_decode_func_name}", f"def {temp_new_decode_name}")
            final_stager_code = final_stager_code.replace(f"{new_decode_func_name}(", f"{temp_new_decode_name}(")
            new_decode_func_name = temp_new_decode_name 
            print(f"[METAMORPH_INFO] Функцію декодування перейменовано на '{new_decode_func_name}'.")
        
        if enable_evasion and f"def {new_evasion_func_name}" in final_stager_code:
            temp_new_evasion_name = generate_random_name(prefix="runtime_check_")
            final_stager_code = final_stager_code.replace(f"def {new_evasion_func_name}", f"def {temp_new_evasion_name}")
            final_stager_code = final_stager_code.replace(f"{new_evasion_func_name}(", f"{temp_new_evasion_name}(")
            new_evasion_func_name = temp_new_evasion_name
            print(f"[METAMORPH_INFO] Функцію ухилення перейменовано на '{new_evasion_func_name}'.")
        
        # Перейменування функції деобфускації рядків, якщо вона була вставлена
        if string_decoder_code_insertion and f"def {_current_string_obfuscation_decode_func_name}" in final_stager_code:
            # Не перейменовуємо знову, якщо вже має унікальне ім'я.
            # Або, якщо потрібно, генеруємо нове і замінюємо. Для простоти, припустимо, що _current_string_obfuscation_decode_func_name вже унікальне.
            pass 
            # print(f"[METAMORPH_INFO] Функція деобфускації рядків '{_current_string_obfuscation_decode_func_name}' залишена.")


        lines = final_stager_code.split('\n')
        transformed_lines = []
        comment_candidates = [
            "# Stage 2 Init", "# Data Integrity Verified", "# Protocol Sync v2",
            "# Buffer Status: OK", "# Loop State: RUNNING", "# Security Context Active",
            "# Timestamp: " + str(time.time()), "# Nonce ID: " + generate_random_name(12, "")
        ]
        for i in range(1, 6): 
            placeholder = f"{{random_comment_placeholder_{i}}}"
            if placeholder in final_stager_code:
                 final_stager_code = final_stager_code.replace(placeholder, random.choice(comment_candidates))
        
        lines = final_stager_code.split('\n') 
        transformed_lines_with_extra_comments = []
        for line_idx, line in enumerate(lines):
            transformed_lines_with_extra_comments.append(line)
            if random.random() < 0.08 and line.strip() and not line.strip().startswith("#"): 
                random_comment = random.choice(comment_candidates)
                leading_whitespace = line[:len(line) - len(line.lstrip())]
                transformed_lines_with_extra_comments.append(leading_whitespace + random_comment)
        final_stager_code = "\n".join(transformed_lines_with_extra_comments)
        print(f"[METAMORPH_INFO] Додано/замінено випадкові коментарі.")

        # Обфускація PAYLOAD_TYPE (залишається як є, але тепер використовує _current_string_obfuscation_decode_func_name)
        # Ця логіка тепер обробляється загальною функцією obfuscate_literal_strings_in_code
        # якщо "ECHO", "FILE_LISTER", "C2_BEACON" додати до STRINGS_TO_OBFUSCATE_IN_STAGER
        # Але для PAYLOAD_TYPE = "..." це робилося окремо. Залишимо поки що так.
        payload_type_match = re.search(r"PAYLOAD_TYPE = \"([A-Z0-9_]+)\"", final_stager_code) # Шукаємо незмінений PAYLOAD_TYPE
        if payload_type_match: 
            original_ptype = payload_type_match.group(1)
            obfuscated_ptype_var_name = generate_random_name(prefix="ptype_const_")
            obfuscated_ptype_b64 = base64.b64encode(conceptual_xor_string(original_ptype, obfuscation_key_for_strings).encode('latin-1')).decode('utf-8') # Обфускуємо XOR + B64
            
            insert_point = final_stager_code.find("import base64") 
            if insert_point != -1:
                insert_point = final_stager_code.find("\n", insert_point) + 1 
                prev_newline = final_stager_code.rfind('\n', 0, insert_point)
                current_indent = final_stager_code[prev_newline+1 : insert_point]
                current_indent = current_indent[:len(current_indent) - len(current_indent.lstrip())]
                
                # Додаємо виклик функції деобфускації для PAYLOAD_TYPE
                var_def = f"{current_indent}{obfuscated_ptype_var_name} = {_current_string_obfuscation_decode_func_name}(\"{obfuscated_ptype_b64}\")\n"
                final_stager_code = final_stager_code[:insert_point] + var_def + final_stager_code[insert_point:]
                final_stager_code = final_stager_code.replace(f"PAYLOAD_TYPE = \"{original_ptype}\"", f"PAYLOAD_TYPE = {obfuscated_ptype_var_name}")
                print(f"[METAMORPH_INFO] Рядковий літерал PAYLOAD_TYPE обфусковано через змінну '{obfuscated_ptype_var_name}' та функцію '{_current_string_obfuscation_decode_func_name}'.")


        cfo_placeholders = re.findall(r"(\{control_flow_obfuscation_placeholder_[A-Z0-9]+\})", final_stager_code)
        for placeholder in cfo_placeholders:
            indent = ""
            placeholder_pos = final_stager_code.find(placeholder)
            if placeholder_pos > 0:
                prev_newline_for_cfo = final_stager_code.rfind('\n', 0, placeholder_pos)
                if prev_newline_for_cfo == -1: prev_newline_for_cfo = -1 
                line_with_placeholder = final_stager_code[prev_newline_for_cfo+1 : placeholder_pos + len(placeholder)]
                indent = line_with_placeholder[:len(line_with_placeholder) - len(line_with_placeholder.lstrip())]

            if random.random() < 0.7: 
                cfo_block = (
                    f"{indent}# --- cfo injected start ---\n"
                    f"{indent}if {random.randint(1, 1000)}*{random.randint(1,10)} > {random.randint(-10, -1)}: # Always True\n"
                    f"{indent}    pass \n"
                    f"{indent}else:\n"
                    f"{indent}    {generate_random_name(prefix='unreachable_var_') } = {random.randint(100,200)}\n"
                    f"{indent}    pass\n"
                    f"{indent}# --- cfo injected end ---"
                )
            else: 
                cfo_block = (
                    f"{indent}# --- cfo injected start (type 2) ---\n"
                    f"{indent}cfo_temp_val_{generate_random_name(3,'v')} = {random.randint(10,20)} / {random.randint(1,5)}\n"
                    f"{indent}if cfo_temp_val_{generate_random_name(3,'v')} != {random.randint(1000,2000)} / {random.randint(1,2)}: # Always True\n"
                    f"{indent}    pass \n"
                    f"{indent}# --- cfo injected end (type 2) ---"
                )
            final_stager_code = final_stager_code.replace(placeholder, cfo_block, 1) 
        if cfo_placeholders:
            print(f"[METAMORPH_INFO] Застосовано просту обфускацію керуючого потоку (замінено {len(cfo_placeholders)} плейсхолдерів).")
        print(f"[METAMORPH_SUCCESS] Метаморфізм стейджера завершено.")
    else:
        print(f"[METAMORPH_INFO] Метаморфізм стейджера вимкнено.")
        cfo_placeholders_to_remove = re.findall(r"(\{control_flow_obfuscation_placeholder_[A-Z0-9]+\})", final_stager_code)
        for placeholder in cfo_placeholders_to_remove:
            final_stager_code = final_stager_code.replace(placeholder, f"# CFO placeholder '{placeholder}' removed (metamorphism disabled)")
        for i in range(1, 6):
            final_stager_code = final_stager_code.replace(f"{{random_comment_placeholder_{i}}}", f"# Comment placeholder {i} removed")

    # Фінальна заміна імен функцій
    final_stager_code = final_stager_code.replace("{decode_function_name}", new_decode_func_name)
    final_stager_code = final_stager_code.replace("{evasion_check_function_name}", new_evasion_func_name)
        
    return final_stager_code


def conceptual_generate_stager(obfuscated_data_for_payload: str, 
                               key: str, 
                               stager_template_content: str, 
                               apply_metamorphism: bool,
                               apply_evasion: bool) -> str:
    """Розширена генерація стейджера з опціональним метаморфізмом та ухиленням."""
    
    data_bytes = obfuscated_data_for_payload.encode('latin-1')
    data_b64 = base64.b64encode(data_bytes).decode('utf-8')
    
    stager_code_formatted_placeholders = stager_template_content.format(
        obfuscated_data_b64=data_b64, 
        obfuscation_key=key.replace("\"", "\\\""),
        decode_function_name=DEFAULT_DECODE_FUNCTION_NAME, 
        evasion_check_function_name=EVASION_CHECK_FUNCTION_NAME, 
        enable_evasion_checks_placeholder="{enable_evasion_checks_placeholder}", 
        generic_evasion_function_placeholder="{generic_evasion_function_placeholder}",
        string_obfuscation_decoder_placeholder="{string_obfuscation_decoder_placeholder}",
        random_comment_placeholder_1="{random_comment_placeholder_1}",
        random_comment_placeholder_2="{random_comment_placeholder_2}",
        random_comment_placeholder_3="{random_comment_placeholder_3}",
        random_comment_placeholder_4="{random_comment_placeholder_4}",
        random_comment_placeholder_5="{random_comment_placeholder_5}",
        control_flow_obfuscation_placeholder_A1="{control_flow_obfuscation_placeholder_A1}",
        control_flow_obfuscation_placeholder_A2="{control_flow_obfuscation_placeholder_A2}",
        control_flow_obfuscation_placeholder_A3="{control_flow_obfuscation_placeholder_A3}",
        control_flow_obfuscation_placeholder_B1="{control_flow_obfuscation_placeholder_B1}",
        control_flow_obfuscation_placeholder_B2="{control_flow_obfuscation_placeholder_B2}",
        control_flow_obfuscation_placeholder_C1="{control_flow_obfuscation_placeholder_C1}",
        control_flow_obfuscation_placeholder_C2="{control_flow_obfuscation_placeholder_C2}",
        control_flow_obfuscation_placeholder_C3="{control_flow_obfuscation_placeholder_C3}"
    )

    final_stager_code = apply_stager_metamorphism_and_evasion(stager_code_formatted_placeholders, apply_metamorphism, apply_evasion, key) 
        
    return final_stager_code
# --- Кінець: Розширена Імітація Блоку 7 Модуля 2 ---

# --- Початок: Імітація Модуля 3: "Виконання" Стейджера ---
# (Без змін від версії 1.7.0)
def simulate_stager_execution(stager_code_string: str, output_format: str):
    """Імітує виконання згенерованого стейджера, враховуючи формат виводу."""
    print("\n[EXECUTION_SIMULATOR_INFO] Імітація виконання згенерованого стейджера...")
    print(f"[EXECUTION_SIMULATOR_INFO] Формат стейджера для виконання: {output_format}")
    print("-" * 50)
    
    code_to_execute = stager_code_string
    if output_format == "base64_encoded_stager":
        try:
            print("[EXECUTION_SIMULATOR_INFO] Стейджер закодовано в Base64. Декодування...")
            code_to_execute = base64.b64decode(stager_code_string).decode('utf-8')
            print("[EXECUTION_SIMULATOR_INFO] Стейджер успішно декодовано з Base64.")
        except Exception as e:
            print(f"[EXECUTION_SIMULATOR_ERROR] Помилка декодування Base64: {e}")
            print("-" * 50)
            print("[EXECUTION_SIMULATOR_INFO] Імітацію виконання завершено з помилкою.")
            return

    try:
        local_namespace = {"__name__": "__main__"} 
        exec(code_to_execute, {}, local_namespace)
    except Exception as e:
        print(f"[EXECUTION_SIMULATOR_ERROR] Помилка під час імітації виконання стейджера: {e}")
    print("-" * 50)
    print("[EXECUTION_SIMULATOR_INFO] Імітацію виконання завершено.")
# --- Кінець: Імітація Модуля 3 ---

# --- Головна Функція Демонстрації Інтегрованого Робочого Процесу ---
def main_integrated_workflow_demo():
    """Запускає повний цикл демонстрації для різних архетипів."""
    print("=" * 70)
    print(f"Syntax Integrated Workflow Demonstration - SIWD-MULTIARCH-{VERSION}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    test_scenarios = [
        {
            "scenario_name": "Ехо-Пейлоад (Raw Output, Повний Метаморфізм + Ухилення + Обфускація Рядків)",
            "params": {
                "payload_archetype": "demo_echo_payload",
                "message_to_echo": "Ехо з усіма фічами! Syntax v1.8 (Raw).",
                "obfuscation_key": "КлючЕхоВсеВключеноRaw",
                "enable_stager_metamorphism": True,
                "enable_evasion_checks": True,
                "output_format": "raw_python_stager"
            }
        },
        {
            "scenario_name": "Ехо-Пейлоад (Base64 Output, Повний Метаморфізм + Ухилення)",
            "params": {
                "payload_archetype": "demo_echo_payload",
                "message_to_echo": "Ехо з усіма фічами! Syntax v1.8 (Base64).",
                "obfuscation_key": "КлючЕхоВсеВключеноB64",
                "enable_stager_metamorphism": True,
                "enable_evasion_checks": True,
                "output_format": "base64_encoded_stager"
            }
        },
        {
            "scenario_name": "Перелік Файлів (Raw Output, Лише Ухилення)",
            "params": {
                "payload_archetype": "demo_file_lister_payload",
                "directory_to_list": "/usr/bin",
                "obfuscation_key": "КлючЛістингУхиленняRaw",
                "enable_stager_metamorphism": False, 
                "enable_evasion_checks": True,
                "output_format": "raw_python_stager"
            }
        },
        {
            "scenario_name": "C2 Маячок (Base64 Output, Лише Метаморфізм)",
            "params": {
                "payload_archetype": "demo_c2_beacon_payload",
                "c2_target_host": "c2-final.syntax-net.local",
                "c2_target_port": 8888,
                "obfuscation_key": "КлючC2МетаB64Фінал",
                "enable_stager_metamorphism": True,
                "enable_evasion_checks": False,
                "output_format": "base64_encoded_stager" 
            }
        }
    ]

    for scenario_idx, scenario in enumerate(test_scenarios):
        print(f"\n\n--- ЗАПУСК СЦЕНАРІЮ #{scenario_idx + 1}: {scenario['scenario_name']} ---")
        payload_params = scenario["params"]
        print(f"[WORKFLOW_INFO] Початкові параметри пейлоада: {payload_params}")

        is_valid, validated_params, errors = conceptual_validate_parameters(payload_params, CONCEPTUAL_PARAMS_SCHEMA)
        if not is_valid:
            print("[VALIDATOR_FAILURE] Помилки валідації:")
            for err_idx, err in enumerate(errors):
                print(f"  Помилка #{err_idx+1}: {err}")
            print("[WORKFLOW_FAILURE] Неможливо продовжити через помилки валідації.")
            continue 

        print(f"[VALIDATOR_SUCCESS] Валідація параметрів для '{scenario['scenario_name']}' успішна.")
        archetype_details = conceptual_select_archetype(validated_params["payload_archetype"], CONCEPTUAL_ARCHETYPE_TEMPLATES)
        if not archetype_details:
            print("[WORKFLOW_FAILURE] Неможливо продовжити через помилку вибору архетипу.")
            continue
        
        print(f"[ARCHETYPE_SELECTOR_SUCCESS] Архетип '{validated_params['payload_archetype']}' обрано. Опис: {archetype_details['description']}")

        data_to_obfuscate = ""
        archetype_name = validated_params["payload_archetype"]

        if archetype_name == "demo_echo_payload":
            data_to_obfuscate = validated_params["message_to_echo"]
        elif archetype_name == "demo_file_lister_payload":
            data_to_obfuscate = validated_params["directory_to_list"]
        elif archetype_name == "demo_c2_beacon_payload":
            data_to_obfuscate = f"{validated_params['c2_target_host']}:{validated_params['c2_target_port']}"
        
        key = validated_params["obfuscation_key"]
        obfuscated_data = conceptual_xor_string(data_to_obfuscate, key)

        stager_template_key = archetype_details.get("template_type")
        apply_metamorphism_flag = validated_params.get("enable_stager_metamorphism", False)
        apply_evasion_flag = validated_params.get("enable_evasion_checks", False)
        output_format_selected = validated_params.get("output_format", "raw_python_stager")


        if stager_template_key and stager_template_key in STAGER_TEMPLATES_BY_TYPE:
            stager_template_content = STAGER_TEMPLATES_BY_TYPE[stager_template_key]
            print(f"[STAGER_GENERATOR_INFO] Генерація стейджера типу '{stager_template_key}' (Метаморфізм: {'Увімкнено' if apply_metamorphism_flag else 'Вимкнено'}, Ухилення: {'Увімкнено' if apply_evasion_flag else 'Вимкнено'}, Формат: {output_format_selected})...")
            stager_script_code_raw = conceptual_generate_stager(obfuscated_data, key, stager_template_content, apply_metamorphism_flag, apply_evasion_flag)
            
            final_stager_output = stager_script_code_raw
            if output_format_selected == "base64_encoded_stager":
                final_stager_output = base64.b64encode(stager_script_code_raw.encode('utf-8')).decode('utf-8')
                print(f"[STAGER_GENERATOR_INFO] Стейджер закодовано в Base64 (довжина закодованого: {len(final_stager_output)}).")
            
            if scenario_idx == 0 : 
                print(f"\n[DEBUG] Згенерований стейджер для першого сценарію (формат: {output_format_selected}):\n{final_stager_output[:600]}...\n") # Друкуємо частину
        else:
            print(f"[WORKFLOW_FAILURE] Не знайдено або не визначено шаблон стейджера ('{stager_template_key}') для архетипу '{archetype_name}'.")
            continue
            
        simulate_stager_execution(final_stager_output, output_format_selected)
    
    print("\n" + "=" * 70)
    print("[WORKFLOW_SUCCESS] Усі демонстраційні сценарії інтегрованого робочого процесу завершено.")
    print("=" * 70)

if __name__ == "__main__":
    main_integrated_workflow_demo()
