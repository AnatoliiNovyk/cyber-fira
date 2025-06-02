# reconnaissance/logic.py
# Основна логіка для модуля розвідки

import json
import re
import random
import time
from datetime import datetime
import subprocess
import shlex
import xml.etree.ElementTree as ET
import requests # Для NVD API

# Імпорти з кореневих файлів проекту
import config # Доступ до NVD_API_BASE_URL, MOCK_EXTERNAL_CVE_API_DB, etc.
from utils import get_service_name_be # Допоміжні функції

# --- Логіка для симуляції базових сканувань (перенесено з app.py) ---
def simulate_port_scan_logic(target: str, log_messages: list) -> str:
    """Імітує базове сканування портів."""
    log_messages.append(f"[RECON_LOGIC_SIM_PORT] Імітація сканування портів для: {target}")
    results_text_lines = [f"Результати імітації сканування портів для: {target}"]
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 8000, 8080, 8443]
    open_ports_found = []
    for port in common_ports:
        # time.sleep(random.uniform(0.01, 0.05)) # Імітація затримки (можна прибрати для швидкості)
        if random.random() < 0.3: 
            service_name = get_service_name_be(port) # Використовуємо get_service_name_be з utils
            banner = ""
            if random.random() < 0.6: 
                banner_version = f"v{random.randint(1,5)}.{random.randint(0,9)}"
                possible_banners = [f"OpenSSH_{banner_version}", f"Apache httpd {banner_version}", f"Microsoft-IIS/{banner_version}", "nginx", f"ProFTPD {banner_version}", f"vsftpd {banner_version}", f"MySQL {banner_version}", f"PostgreSQL {banner_version}"]
                banner = f" (Banner: {random.choice(possible_banners)})"
            open_ports_found.append(f"  Порт {port} ({service_name}): ВІДКРИТО{banner}")
    if open_ports_found: results_text_lines.extend(open_ports_found)
    else: results_text_lines.append("  Відкритих поширених портів не знайдено (імітація).")
    log_messages.append("[RECON_LOGIC_SIM_PORT_SUCCESS] Імітацію сканування портів завершено.")
    return "\n".join(results_text_lines)

def simulate_osint_email_search_logic(target_domain: str, log_messages: list) -> str:
    """Імітує OSINT пошук email для домену."""
    log_messages.append(f"[RECON_LOGIC_SIM_EMAIL] Імітація OSINT пошуку email для: {target_domain}")
    results_text_lines = [f"Результати імітації OSINT пошуку Email для домену: {target_domain}"]
    domain_parts = target_domain.split('.')
    main_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else target_domain # >=2 для example.com
    common_names = ["info", "support", "admin", "contact", "sales", "hr", "abuse", "webmaster", "dev", "test"]
    first_names = ["john.doe", "jane.smith", "peter.jones", "susan.lee", "michael.brown", "alex.williams", "david.miller"]
    found_emails = set() # Використовуємо set для унікальності
    for _ in range(random.randint(2, 6)): 
        email_prefix = random.choice(common_names) if random.random() < 0.6 else random.choice(first_names)
        email = f"{email_prefix}@{main_domain}"
        found_emails.add(email)
    if found_emails: results_text_lines.extend([f"  Знайдено Email: {email}" for email in sorted(list(found_emails))])
    else: results_text_lines.append("  Email-адрес не знайдено (імітація).")
    log_messages.append("[RECON_LOGIC_SIM_EMAIL_SUCCESS] Імітацію OSINT пошуку email завершено.")
    return "\n".join(results_text_lines)

def simulate_osint_subdomain_search_logic(target_domain: str, log_messages: list) -> str:
    """Імітує OSINT пошук субдоменів."""
    log_messages.append(f"[RECON_LOGIC_SIM_SUBDOMAIN] Імітація OSINT пошуку субдоменів для: {target_domain}")
    results_text_lines = [f"Результати імітації OSINT пошуку Субдоменів для домену: {target_domain}"]
    cleaned_domain = re.sub(r"^(www|ftp|mail)\.", "", target_domain, flags=re.IGNORECASE)
    common_subdomains_prefixes = [
        "www", "mail", "ftp", "webmail", "cpanel", "blog", "dev", "stage", "test", "api", "shop", "store", 
        "secure", "vpn", "remote", "portal", "owa", "autodiscover", "admin", "dashboard", "app", "beta", 
        "alpha", "db", "assets", "static", "cdn", "intranet", "support", "helpdesk", "status", "git", 
        "svn", "m", "mta", "ns1", "ns2", "owa", "vpn2", "devops", "staging", "backup"
    ]
    found_subdomains_list = set()
    for sub_prefix in common_subdomains_prefixes:
        if random.random() < 0.18: # Зменшено ймовірність для більш реалістичного вигляду
            found_subdomains_list.add(f"{sub_prefix}.{cleaned_domain}")
    for _ in range(random.randint(0, 3)): # Додамо кілька більш "складних"
        p1 = random.choice(["data", "svc", "internal", "ext", "prod", "dev-app", "user", "sys", "app-test"])
        p2 = random.choice(["01", "02", "new", "old", "v2", str(random.randint(1,5))])
        if random.random() < 0.5: found_subdomains_list.add(f"{p1}-{p2}.{cleaned_domain}")
        else: found_subdomains_list.add(f"{p1}{random.randint(1,9)}.{cleaned_domain}")
    
    if not found_subdomains_list and cleaned_domain: # Гарантуємо хоча б щось
        found_subdomains_list.add(f"www.{cleaned_domain}")
        if random.random() > 0.3 : found_subdomains_list.add(f"mail.{cleaned_domain}")

    if found_subdomains_list:
        results_text_lines.extend([f"  Знайдено Субдомен: {sub}" for sub in sorted(list(found_subdomains_list))])
    else:
        results_text_lines.append(f"  Субдоменів для '{cleaned_domain}' не знайдено (імітація).")
    log_messages.append("[RECON_LOGIC_SIM_SUBDOMAIN_SUCCESS] Імітацію OSINT пошуку субдоменів завершено.")
    return "\n".join(results_text_lines)

# --- Логіка для Nmap та CVE (перенесено та адаптовано з app.py v1.9.8) ---
def parse_nmap_xml_output_logic(nmap_xml_output: str, log_messages: list) -> tuple[list[dict], list[dict]]:
    """Парсить XML-вивід nmap для отримання інформації про хости, сервіси, ОС та результати скриптів."""
    # Ця функція розбирає XML, згенерований nmap з опцією -oX,
    # та витягує структуровані дані про відкриті порти, сервіси, версії,
    # визначення ОС та результати виконання NSE-скриптів.
    # Замість log_messages.append використовуйте переданий список log_messages
    # Наприклад: log_messages.append("[NMAP_XML_PARSE_LOGIC_INFO] Початок парсингу XML-виводу nmap.")
    parsed_services = []
    parsed_os = []
    try:
        log_messages.append("[NMAP_XML_PARSE_LOGIC_INFO] Початок парсингу XML-виводу nmap.")
        if not nmap_xml_output.strip():
            log_messages.append("[NMAP_XML_PARSE_LOGIC_WARN] XML-вивід порожній.")
            return parsed_services, parsed_os
        root = ET.fromstring(nmap_xml_output)
        for host_node in root.findall('host'):
            address_node = host_node.find('address')
            host_ip = address_node.get('addr') if address_node is not None else "N/A"
            
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
                    parsed_os.append({
                        "host_ip": host_ip, "name": os_name, "accuracy": accuracy,
                        "family": os_family, "generation": os_gen, "cpes": os_cpes
                    })
                    log_messages.append(f"[NMAP_XML_PARSE_LOGIC_OS] Знайдено ОС: {os_name} (Точність: {accuracy}) для хоста {host_ip}")

            ports_node = host_node.find('ports')
            if ports_node is None: continue
            for port_node in ports_node.findall('port'):
                state_node = port_node.find('state')
                if state_node is None or state_node.get('state') != 'open': continue
                port_id = port_node.get('portid')
                protocol = port_node.get('protocol')
                service_node = port_node.find('service')
                service_name = service_node.get('name', 'unknown') if service_node is not None else 'unknown'
                product_name = service_node.get('product', '') if service_node is not None else ''
                version_number = service_node.get('version', '') if service_node is not None else ''
                extrainfo = service_node.get('extrainfo', '') if service_node is not None else ''
                service_cpes = [cpe.text for cpe in service_node.findall('cpe') if service_node is not None and cpe.text]
                
                scripts_output = []
                for script_node in port_node.findall('script'):
                    script_id = script_node.get('id', 'N/A')
                    script_data = script_node.get('output', '')
                    structured_script_data = {elem.get('key'): elem.text for elem in script_node.findall('elem') if elem.get('key')}
                    tables_data = [{elem.get('key'): elem.text for elem in table_node.findall('elem') if elem.get('key')} for table_node in script_node.findall('table')]
                    
                    scripts_output.append({"id": script_id, "output": script_data, "structured_data": structured_script_data, "tables": tables_data})
                    log_messages.append(f"[NMAP_XML_PARSE_LOGIC_SCRIPT] Знайдено скрипт '{script_id}' для порту {port_id} на {host_ip}.")

                version_info_parts = [product_name, version_number, extrainfo]
                version_info_full = " ".join(part for part in version_info_parts if part).strip() or service_name
                
                service_key_for_cve = product_name.lower().strip() if product_name else service_name.lower().strip()
                if version_number: service_key_for_cve += f" {version_number.lower().strip()}"
                elif not product_name and service_name != 'unknown' and extrainfo:
                     version_match_extra = re.search(r"(\d+\.[\d\.\w-]+)", extrainfo)
                     if version_match_extra: service_key_for_cve += f" {version_match_extra.group(1).lower().strip()}"

                parsed_services.append({
                    "host_ip": host_ip, "port": port_id, "protocol": protocol, "service_name": service_name, 
                    "product": product_name, "version_number": version_number, "extrainfo": extrainfo,
                    "version_info_full": version_info_full, "cpes": service_cpes,
                    "service_key_for_cve": service_key_for_cve.strip(), "scripts": scripts_output
                })
        
        for host_node in root.findall('host'): # Обробка hostscript
            host_ip = host_node.find('address').get('addr') if host_node.find('address') is not None else "N/A"
            hostscript_node = host_node.find('hostscript')
            if hostscript_node:
                host_scripts_output = []
                for script_node in hostscript_node.findall('script'):
                    # ... (аналогічно до парсингу скриптів порту) ...
                    script_id = script_node.get('id', 'N/A')
                    script_data = script_node.get('output', '')
                    structured_script_data = {elem.get('key'): elem.text for elem in script_node.findall('elem') if elem.get('key')}
                    tables_data = [{elem.get('key'): elem.text for elem in table_node.findall('elem') if elem.get('key')} for table_node in script_node.findall('table')]
                    host_scripts_output.append({"id": script_id, "output": script_data, "structured_data": structured_script_data, "tables": tables_data})
                    log_messages.append(f"[NMAP_XML_PARSE_LOGIC_HOSTSCRIPT] Знайдено хост-скрипт '{script_id}' для {host_ip}.")

                os_info_entry = next((os_info for os_info in parsed_os if os_info["host_ip"] == host_ip), None)
                if os_info_entry:
                    os_info_entry.setdefault("host_scripts", []).extend(host_scripts_output)
                elif host_scripts_output: 
                    parsed_os.append({"host_ip": host_ip, "name": "N/A (Host Scripts Only)", "accuracy": "N/A", "family": "", "generation": "", "cpes": [], "host_scripts": host_scripts_output})
        log_messages.append(f"[NMAP_XML_PARSE_LOGIC_SUCCESS] Успішно розпарсено XML, знайдено {len(parsed_services)} сервісів та {len(parsed_os)} записів ОС/хост-скриптів.")
    except ET.ParseError as e_parse:
        log_messages.append(f"[NMAP_XML_PARSE_LOGIC_ERROR] Помилка парсингу XML: {e_parse}")
    except Exception as e_generic:
        log_messages.append(f"[NMAP_XML_PARSE_LOGIC_FATAL] Непередбачена помилка під час парсингу XML: {e_generic}")
    return parsed_services, parsed_os


def fetch_cves_from_nvd_api_logic(service_key_raw: str, service_cpes: list, log_messages: list) -> list[dict]:
    """Отримує дані CVE з NVD API 2.0."""
    # Ця функція формує запити до NVD API на основі CPE або ключових слів сервісу,
    # отримує інформацію про вразливості (CVE), включаючи опис, рейтинг CVSS,
    # дати публікації/модифікації та посилання.
    # Використовуйте config.NVD_API_BASE_URL, config.NVD_API_KEY (якщо є), config.NVD_REQUEST_TIMEOUT_SECONDS, config.NVD_RESULTS_PER_PAGE
    nvd_cves_found = []
    headers = {}
    nvd_api_key_val = config.NVD_API_KEY # Якщо NVD_API_KEY визначено в config.py
    if nvd_api_key_val:
        headers['apiKey'] = nvd_api_key_val
        log_messages.append("[NVD_API_LOGIC_INFO] Використовується NVD API ключ.")
    else:
        log_messages.append("[NVD_API_LOGIC_WARN] NVD API ключ не надано. Можливі обмеження частоти запитів.")

    search_terms = []
    if service_cpes:
        for cpe in service_cpes:
            search_terms.append({'type': 'cpeName', 'value': cpe})
    if service_key_raw and not service_cpes: # Шукаємо за ключовим словом, якщо CPE немає або вони не дали результату
         search_terms.append({'type': 'keywordSearch', 'value': service_key_raw, 'exactMatch': True}) # Спробуємо точний збіг спочатку
         search_terms.append({'type': 'keywordSearch', 'value': service_key_raw}) # Потім неточний

    for term in search_terms:
        params = {term['type']: term['value'], 'resultsPerPage': config.NVD_RESULTS_PER_PAGE}
        if term['type'] == 'keywordSearch' and term.get('exactMatch'):
            params['keywordExactMatch'] = '' # Додаємо параметр для точного збігу

        log_messages.append(f"[NVD_API_LOGIC_INFO] Запит до NVD API за {term['type']}: '{term['value']}'.")
        try:
            response = requests.get(config.NVD_API_BASE_URL, headers=headers, params=params, timeout=config.NVD_REQUEST_TIMEOUT_SECONDS)
            response.raise_for_status()
            data = response.json()
            total_results = data.get('totalResults', 0)
            log_messages.append(f"[NVD_API_LOGIC_RESPONSE] Отримано {len(data.get('vulnerabilities', []))} з {total_results} для {term['type']} '{term['value']}'.")

            for vuln in data.get('vulnerabilities', []):
                cve_item = vuln.get('cve', {})
                cve_id = cve_item.get('id')
                description = next((d.get('value') for d in cve_item.get('descriptions', []) if d.get('lang') == 'en'), "N/A")
                
                severity, cvss_score, cvss_vector, cvss_version = "UNKNOWN", None, None, None
                metrics = cve_item.get('metrics', {})
                cvss_data_list = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', metrics.get('cvssMetricV2', [])))
                if cvss_data_list:
                    cvss_data_item = cvss_data_list[0].get('cvssData', {})
                    severity = cvss_data_list[0].get('baseSeverity', cvss_data_item.get('baseSeverity', severity)) # Для v2 baseSeverity в cvssData
                    cvss_score = cvss_data_item.get('baseScore')
                    cvss_vector = cvss_data_item.get('vectorString')
                    cvss_version = cvss_data_item.get('version', "2.0" if 'cvssMetricV2' in metrics else None)
                
                references = [ref.get('url') for ref in cve_item.get('references', []) if ref.get('url')]
                vulnerable_configs_cpe = []
                if cve_item.get('configurations'):
                    for node_config in cve_item.get('configurations'):
                        for node_item in node_config.get('nodes', []):
                            for cpe_match_item in node_item.get('cpeMatch', []):
                                if cpe_match_item.get('vulnerable') and cpe_match_item.get('criteria'):
                                    vulnerable_configs_cpe.append(cpe_match_item.get('criteria'))
                
                nvd_cves_found.append({
                    "cve_id": cve_id, "summary": description, "severity": severity.upper() if severity else "UNKNOWN",
                    "cvss_score": cvss_score, "cvss_vector": cvss_vector, "cvss_version": cvss_version,
                    "published_date": cve_item.get('published'), "last_modified_date": cve_item.get('lastModified'),
                    "vulnerable_configurations_cpe": vulnerable_configs_cpe, "references": references, "source": f"NVD API ({term['type']})"
                })
            if nvd_cves_found and term['type'] == 'cpeName': break # Якщо знайшли по CPE, не шукаємо далі за ключовими словами для цього сервісу
            if nvd_cves_found and term.get('exactMatch'): break # Якщо знайшли по точному ключовому слову

            time.sleep(0.7) # Затримка між запитами
        except requests.exceptions.RequestException as e_req: log_messages.append(f"[NVD_API_LOGIC_ERROR] Запит для {term['type']} '{term['value']}': {e_req}")
        except json.JSONDecodeError as e_json: log_messages.append(f"[NVD_API_LOGIC_ERROR] JSON для {term['type']} '{term['value']}': {e_json}")
        except Exception as e_generic: log_messages.append(f"[NVD_API_LOGIC_FATAL] Обробка {term['type']} '{term['value']}': {e_generic}")
    
    unique_cves_from_nvd = {cve['cve_id']: cve for cve in nvd_cves_found}.values() # Дедуплікація
    log_messages.append(f"[NVD_API_LOGIC_SUCCESS] NVD API повернув {len(unique_cves_from_nvd)} унікальних CVE.")
    return list(unique_cves_from_nvd)


def conceptual_cve_lookup_logic(services_info: list, log_messages: list) -> list[dict]:
    """Виконує пошук CVE, використовуючи NVD API та резервні бази."""
    # Ця функція агрегує пошук CVE з різних джерел:
    # 1. Спочатку запитує NVD API (через fetch_cves_from_nvd_api_logic).
    # 2. Потім перевіряє внутрішні мок-бази (MOCK_EXTERNAL_CVE_API_DB, CONCEPTUAL_CVE_DATABASE_BE) для повноти.
    found_cves_overall = []
    processed_cve_ids = set()
    log_messages.append(f"[CVE_LOOKUP_LOGIC_INFO] Пошук CVE для {len(services_info)} сервісів.")

    for service_item in services_info:
        service_key_raw = service_item.get("service_key_for_cve", "").lower().strip()
        service_cpes_list = service_item.get("cpes", [])
        host_ip_for_cve = service_item.get("host_ip")
        port_for_cve = service_item.get("port")

        if not service_key_raw and not service_cpes_list:
            log_messages.append(f"[CVE_LOOKUP_LOGIC_WARN] Пропущено сервіс (порт {port_for_cve}) через порожній ключ CVE та відсутність CPE.")
            continue

        # 1. NVD API
        log_messages.append(f"[CVE_LOOKUP_LOGIC_NVD_ATTEMPT] Запит до NVD API для '{service_key_raw}' (CPEs: {service_cpes_list}).")
        cves_from_nvd = fetch_cves_from_nvd_api_logic(service_key_raw, service_cpes_list, log_messages)
        for cve_nvd in cves_from_nvd:
            if cve_nvd['cve_id'] not in processed_cve_ids:
                found_cves_overall.append({"host_ip": host_ip_for_cve, "port": port_for_cve, "service_key": service_key_raw, "matched_db_key": service_key_raw, **cve_nvd})
                processed_cve_ids.add(cve_nvd['cve_id'])
                log_messages.append(f"  [NVD_LOGIC_HIT] {cve_nvd['cve_id']} ({cve_nvd['severity']})")
        
        # 2. MOCK_EXTERNAL_CVE_API_DB
        mock_api_cves_found = [cve for db_key, cves in config.MOCK_EXTERNAL_CVE_API_DB.items() if service_key_raw == db_key or service_key_raw.startswith(db_key.split(' ')[0]) and service_key_raw.split(' ')[0] in db_key for cve in cves]
        for cve_mock in mock_api_cves_found:
            if cve_mock['cve_id'] not in processed_cve_ids:
                found_cves_overall.append({"host_ip": host_ip_for_cve, "port": port_for_cve, "service_key": service_key_raw, "matched_db_key": service_key_raw, **cve_mock, **{k:None for k in ["cvss_score","cvss_vector","cvss_version","published_date","last_modified_date","vulnerable_configurations_cpe","references"] if k not in cve_mock}})
                processed_cve_ids.add(cve_mock['cve_id'])
                log_messages.append(f"  [MOCK_DB_LOGIC_HIT] {cve_mock['cve_id']} ({cve_mock['severity']})")

        # 3. CONCEPTUAL_CVE_DATABASE_BE
        internal_db_cves_found = config.CONCEPTUAL_CVE_DATABASE_BE.get(service_key_raw, [])
        for cve_internal in internal_db_cves_found:
            if cve_internal['cve_id'] not in processed_cve_ids:
                found_cves_overall.append({"host_ip": host_ip_for_cve, "port": port_for_cve, "service_key": service_key_raw, "matched_db_key": service_key_raw, **cve_internal, "source": "Internal Fallback DB", **{k:None for k in ["cvss_score","cvss_vector","cvss_version","published_date","last_modified_date","vulnerable_configurations_cpe","references"] if k not in cve_internal}})
                processed_cve_ids.add(cve_internal['cve_id'])
                log_messages.append(f"  [INTERNAL_DB_LOGIC_HIT] {cve_internal['cve_id']} ({cve_internal['severity']})")

    log_messages.append(f"[CVE_LOOKUP_LOGIC_SUCCESS] Загалом знайдено {len(found_cves_overall)} унікальних CVE.")
    return found_cves_overall


def perform_nmap_scan_logic(target: str, options: list = None, use_xml_output: bool = False, recon_type_hint: str = None, log_messages: list = None) -> tuple[str, list[dict], list[dict]]:
    """Виконує сканування Nmap з заданими опціями."""
    # Ця функція будує та виконує команду nmap, обробляє її вивід.
    # Вона намагається валідувати та фільтрувати опції для безпеки та коректності.
    # Використовуйте переданий log_messages, викликайте parse_nmap_xml_output_logic
    if log_messages is None: log_messages = [] # Ініціалізація, якщо не передано
    log_messages.append(f"[RECON_NMAP_LOGIC_INFO] Запуск nmap для: {target}, опції: {options}, XML: {use_xml_output}, Тип: {recon_type_hint}")
    base_command = ["nmap"] # Можна винести в config.py, якщо шлях до nmap інший
    effective_options = list(options) if options else []

    if use_xml_output:
        if not any("-oX" in opt for opt in effective_options): effective_options.extend(["-oX", "-"])
        if not any("-sV" in opt for opt in effective_options): effective_options.append("-sV")
        if not any(opt in effective_options for opt in ["-O", "-A"]): effective_options.append("-O")
    
    if recon_type_hint == "port_scan_nmap_vuln_scripts" and not options:
        effective_options.extend(["-sV", "--script", "vuln", "-Pn"])
        log_messages.append("[RECON_NMAP_LOGIC_INFO] Використання дефолтних опцій для vuln_scripts: -sV --script vuln -Pn")
        if not any("-oX" in opt for opt in effective_options): effective_options.extend(["-oX", "-"])
    elif not effective_options:
        effective_options = ["-sV", "-T4", "-Pn"] if not use_xml_output else ["-sV", "-O", "-T4", "-Pn", "-oX", "-"]

    # Фільтрація та валідація опцій nmap (спрощена, можна розширити)
    allowed_options_prefixes = ["-sV", "-Pn", "-T4", "-p", "-F", "-A", "-O", "--top-ports", "-sS", "-sU", "-sC", "-oX", "-oN", "-oG", "-iL", "--script", "--script-args", "-n", "-v", "-PE", "-PP", "-PS", "-PA", "-PU", "-PY", "-g", "--data-length", "--max-retries", "--host-timeout", "--scan-delay"]
    final_command_parts = [base_command[0]]
    
    # Складніша логіка обробки опцій, щоб уникнути дублікатів та правильно обробляти аргументи
    processed_opts_args = []
    skip_next = False
    for i, opt_part in enumerate(effective_options):
        if skip_next:
            skip_next = False
            continue
        
        is_allowed_prefix_match = any(opt_part.startswith(p) for p in allowed_options_prefixes)
        
        if is_allowed_prefix_match:
            processed_opts_args.append(opt_part)
            # Якщо опція вимагає аргументу і наступний елемент не є новою опцією
            if opt_part in ["-p", "--top-ports", "-oX", "-oN", "-oG", "-iL", "--script", "--script-args", "-g"] and (i + 1) < len(effective_options):
                next_opt_part = effective_options[i+1]
                if not any(next_opt_part.startswith(p) for p in allowed_options_prefixes if p != next_opt_part): # Дозволяємо аргументи типу "-"
                    processed_opts_args.append(next_opt_part)
                    skip_next = True
        elif opt_part: # Якщо це не порожній рядок і не опція, вважаємо аргументом для попередньої (якщо вона його очікує)
            if processed_opts_args and processed_opts_args[-1] in ["-p", "--top-ports", "-oX", "-oN", "-oG", "-iL", "--script", "--script-args", "-g"]:
                 processed_opts_args.append(opt_part)
            else:
                 log_messages.append(f"[RECON_NMAP_LOGIC_WARN] Недозволена або невідома опція/аргумент nmap: {opt_part}")
        
    final_command_parts.extend(processed_opts_args)
    final_command_parts.append(target)
    log_messages.append(f"[RECON_NMAP_LOGIC_CMD_FINAL] Команда nmap: {' '.join(final_command_parts)}")

    parsed_services_list, parsed_os_list, raw_output_text = [], [], ""
    try:
        process = subprocess.run(final_command_parts, capture_output=True, text=True, timeout=600, check=False, encoding='utf-8', errors='ignore')
        raw_output_text = process.stdout if process.returncode == 0 or process.stdout else process.stderr # Пріоритет stdout, якщо є
        if process.returncode == 0 or (process.returncode != 0 and "Host seems down" not in raw_output_text and "Failed to resolve" not in raw_output_text): # Деякі помилки nmap все одно дають XML
            log_messages.append(f"[RECON_NMAP_LOGIC_STATUS] Nmap завершено (код: {process.returncode}).")
            if any("-oX" in opt and "-" in final_command_parts for opt in final_command_parts): # Перевірка, чи був запит на XML в stdout
                parsed_services_list, parsed_os_list = parse_nmap_xml_output_logic(process.stdout, log_messages) # Парсимо stdout, де очікується XML
                log_messages.append(f"[RECON_NMAP_LOGIC_PARSE_XML] Знайдено {len(parsed_services_list)} сервісів та {len(parsed_os_list)} записів ОС/хост-скриптів з XML.")
        else:
            error_message = f"Помилка виконання Nmap (код: {process.returncode}): {raw_output_text}"
            log_messages.append(f"[RECON_NMAP_LOGIC_ERROR] {error_message}")
            if "Host seems down" in raw_output_text: raw_output_text += "\nПідказка: Ціль може бути недоступна або блокувати ping. Спробуйте опцію -Pn."
            elif " consentement explicite" in raw_output_text or "explicit permission" in raw_output_text: raw_output_text += "\nПОПЕРЕДЖЕННЯ NMAP: Сканування мереж без явного дозволу є незаконним."
    except FileNotFoundError:
        log_messages.append("[RECON_NMAP_LOGIC_ERROR] Команду nmap не знайдено.")
        raw_output_text = "Помилка: nmap не встановлено або не знайдено в системному PATH."
    except subprocess.TimeoutExpired:
        log_messages.append("[RECON_NMAP_LOGIC_ERROR] Час очікування nmap сканування вичерпано.")
        raw_output_text = f"Помилка: Час очікування сканування nmap для {target} вичерпано."
    except Exception as e:
        log_messages.append(f"[RECON_NMAP_LOGIC_FATAL] Непередбачена помилка: {str(e)}")
        raw_output_text = f"Непередбачена помилка під час nmap сканування: {str(e)}"
    
    return raw_output_text, parsed_services_list, parsed_os_list


# Основна функція-обробник для модуля розвідки
def handle_run_recon_logic(request_data: dict, log_messages_main: list) -> tuple[dict, int]:
    """
    Обробляє запит на виконання операцій розвідки.
    """
    log_messages = list(log_messages_main)
    log_messages.append(f"[RECON_LOGIC_INFO] Початок обробки запиту на розвідку о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")

    target = request_data.get("target")
    recon_type = request_data.get("recon_type")
    nmap_options_str = request_data.get("nmap_options_str", "")
    log_messages.append(f"[RECON_LOGIC_PARAMS] Ціль='{target}', Тип='{recon_type}', Опції Nmap='{nmap_options_str}'.")

    if not target or not recon_type:
        log_messages.append("[RECON_LOGIC_ERROR] Відсутні обов'язкові параметри (target або recon_type).")
        return {"success": False, "error": "Missing target or recon_type", "reconLog": "\n".join(log_messages)}, 400

    recon_results_text = ""
    # parsed_services та parsed_os ініціалізуються порожніми списками
    parsed_services_for_report, parsed_os_for_report = [], []


    if recon_type == "port_scan_basic":
        recon_results_text = simulate_port_scan_logic(target, log_messages)
    elif recon_type == "osint_email_search":
        recon_results_text = simulate_osint_email_search_logic(target, log_messages)
    elif recon_type == "osint_subdomain_search_concept":
        recon_results_text = simulate_osint_subdomain_search_logic(target, log_messages)
    elif recon_type == "port_scan_nmap_standard":
        nmap_options_list = shlex.split(nmap_options_str) if nmap_options_str else []
        raw_nmap_output, _, _ = perform_nmap_scan_logic(target, options=nmap_options_list, use_xml_output=False, recon_type_hint=recon_type, log_messages=log_messages)
        recon_results_text = f"Результати Nmap сканування для: {target}\n\n{raw_nmap_output}"
    
    elif recon_type == "port_scan_nmap_cve_basic" or recon_type == "port_scan_nmap_vuln_scripts":
        nmap_options_list = shlex.split(nmap_options_str) if nmap_options_str else []
        # Для CVE та vuln_scripts завжди використовуємо XML для детального парсингу
        nmap_xml_data, parsed_services_nmap, parsed_os_nmap = perform_nmap_scan_logic(target, options=nmap_options_list, use_xml_output=True, recon_type_hint=recon_type, log_messages=log_messages)
        
        parsed_services_for_report = parsed_services_nmap
        parsed_os_for_report = parsed_os_nmap

        report_lines = [f"Nmap Scan Report for: {target} (Type: {recon_type})"]
        report_lines.append("="*40)

        if "Помилка" in nmap_xml_data or "nmap не знайдено" in nmap_xml_data or "вичерпано" in nmap_xml_data or not (parsed_services_nmap or parsed_os_nmap) and "Host seems down" in nmap_xml_data :
            report_lines.append("\nNmap Execution Issues or No Parsable Data:")
            report_lines.append(nmap_xml_data if nmap_xml_data.strip() else "Nmap did not produce significant output or it was empty.")
        else:
            report_lines.append("\n--- Host Information & OS Detection ---")
            if parsed_os_nmap:
                for os_entry in parsed_os_nmap:
                    report_lines.append(f"Host: {os_entry.get('host_ip', 'N/A')}")
                    if os_entry.get('name') != "N/A (Host Scripts Only)":
                        report_lines.append(f"  OS Name: {os_entry.get('name', 'N/A')} (Accuracy: {os_entry.get('accuracy', 'N/A')}%")
                        if os_entry.get('family'): report_lines.append(f"  Family: {os_entry['family']}")
                        if os_entry.get('generation'): report_lines.append(f"  Generation: {os_entry['generation']}")
                        if os_entry.get('cpes'): report_lines.append(f"  OS CPEs: {', '.join(os_entry['cpes'])}")
                    if os_entry.get("host_scripts"):
                        report_lines.append("  Host Scripts:")
                        for script_info in os_entry["host_scripts"]:
                            report_lines.append(f"    Script ID: {script_info['id']}")
                            if script_info['output']: report_lines.append(f"      Output: {script_info['output'].strip()}")
                            # ... (додати вивід structured_data та tables для host_scripts)
                    report_lines.append("") 
            else:
                report_lines.append("OS information or host scripts not found or could not be parsed.")
            report_lines.append("")

            report_lines.append("--- Open Ports, Services, Scripts & CVEs ---")
            if parsed_services_nmap:
                cve_results_local = conceptual_cve_lookup_logic(parsed_services_nmap, log_messages)
                
                for service in parsed_services_nmap:
                    report_lines.append(f"Port: {service.get('port')}/{service.get('protocol')} on {service.get('host_ip', target)}")
                    report_lines.append(f"  Service: {service.get('service_name')}")
                    if service.get('product'): report_lines.append(f"  Product: {service.get('product','')}")
                    if service.get('version_number'): report_lines.append(f"  Version: {service.get('version_number','')}")
                    if service.get('extrainfo'): report_lines.append(f"  ExtraInfo: {service.get('extrainfo')}")
                    if service.get('cpes'): report_lines.append(f"  Service CPEs: {', '.join(service.get('cpes'))}")
                    
                    service_cves_found = [cve for cve in cve_results_local if str(cve.get('port')) == str(service.get('port')) and cve.get('host_ip', service.get('host_ip')) == service.get('host_ip')]
                    if service_cves_found:
                        report_lines.append(f"  CVEs (Source: {service_cves_found[0].get('source', 'N/A')}):")
                        for cve in service_cves_found:
                            report_lines.append(f"    - {cve['cve_id']} (Severity: {cve['severity']})")
                            report_lines.append(f"      Summary: {cve['summary']}")
                            if cve.get('cvss_score') is not None: report_lines.append(f"      CVSS Score: {cve['cvss_score']} (v{cve.get('cvss_version', '')})")
                            if cve.get('cvss_vector'): report_lines.append(f"      CVSS Vector: {cve['cvss_vector']}")
                            if cve.get('published_date'): report_lines.append(f"      Published: {cve['published_date']}")
                            if cve.get('references'): report_lines.append(f"      References: {', '.join(cve['references'][:2])}{'...' if len(cve['references']) > 2 else ''}")
                    
                    if service.get("scripts"):
                        report_lines.append("  Port Scripts Output:")
                        for script_info in service["scripts"]:
                            report_lines.append(f"    Script ID: {script_info['id']}")
                            if script_info['output']:
                                if script_info['id'] == 'vulners': # Спеціальна обробка для vulners
                                    vulners_output_lines = script_info['output'].strip().split('\n')
                                    report_lines.append("      Vulners Scan Details:")
                                    for line_vln in vulners_output_lines: # Унікальне ім'я змінної
                                        line_stripped_vln = line_vln.strip()
                                        if line_stripped_vln: report_lines.append(f"        {line_stripped_vln}")
                                else:
                                     report_lines.append(f"      Raw Output: {script_info['output'].strip()}")
                            # ... (додати вивід structured_data та tables для port_scripts)
                    report_lines.append("")
            else:
                report_lines.append("Services for analysis not found or Nmap scan failed before service parsing.")
            
            if recon_type == "port_scan_nmap_vuln_scripts":
                 report_lines.append("\n--- Raw Nmap XML Output (for detailed analysis) ---")
                 report_lines.append(nmap_xml_data if nmap_xml_data.strip() else "Nmap did not produce XML output or it was empty.")

        recon_results_text = "\n".join(report_lines)
    else:
        log_messages.append(f"[RECON_LOGIC_ERROR] Невідомий тип розвідки: {recon_type}")
        return {"success": False, "error": f"Unknown recon_type: {recon_type}", "reconLog": "\n".join(log_messages)}, 400

    log_messages.append("[RECON_LOGIC_SUCCESS] Обробку запиту на розвідку завершено.")
    return {"success": True, "reconResults": recon_results_text, "reconLog": "\n".join(log_messages)}, 200

