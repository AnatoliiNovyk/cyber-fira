# CYBER_DASHBOARD_BACKEND/reconnaissance/logic.py
# Координатор: Синтаксис
# Опис: Основна логіка для модуля розвідки.
# Версія з покращеним застосуванням дефолтних опцій Nmap.

import json
import re
import random
import time
from datetime import datetime
import subprocess
import shlex 
import xml.etree.ElementTree as ET
import requests 
import traceback 

# Імпорти з кореневих файлів проекту
import config 
from utils import get_service_name_be 

# --- Логіка для симуляції базових сканувань ---
def simulate_port_scan_logic(target: str, log_messages: list) -> str:
    # Коментарі українською для кращого розуміння логіки.
    log_messages.append(f"[RECON_LOGIC_SIM_PORT] Імітація сканування портів для: {target}")
    results_text_lines = [f"Результати імітації сканування портів для: {target}"]
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 8000, 8080, 8443]
    open_ports_found = []
    for port in common_ports:
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
    log_messages.append("[RECON_LOGIC_SIM_PORT_SUCCESS] Імітацію сканування портів завершено.")
    return "\n".join(results_text_lines)

def simulate_osint_email_search_logic(target_domain: str, log_messages: list) -> str:
    # Коментарі українською для кращого розуміння логіки.
    log_messages.append(f"[RECON_LOGIC_SIM_EMAIL] Імітація OSINT пошуку email для: {target_domain}")
    results_text_lines = [f"Результати імітації OSINT пошуку Email для домену: {target_domain}"]
    domain_parts = target_domain.split('.')
    main_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else target_domain
    common_names = ["info", "support", "admin", "contact", "sales", "hr", "abuse", "webmaster", "dev", "test"]
    first_names = ["john.doe", "jane.smith", "peter.jones", "susan.lee", "michael.brown", "alex.williams", "david.miller"]
    found_emails = set() 
    for _ in range(random.randint(2, 6)): 
        email_prefix = random.choice(common_names) if random.random() < 0.6 else random.choice(first_names)
        email = f"{email_prefix}@{main_domain}"
        found_emails.add(email)
    if found_emails: results_text_lines.extend([f"  Знайдено Email: {email}" for email in sorted(list(found_emails))])
    else: results_text_lines.append("  Email-адрес не знайдено (імітація).")
    log_messages.append("[RECON_LOGIC_SIM_EMAIL_SUCCESS] Імітацію OSINT пошуку email завершено.")
    return "\n".join(results_text_lines)

def simulate_osint_subdomain_search_logic(target_domain: str, log_messages: list) -> str:
    # Коментарі українською для кращого розуміння логіки.
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
        if random.random() < 0.18: 
            found_subdomains_list.add(f"{sub_prefix}.{cleaned_domain}")
    for _ in range(random.randint(0, 3)): 
        p1 = random.choice(["data", "svc", "internal", "ext", "prod", "dev-app", "user", "sys", "app-test"])
        p2 = random.choice(["01", "02", "new", "old", "v2", str(random.randint(1,5))])
        if random.random() < 0.5: found_subdomains_list.add(f"{p1}-{p2}.{cleaned_domain}")
        else: found_subdomains_list.add(f"{p1}{random.randint(1,9)}.{cleaned_domain}")
    
    if not found_subdomains_list and cleaned_domain: 
        found_subdomains_list.add(f"www.{cleaned_domain}")
        if random.random() > 0.3 : found_subdomains_list.add(f"mail.{cleaned_domain}")

    if found_subdomains_list:
        results_text_lines.extend([f"  Знайдено Субдомен: {sub}" for sub in sorted(list(found_subdomains_list))])
    else:
        results_text_lines.append(f"  Субдоменів для '{cleaned_domain}' не знайдено (імітація).")
    log_messages.append("[RECON_LOGIC_SIM_SUBDOMAIN_SUCCESS] Імітацію OSINT пошуку субдоменів завершено.")
    return "\n".join(results_text_lines)

# --- Логіка для Nmap та CVE ---
def parse_nmap_xml_output_logic(nmap_xml_output: str, log_messages: list) -> tuple[list[dict], list[dict]]:
    # Коментарі українською для кращого розуміння логіки.
    parsed_services = []
    parsed_os_info = []
    try:
        log_messages.append("[NMAP_XML_PARSE_LOGIC_INFO] Початок парсингу XML-виводу nmap.")
        if not nmap_xml_output.strip():
            log_messages.append("[NMAP_XML_PARSE_LOGIC_WARN] XML-вивід порожній.")
            return parsed_services, parsed_os_info
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
                    parsed_os_info.append({
                        "host_ip": host_ip, "name": os_name, "accuracy": accuracy,
                        "family": os_family, "generation": os_gen, "cpes": os_cpes
                    })
                    # log_messages.append(f"[NMAP_XML_PARSE_LOGIC_OS] Знайдено ОС: {os_name} (Точність: {accuracy}) для хоста {host_ip}")

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
                    # log_messages.append(f"[NMAP_XML_PARSE_LOGIC_SCRIPT] Знайдено скрипт '{script_id}' для порту {port_id} на {host_ip}.")

                version_info_parts = [product_name, version_number, extrainfo]
                version_info_full = " ".join(part for part in version_info_parts if part).strip() or service_name
                
                service_key_for_cve_parts = []
                if product_name:
                    service_key_for_cve_parts.append(product_name.lower().strip())
                elif service_name and service_name != 'unknown':
                     service_key_for_cve_parts.append(service_name.lower().strip())

                if version_number:
                    service_key_for_cve_parts.append(version_number.lower().strip())
                elif not product_name and service_name != 'unknown' and extrainfo: 
                     version_match_extra = re.search(r"(\d+\.(?:\d+\.)*[\d\w-]+)", extrainfo) 
                     if version_match_extra: 
                         service_key_for_cve_parts.append(version_match_extra.group(1).lower().strip())
                
                service_key_for_cve = " ".join(service_key_for_cve_parts)

                parsed_services.append({
                    "host_ip": host_ip, "port": port_id, "protocol": protocol, "service_name": service_name, 
                    "product": product_name, "version_number": version_number, "extrainfo": extrainfo,
                    "version_info_full": version_info_full, "cpes": service_cpes,
                    "service_key_for_cve": service_key_for_cve.strip(), "scripts": scripts_output
                })
        
        for host_node in root.findall('host'): 
            host_ip = host_node.find('address').get('addr') if host_node.find('address') is not None else "N/A"
            hostscript_node = host_node.find('hostscript')
            if hostscript_node:
                host_scripts_output = []
                for script_node in hostscript_node.findall('script'):
                    script_id = script_node.get('id', 'N/A')
                    script_data = script_node.get('output', '')
                    structured_script_data = {elem.get('key'): elem.text for elem in script_node.findall('elem') if elem.get('key')}
                    tables_data = [{elem.get('key'): elem.text for elem in table_node.findall('elem') if elem.get('key')} for table_node in script_node.findall('table')]
                    host_scripts_output.append({"id": script_id, "output": script_data, "structured_data": structured_script_data, "tables": tables_data})
                    # log_messages.append(f"[NMAP_XML_PARSE_LOGIC_HOSTSCRIPT] Знайдено хост-скрипт '{script_id}' для {host_ip}.")

                os_info_entry = next((os_info for os_info in parsed_os_info if os_info["host_ip"] == host_ip), None)
                if os_info_entry:
                    os_info_entry.setdefault("host_scripts", []).extend(host_scripts_output)
                elif host_scripts_output: 
                    parsed_os_info.append({"host_ip": host_ip, "name": "N/A (Host Scripts Only)", "accuracy": "N/A", "family": "", "generation": "", "cpes": [], "host_scripts": host_scripts_output})
        log_messages.append(f"[NMAP_XML_PARSE_LOGIC_SUCCESS] Успішно розпарсено XML, знайдено {len(parsed_services)} сервісів та {len(parsed_os_info)} записів ОС/хост-скриптів.")
    except ET.ParseError as e_parse:
        log_messages.append(f"[NMAP_XML_PARSE_LOGIC_ERROR] Помилка парсингу XML: {e_parse}")
    except Exception as e_generic:
        log_messages.append(f"[NMAP_XML_PARSE_LOGIC_FATAL] Непередбачена помилка під час парсингу XML: {e_generic}")
        log_messages.append(traceback.format_exc()) 
    return parsed_services, parsed_os_info


def fetch_cves_from_nvd_api_logic(service_key_raw: str, service_cpes: list, log_messages: list) -> list[dict]:
    # Коментарі українською для кращого розуміння логіки.
    nvd_cves_found = []
    headers = {}
    nvd_api_key_val = config.NVD_API_KEY 
    if nvd_api_key_val: headers['apiKey'] = nvd_api_key_val

    search_terms = []
    if service_cpes:
        for cpe in service_cpes:
            search_terms.append({'type': 'cpeName', 'value': cpe}) 
    
    if not service_cpes or not any(st['type'] == 'cpeName' for st in search_terms):
        if service_key_raw:
             search_terms.append({'type': 'keywordSearch', 'value': service_key_raw, 'exactMatch': True})
             search_terms.append({'type': 'keywordSearch', 'value': service_key_raw}) 

    for term in search_terms:
        params = {'resultsPerPage': config.NVD_RESULTS_PER_PAGE}
        if term['type'] == 'cpeName':
            params['cpeName'] = term['value']
        elif term['type'] == 'keywordSearch':
            params['keywordSearch'] = term['value']
            if term.get('exactMatch'):
                params['keywordExactMatch'] = '' 

        log_messages.append(f"[NVD_API_LOGIC_INFO] Запит до NVD API за {term['type']}: '{term['value']}'. URL: {config.NVD_API_BASE_URL} PARAMS: {params}")
        try:
            response = requests.get(config.NVD_API_BASE_URL, headers=headers, params=params, timeout=config.NVD_REQUEST_TIMEOUT_SECONDS)
            log_messages.append(f"[NVD_API_LOGIC_DEBUG] URL запиту NVD: {response.url}") 
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
                    cvss_data_item_wrapper = cvss_data_list[0] 
                    cvss_data_item = cvss_data_item_wrapper.get('cvssData', {})
                    severity = cvss_data_item_wrapper.get('baseSeverity', cvss_data_item.get('baseSeverity', severity)) 
                    cvss_score = cvss_data_item.get('baseScore')
                    cvss_vector = cvss_data_item.get('vectorString')
                    cvss_version_from_data = cvss_data_item.get('version')
                    if not cvss_version_from_data: 
                        if 'cvssMetricV31' in metrics: cvss_version_from_data = "3.1"
                        elif 'cvssMetricV30' in metrics: cvss_version_from_data = "3.0"
                        elif 'cvssMetricV2' in metrics: cvss_version_from_data = "2.0"
                    cvss_version = cvss_version_from_data
                
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
            if nvd_cves_found and term['type'] == 'cpeName': break 
            if nvd_cves_found and term.get('exactMatch') and term['type'] == 'keywordSearch': break 

            time.sleep(0.7) 
        except requests.exceptions.HTTPError as e_http:
            if e_http.response.status_code == 404:
                log_messages.append(f"[NVD_API_LOGIC_NOT_FOUND] Ресурс не знайдено (404) для {term['type']} '{term['value']}'. URL: {e_http.request.url}")
            else:
                log_messages.append(f"[NVD_API_LOGIC_HTTP_ERROR] HTTP помилка для {term['type']} '{term['value']}': {e_http}. URL: {e_http.request.url}")
        except requests.exceptions.RequestException as e_req: 
            log_messages.append(f"[NVD_API_LOGIC_REQUEST_ERROR] Помилка запиту для {term['type']} '{term['value']}': {e_req}")
        except json.JSONDecodeError as e_json: 
            log_messages.append(f"[NVD_API_LOGIC_JSON_ERROR] Помилка декодування JSON для {term['type']} '{term['value']}': {e_json}")
        except Exception as e_generic: 
            log_messages.append(f"[NVD_API_LOGIC_FATAL] Непередбачена помилка обробки {term['type']} '{term['value']}': {e_generic}")
            log_messages.append(traceback.format_exc()) 
    
    unique_cves_from_nvd = {cve['cve_id']: cve for cve in nvd_cves_found}.values() 
    log_messages.append(f"[NVD_API_LOGIC_SUCCESS] NVD API повернув {len(unique_cves_from_nvd)} унікальних CVE.")
    return list(unique_cves_from_nvd)


def conceptual_cve_lookup_logic(services_info: list, log_messages: list) -> list[dict]:
    # Коментарі українською для кращого розуміння логіки.
    found_cves_overall = []
    processed_cve_ids = set() 
    log_messages.append(f"[CVE_LOOKUP_LOGIC_INFO] Пошук CVE для {len(services_info)} сервісів.")

    for service_item in services_info:
        service_key_raw = service_item.get("service_key_for_cve", "").lower().strip()
        service_cpes_list = service_item.get("cpes", [])
        host_ip_for_cve = service_item.get("host_ip")
        port_for_cve = service_item.get("port")

        if not service_key_raw and not service_cpes_list:
            log_messages.append(f"[CVE_LOOKUP_LOGIC_WARN] Пропущено сервіс (порт {port_for_cve} на {host_ip_for_cve}) через порожній ключ CVE та відсутність CPE.")
            continue

        # 1. NVD API
        log_messages.append(f"[CVE_LOOKUP_LOGIC_NVD_ATTEMPT] Запит до NVD API для '{service_key_raw}' (CPEs: {service_cpes_list}) на {host_ip_for_cve}:{port_for_cve}.")
        cves_from_nvd = fetch_cves_from_nvd_api_logic(service_key_raw, service_cpes_list, log_messages)
        for cve_nvd in cves_from_nvd:
            if cve_nvd['cve_id'] not in processed_cve_ids:
                found_cves_overall.append({"host_ip": host_ip_for_cve, "port": port_for_cve, "service_key": service_key_raw, "matched_db_key": service_key_raw, **cve_nvd})
                processed_cve_ids.add(cve_nvd['cve_id'])
                log_messages.append(f"  [NVD_LOGIC_HIT] {cve_nvd['cve_id']} ({cve_nvd['severity']}) для {host_ip_for_cve}:{port_for_cve}")
        
        # 2. MOCK_EXTERNAL_CVE_API_DB (резервна база)
        matched_mock_cves = []
        service_product_parts = service_key_raw.split(' ')
        service_product_name_short = service_product_parts[0] # Наприклад, "openssh"
        service_product_name_full = " ".join(service_product_parts[:2]) if len(service_product_parts) > 1 and service_product_parts[1].isalpha() else service_product_name_short # Наприклад, "apache httpd"

        for db_key, cves_in_db in config.MOCK_EXTERNAL_CVE_API_DB.items():
            db_key_parts = db_key.split(' ')
            db_product_name_short = db_key_parts[0]
            db_product_name_full = " ".join(db_key_parts[:2]) if len(db_key_parts) > 1 and db_key_parts[1].isalpha() else db_product_name_short
            
            # Пріоритет на більш точне зіставлення (повна назва продукту), потім коротка
            if service_product_name_full == db_product_name_full or \
               (service_product_name_short == db_product_name_short and service_product_name_full != db_product_name_full): # Якщо повні не співпали, але короткі так
                # Додаткова перевірка версії, якщо вона є в service_key_raw
                # Це дуже спрощена перевірка версій, для реального застосування потрібен кращий парсер версій
                version_match = True # За замовчуванням вважаємо, що версія підходить, якщо її немає в db_key
                if len(db_key_parts) > (1 if db_product_name_short == db_product_name_full else 2): # Якщо в db_key є версія
                    db_version_part = db_key_parts[1 if db_product_name_short == db_product_name_full else 2]
                    if len(service_product_parts) > (1 if service_product_name_short == service_product_name_full else 2):
                        service_version_part = service_product_parts[1 if service_product_name_short == service_product_name_full else 2]
                        # Проста перевірка, чи починається версія сервісу з версії в БД (напр. "7.4" vs "7.")
                        if not service_version_part.startswith(db_version_part.split('.')[0]): # Порівняння тільки мажорної версії
                             version_match = False
                    else: # У сервіса немає версії, а в БД є - не співпадає
                        version_match = False 
                
                if version_match:
                    matched_mock_cves.extend(cves_in_db)
                    log_messages.append(f"  [MOCK_DB_LOGIC_KEY_MATCH] Знайдено співпадіння в Mock DB: ключ сервісу '{service_key_raw}' з ключем БД '{db_key}'.")
                    break # Знайшли відповідний продукт, переходимо до наступного сервісу

        for cve_mock in matched_mock_cves:
            if cve_mock['cve_id'] not in processed_cve_ids:
                cve_data_to_add = {k:None for k in ["cvss_score","cvss_vector","cvss_version","published_date","last_modified_date","vulnerable_configurations_cpe","references"]}
                cve_data_to_add.update(cve_mock) 
                found_cves_overall.append({"host_ip": host_ip_for_cve, "port": port_for_cve, "service_key": service_key_raw, "matched_db_key": "N/A (Matched by product name)", **cve_data_to_add})
                processed_cve_ids.add(cve_mock['cve_id'])
                log_messages.append(f"  [MOCK_DB_LOGIC_HIT] {cve_mock['cve_id']} ({cve_mock.get('severity', 'N/A')}) для {host_ip_for_cve}:{port_for_cve}")

        # 3. CONCEPTUAL_CVE_DATABASE_BE (внутрішня резервна база - точне зіставлення)
        internal_db_cves_found = config.CONCEPTUAL_CVE_DATABASE_BE.get(service_key_raw, [])
        for cve_internal in internal_db_cves_found:
            if cve_internal['cve_id'] not in processed_cve_ids:
                cve_data_to_add = {k:None for k in ["cvss_score","cvss_vector","cvss_version","published_date","last_modified_date","vulnerable_configurations_cpe","references"]}
                cve_data_to_add.update(cve_internal)
                cve_data_to_add["source"] = cve_internal.get("source", "Internal Fallback DB") 
                found_cves_overall.append({"host_ip": host_ip_for_cve, "port": port_for_cve, "service_key": service_key_raw, "matched_db_key": service_key_raw, **cve_data_to_add})
                processed_cve_ids.add(cve_internal['cve_id'])
                log_messages.append(f"  [INTERNAL_DB_LOGIC_HIT] {cve_internal['cve_id']} ({cve_internal.get('severity', 'N/A')}) для {host_ip_for_cve}:{port_for_cve}")

    log_messages.append(f"[CVE_LOOKUP_LOGIC_SUCCESS] Загалом знайдено {len(found_cves_overall)} унікальних CVE.")
    return found_cves_overall


def perform_nmap_scan_logic(target: str, options: list = None, use_xml_output: bool = False, recon_type_hint: str = None, log_messages: list = None) -> tuple[str, list[dict], list[dict]]:
    # Коментарі українською для кращого розуміння логіки.
    if log_messages is None: log_messages = [] 
    log_messages.append(f"[RECON_NMAP_LOGIC_INFO] Запуск nmap для: {target}, початкові опції: {options}, XML: {use_xml_output}, Тип: {recon_type_hint}")
    
    base_nmap_command = getattr(config, "NMAP_COMMAND_PATH", "nmap") 
    
    # 0. Початкові опції від користувача (якщо є)
    user_provided_options = list(options) if options else []
    current_nmap_options = list(user_provided_options) # Робочий список опцій

    # 1. Визначення дефолтних опцій для типу сканування
    # Ці опції будуть додані, тільки якщо користувач не надав конфліктуючих або еквівалентних опцій.
    default_scan_type_options = []
    if recon_type_hint == "port_scan_nmap_standard":
        default_scan_type_options = ["-sV", "-T4", "-Pn"]
    elif recon_type_hint == "port_scan_nmap_cve_basic":
        default_scan_type_options = ["-sV", "-O", "-T4", "-Pn"]
    elif recon_type_hint == "port_scan_nmap_vuln_scripts":
        default_scan_type_options = ["-sV", "-O", "--script", "vuln", "-Pn"] # -O додано для повноти

    # 2. Додавання дефолтних опцій для типу сканування, якщо вони не конфліктують з користувацькими
    # Ця логіка має бути обережною, щоб не перезаписати навмисні налаштування користувача.
    # Простий підхід: якщо користувач надав будь-які опції, дефолтні для типу не додаються автоматично,
    # окрім тих, що потрібні для XML (див. нижче).
    if not user_provided_options and default_scan_type_options: # Додаємо дефолтні, тільки якщо користувач нічого не вказав
        log_messages.append(f"[RECON_NMAP_LOGIC_INFO] Застосування дефолтних опцій для '{recon_type_hint}': {default_scan_type_options}")
        for opt_to_add in default_scan_type_options:
            # Проста перевірка на наявність базової опції (без урахування аргументів)
            base_opt_to_add = opt_to_add.split(' ')[0]
            if not any(existing_opt.startswith(base_opt_to_add) for existing_opt in current_nmap_options):
                if ' ' in opt_to_add: # Опція з аргументом, як "--script vuln"
                    current_nmap_options.extend(opt_to_add.split(' ', 1))
                else:
                    current_nmap_options.append(opt_to_add)
    
    # 3. Забезпечення опцій для XML виводу, якщо use_xml_output встановлено в True
    if use_xml_output:
        # Видаляємо будь-які інші -oX <file> перед додаванням -oX -
        temp_opts_xml = []
        skip_xml = False
        for i_temp_xml, opt_temp_xml in enumerate(current_nmap_options):
            if skip_xml: skip_xml = False; continue
            if opt_temp_xml == "-oX" and (i_temp_xml + 1) < len(current_nmap_options) and current_nmap_options[i_temp_xml+1] != "-":
                skip_xml = True 
            elif opt_temp_xml.startswith("-oX") and not opt_temp_xml.endswith("-"):
                 pass 
            else:
                temp_opts_xml.append(opt_temp_xml)
        current_nmap_options = temp_opts_xml
        
        is_oX_dash_present = any(
            (opt == "-oX" and (idx + 1) < len(current_nmap_options) and current_nmap_options[idx+1] == "-") or opt == "-oX-"
            for idx, opt in enumerate(current_nmap_options)
        )
        if not is_oX_dash_present:
            current_nmap_options.extend(["-oX", "-"])
            log_messages.append("[RECON_NMAP_LOGIC_INFO] Додано '-oX -' для XML виводу.")

        if not any(opt.startswith("-sV") for opt in current_nmap_options): 
            current_nmap_options.append("-sV")
            log_messages.append("[RECON_NMAP_LOGIC_INFO] Додано '-sV' для XML виводу.")
        if not any(opt.startswith("-O") for opt in current_nmap_options) and not any(opt.startswith("-A") for opt in current_nmap_options):
            current_nmap_options.append("-O")
            log_messages.append("[RECON_NMAP_LOGIC_INFO] Додано '-O' для XML виводу (якщо немає -A).")

    # 4. Якщо після всіх маніпуляцій список опцій порожній (і користувач нічого не вводив)
    if not current_nmap_options and not user_provided_options: 
        if use_xml_output:
            current_nmap_options = ["-sV", "-O", "-T4", "-Pn", "-oX", "-"] 
        else: # Дефолт для не-XML стандартного сканування
            current_nmap_options = ["-sV", "-T4", "-Pn"] 
        log_messages.append(f"[RECON_NMAP_LOGIC_INFO] Застосування фінальних загальних дефолтних опцій Nmap: {current_nmap_options}")


    # Фільтрація та валідація фінального набору опцій (взято з попередньої версії)
    allowed_options_prefixes = [
        "-sS", "-sT", "-sU", "-sV", "-sC", "-sX", "-sA", "-sW", "-sM", 
        "-Pn", "-n", "-R", "--dns-servers", 
        "-p", "--top-ports", "--exclude-ports", "-F", "-r", 
        "-O", "--osscan-limit", "--osscan-guess", 
        "-T0", "-T1", "-T2", "-T3", "-T4", "-T5", 
        "--host-timeout", "--scan-delay", "--max-retries", 
        "-v", "-vv", "-d", "-dd", 
        "-A", 
        "-oX", "-oN", "-oG", "-oA",
        "-iL", 
        "--script", "--script-args", "--script-help", 
        "-PE", "-PP", "-PS", "-PA", "-PU", "-PY", 
        "-g", "--source-port", 
        "--data-length", 
    ]
    
    output_options_requiring_dash_arg = ["-oX", "-oN", "-oG", "-oA"] 
    options_with_arguments = ["-p", "--top-ports", "--exclude-ports", "-iL", "--script", "--script-args", "-g", "--source-port", "--dns-servers", "--host-timeout", "--scan-delay", "--max-retries"] + output_options_requiring_dash_arg

    final_command_parts = [base_nmap_command] 
    processed_opts_args = []
    skip_next_arg = False 

    for i, opt_part_raw in enumerate(current_nmap_options): # Тепер ітеруємо по current_nmap_options
        if skip_next_arg:
            skip_next_arg = False
            continue
        
        opt_part = opt_part_raw
        next_arg_candidate_implicit = None
        if len(opt_part_raw) > 2 and opt_part_raw[:-1] in output_options_requiring_dash_arg and opt_part_raw[-1] == '-':
            opt_part = opt_part_raw[:-1] 
            next_arg_candidate_implicit = "-" 

        is_allowed_option = any(opt_part == p or opt_part.startswith(p + "=") for p in allowed_options_prefixes) 
        if not is_allowed_option and any(p.startswith(opt_part) for p in allowed_options_prefixes if len(opt_part) < len(p) and not p.startswith(opt_part + "=")): 
             is_allowed_option = True 

        if is_allowed_option:
            processed_opts_args.append(opt_part_raw if next_arg_candidate_implicit else opt_part)             
            current_opt_base = opt_part.split('=')[0] 
            
            actual_next_arg = None
            if next_arg_candidate_implicit:
                actual_next_arg = next_arg_candidate_implicit
            elif "=" not in opt_part and current_opt_base in options_with_arguments and (i + 1) < len(current_nmap_options):
                actual_next_arg = current_nmap_options[i+1]

            if actual_next_arg is not None:
                if current_opt_base in output_options_requiring_dash_arg:
                    if actual_next_arg == "-":
                        if not next_arg_candidate_implicit: 
                            processed_opts_args.append(actual_next_arg)
                            skip_next_arg = True
                        log_messages.append(f"[RECON_NMAP_LOGIC_SECURE_OUT] Дозволено опцію виводу '{current_opt_base}' з аргументом '-'.")
                    else:
                        log_messages.append(f"[RECON_NMAP_LOGIC_REJECT_FILE_OUT] ЗАБОРОНЕНО: Опція виводу '{current_opt_base}' з аргументом файлу '{actual_next_arg}'. Дозволено тільки '-'. Опцію та аргумент відкинуто.")
                        if not next_arg_candidate_implicit: processed_opts_args.pop() 
                        else: processed_opts_args[-1] = current_opt_base 
                        if not next_arg_candidate_implicit: skip_next_arg = True 
                        continue 
                elif not any(actual_next_arg == p_prefix or actual_next_arg.startswith(p_prefix + "=") for p_prefix in allowed_options_prefixes):
                    if not next_arg_candidate_implicit:
                        processed_opts_args.append(actual_next_arg)
                        skip_next_arg = True
            elif "=" in opt_part_raw and current_opt_base in options_with_arguments:
                pass # Аргумент вже є частиною опції
        elif opt_part_raw: 
            log_messages.append(f"[RECON_NMAP_LOGIC_WARN_UNKNOWN] Невідома або недозволена опція/аргумент Nmap: '{opt_part_raw}'. Відкинуто.")
        
    final_command_parts.extend(processed_opts_args)
    final_command_parts.append(target) 
    log_messages.append(f"[RECON_NMAP_LOGIC_CMD_FINAL] Сформована команда Nmap: {' '.join(final_command_parts)}")

    # ... (решта коду функції perform_nmap_scan_logic без змін) ...
    parsed_services_list, parsed_os_list, raw_output_text = [], [], ""
    try:
        process = subprocess.run(final_command_parts, capture_output=True, text=True, timeout=600, check=False, encoding='utf-8', errors='ignore')
        raw_output_text = process.stdout if process.returncode == 0 or process.stdout else process.stderr 
        
        if process.returncode == 0 or (process.returncode != 0 and "Host seems down" not in raw_output_text and "Failed to resolve" not in raw_output_text): 
            log_messages.append(f"[RECON_NMAP_LOGIC_STATUS] Nmap завершено (код: {process.returncode}).")
            xml_output_requested_to_stdout = False
            for idx, opt_check in enumerate(final_command_parts):
                if opt_check == "-oX" and (idx + 1) < len(final_command_parts) and final_command_parts[idx+1] == "-":
                    xml_output_requested_to_stdout = True; break
                elif opt_check == "-oX-": 
                    xml_output_requested_to_stdout = True; break
            
            if xml_output_requested_to_stdout:
                parsed_services_list, parsed_os_list = parse_nmap_xml_output_logic(process.stdout, log_messages) 
                log_messages.append(f"[RECON_NMAP_LOGIC_PARSE_XML] Знайдено {len(parsed_services_list)} сервісів та {len(parsed_os_list)} записів ОС/хост-скриптів з XML.")
        else:
            error_message = f"Помилка виконання Nmap (код: {process.returncode}): {raw_output_text}"
            log_messages.append(f"[RECON_NMAP_LOGIC_ERROR] {error_message}")
            if "Host seems down" in raw_output_text: raw_output_text += "\nПідказка: Ціль може бути недоступна або блокувати ping. Спробуйте опцію -Pn."
            elif " consentement explicite" in raw_output_text or "explicit permission" in raw_output_text: raw_output_text += "\nПОПЕРЕДЖЕННЯ NMAP: Сканування мереж без явного дозволу є незаконним."
    except FileNotFoundError:
        log_messages.append(f"[RECON_NMAP_LOGIC_ERROR] Команду '{base_nmap_command}' не знайдено. Переконайтеся, що Nmap встановлено та доступно в системному PATH.")
        raw_output_text = f"Помилка: {base_nmap_command} не встановлено або не знайдено в системному PATH."
    except subprocess.TimeoutExpired:
        log_messages.append("[RECON_NMAP_LOGIC_ERROR] Час очікування nmap сканування вичерпано.")
        raw_output_text = f"Помилка: Час очікування сканування nmap для {target} вичерпано."
    except Exception as e:
        log_messages.append(f"[RECON_NMAP_LOGIC_FATAL] Непередбачена помилка під час nmap сканування: {str(e)}")
        log_messages.append(traceback.format_exc()) 
        raw_output_text = f"Непередбачена помилка під час nmap сканування: {str(e)}"
    
    return raw_output_text, parsed_services_list, parsed_os_list


# Основна функція-обробник для модуля розвідки
def handle_run_recon_logic(request_data: dict, log_messages_main: list) -> tuple[dict, int]:
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
    try: 
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
            nmap_xml_data, parsed_services_nmap, parsed_os_nmap = perform_nmap_scan_logic(target, options=nmap_options_list, use_xml_output=True, recon_type_hint=recon_type, log_messages=log_messages)
            
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
                                    if script_info['id'] == 'vulners': 
                                        vulners_output_lines = script_info['output'].strip().split('\n')
                                        report_lines.append("      Vulners Scan Details:")
                                        for line_vln in vulners_output_lines: 
                                            line_stripped_vln = line_vln.strip()
                                            if line_stripped_vln: report_lines.append(f"        {line_stripped_vln}")
                                    else:
                                         report_lines.append(f"      Raw Output: {script_info['output'].strip()}")
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
    except Exception as e_main_handler: 
        error_traceback = traceback.format_exc()
        log_messages.append(f"[RECON_LOGIC_FATAL_ERROR] Непередбачена помилка в handle_run_recon_logic: {str(e_main_handler)}")
        log_messages.append(f"TRACEBACK:\n{error_traceback}")
        return {"success": False, "error": f"Unexpected server error during reconnaissance: {str(e_main_handler)}", "reconLog": "\n".join(log_messages)}, 500
