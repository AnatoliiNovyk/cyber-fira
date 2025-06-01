# reconnaissance/routes.py
# Визначає ендпоінти для модуля розвідки

from flask import Blueprint, request, jsonify
from .logic import handle_run_recon_logic # Імпорт основної логіки
import config 
from datetime import datetime

# Створюємо Blueprint для цього модуля
recon_bp = Blueprint('reconnaissance', __name__, url_prefix='/api/recon')

@recon_bp.route('/run', methods=['POST'])
def run_recon_route():
    """
    Маршрут для запуску операцій розвідки.
    Обробляє JSON-запит та викликає логіку розвідки.
    """
    log_messages_route = [f"[ROUTE_RECON v{config.VERSION_BACKEND}] Запит /api/recon/run о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    
    request_json_data = request.get_json()
    if not request_json_data:
        log_messages_route.append("[ROUTE_RECON_ERROR] Не отримано JSON даних у запиті.")
        return jsonify({
            "success": False, 
            "error": "No JSON data provided for recon", 
            "reconLog": "\n".join(log_messages_route)
        }), 400

    try:
        # Виклик основної логіки розвідки
        response_data, status_code = handle_run_recon_logic(request_json_data, log_messages_route)
        return jsonify(response_data), status_code
    except Exception as e:
        log_messages_route.append(f"[ROUTE_RECON_FATAL_ERROR] Непередбачена помилка: {str(e)}")
        # import traceback # Для детального логування помилки
        # log_messages_route.append(traceback.format_exc())
        return jsonify({
            "success": False,
            "error": "An unexpected server error occurred during reconnaissance.",
            "reconLog": "\n".join(log_messages_route)
        }), 500

# Можна додати інші маршрути, наприклад, для отримання списку типів розвідки
@recon_bp.route('/types', methods=['GET'])
def get_recon_types_route():
    """
    Маршрут для отримання списку доступних типів розвідки.
    """
    log_messages_route = [f"[ROUTE_RECON_TYPES v{config.VERSION_BACKEND}] Запит /api/recon/types о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        # Типи розвідки можна взяти з конфігурації або визначити тут
        recon_types_available = [
            {"id": "port_scan_basic", "name": "Сканування Портів (Базове - Імітація)"},
            {"id": "osint_email_search", "name": "Пошук Email (OSINT - Імітація)"},
            {"id": "osint_subdomain_search_concept", "name": "OSINT Пошук Субдоменів (Концепт)"},
            {"id": "port_scan_nmap_standard", "name": "Nmap Скан (Стандартний)"},
            {"id": "port_scan_nmap_cve_basic", "name": "Nmap Скан (Версії, ОС, CVE)"},
            {"id": "port_scan_nmap_vuln_scripts", "name": "Nmap Сканування Скриптами Вразливостей"}
        ]
        log_messages_route.append(f"[ROUTE_RECON_TYPES_SUCCESS] Повернено {len(recon_types_available)} типів розвідки.")
        return jsonify({"success": True, "recon_types": recon_types_available, "log": "\n".join(log_messages_route)}), 200
    except Exception as e:
        log_messages_route.append(f"[ROUTE_RECON_TYPES_ERROR] Помилка: {str(e)}")
        return jsonify({"success": False, "error": "Server error retrieving recon types", "log": "\n".join(log_messages_route)}), 500
