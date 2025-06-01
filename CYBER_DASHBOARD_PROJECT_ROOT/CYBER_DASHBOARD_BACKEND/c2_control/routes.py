# c2_control/routes.py
# Визначає ендпоінти для модуля C2 (Командування та Контроль)

from flask import Blueprint, request, jsonify
# Імпорт логіки буде додано пізніше
from .logic import (
    handle_c2_beacon_logic,
    handle_dns_resolver_sim_logic,
    get_c2_implants_logic,
    handle_c2_task_logic
)
import config # Для доступу до VERSION_BACKEND
from datetime import datetime

# Створюємо Blueprint для цього модуля
c2_bp = Blueprint('c2_control', __name__, url_prefix='/api/c2')

@c2_bp.route('/beacon_receiver', methods=['POST'])
def c2_beacon_route():
    """Маршрут для прийому маячків від імплантів."""
    log_messages_route = [f"[ROUTE_C2_BEACON v{config.VERSION_BACKEND}] Запит /api/c2/beacon_receiver о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    request_json_data = request.get_json()
    # Виклик логіки з logic.py
    response_data, status_code = handle_c2_beacon_logic(request_json_data, log_messages_route)
    return jsonify(response_data), status_code

@c2_bp.route('/dns_resolver_sim', methods=['GET'])
def dns_resolver_sim_route():
    """Маршрут для симуляції DNS-резолвера для DNS C2."""
    log_messages_route = [f"[ROUTE_C2_DNS_SIM v{config.VERSION_BACKEND}] Запит /api/c2/dns_resolver_sim о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    # Виклик логіки з logic.py
    response_data, status_code = handle_dns_resolver_sim_logic(request.args, log_messages_route) # Передаємо request.args
    return jsonify(response_data), status_code

@c2_bp.route('/implants', methods=['GET'])
def get_implants_route():
    """Маршрут для отримання списку активних імплантів."""
    log_messages_route = [f"[ROUTE_C2_IMPLANTS v{config.VERSION_BACKEND}] Запит /api/c2/implants о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    # Виклик логіки з logic.py
    response_data, status_code = get_c2_implants_logic(log_messages_route)
    return jsonify(response_data), status_code

@c2_bp.route('/task', methods=['POST'])
def c2_task_route():
    """Маршрут для постановки завдань імплантам."""
    log_messages_route = [f"[ROUTE_C2_TASK v{config.VERSION_BACKEND}] Запит /api/c2/task о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    request_json_data = request.get_json()
    # Виклик логіки з logic.py
    response_data, status_code = handle_c2_task_logic(request_json_data, log_messages_route)
    return jsonify(response_data), status_code

# Інші маршрути, пов'язані з C2, можуть бути додані тут.
