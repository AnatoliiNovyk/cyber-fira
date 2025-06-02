# operational_data/routes.py
# Визначає ендпоінти для модуля оперативних даних та адаптації

from flask import Blueprint, request, jsonify
# Імпорт логіки буде додано пізніше
from .logic import (
    get_operational_data_logic,
    update_framework_rules_logic
)
import config # Для доступу до VERSION_BACKEND
from datetime import datetime

# Створюємо Blueprint для цього модуля
# Використовуємо префікс /api/data для цих маршрутів
ops_bp = Blueprint('operational_data', __name__, url_prefix='/api/data')

@ops_bp.route('/operational', methods=['GET'])
def get_operational_data_route():
    """
    Маршрут для отримання агрегованих логів та статистики.
    (Раніше /api/operational_data)
    """
    log_messages_route = [f"[ROUTE_OPS_DATA v{config.VERSION_BACKEND}] Запит /api/data/operational о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    # Виклик логіки з logic.py
    response_data, status_code = get_operational_data_logic(log_messages_route)
    return jsonify(response_data), status_code

@ops_bp.route('/framework_rules', methods=['POST'])
def update_framework_rules_route():
    """
    Маршрут для оновлення правил фреймворку.
    (Раніше /api/framework_rules)
    """
    log_messages_route = [f"[ROUTE_OPS_RULES v{config.VERSION_BACKEND}] Запит /api/data/framework_rules о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    request_json_data = request.get_json()
    if not request_json_data:
        log_messages_route.append("[ROUTE_OPS_RULES_ERROR] Не отримано JSON даних у запиті.")
        return jsonify({
            "success": False, 
            "error": "No JSON data provided for rules", 
            "log": "\n".join(log_messages_route)
        }), 400
    
    # Виклик логіки з logic.py
    response_data, status_code = update_framework_rules_logic(request_json_data, log_messages_route)
    return jsonify(response_data), status_code

# Інші маршрути, пов'язані з оперативними даними, можуть бути додані тут.
