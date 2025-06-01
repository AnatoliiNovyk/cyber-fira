# payload_generator/routes.py
# Визначає ендпоінти для модуля генерації пейлоадів

from flask import Blueprint, request, jsonify
from .logic import handle_payload_generation_logic # Імпорт основної логіки
import config 
from datetime import datetime

# Створюємо Blueprint для цього модуля
payload_bp = Blueprint('payload_generator', __name__, url_prefix='/api/payload')

@payload_bp.route('/generate', methods=['POST'])
def generate_payload_route():
    """
    Маршрут для генерації пейлоада.
    Обробляє JSON-запит та викликає логіку генерації пейлоада.
    """
    log_messages_route = [f"[ROUTE_PAYLOAD_GEN v{config.VERSION_BACKEND}] Запит /api/payload/generate о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    
    request_json_data = request.get_json()
    if not request_json_data:
        log_messages_route.append("[ROUTE_PAYLOAD_GEN_ERROR] Не отримано JSON даних у запиті.")
        return jsonify({
            "success": False, 
            "error": "No JSON data provided", 
            "generationLog": "\n".join(log_messages_route)
        }), 400

    try:
        # Виклик основної логіки генерації пейлоада
        response_data, status_code = handle_payload_generation_logic(request_json_data, log_messages_route)
        return jsonify(response_data), status_code
    except Exception as e:
        # Загальна обробка непередбачених помилок на рівні маршруту
        log_messages_route.append(f"[ROUTE_PAYLOAD_GEN_FATAL_ERROR] Непередбачена помилка: {str(e)}")
        # Додати traceback до логів для діагностики, якщо потрібно
        # import traceback
        # log_messages_route.append(traceback.format_exc())
        return jsonify({
            "success": False,
            "error": "An unexpected server error occurred.",
            "generationLog": "\n".join(log_messages_route)
        }), 500

# Інші маршрути, пов'язані з пейлоадами, можуть бути додані тут.
# Наприклад, для отримання списку доступних архетипів:
@payload_bp.route('/archetypes', methods=['GET'])
def get_payload_archetypes_route():
    """
    Маршрут для отримання списку доступних архетипів пейлоадів.
    """
    log_messages_route = [f"[ROUTE_PAYLOAD_ARCHETYPES v{config.VERSION_BACKEND}] Запит /api/payload/archetypes о {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."]
    try:
        archetypes_info = []
        for name, details in config.CONCEPTUAL_ARCHETYPE_TEMPLATES_BE.items():
            archetypes_info.append({
                "name": name,
                "description": details.get("description", "Опис відсутній")
            })
        
        log_messages_route.append(f"[ROUTE_PAYLOAD_ARCHETYPES_SUCCESS] Повернено {len(archetypes_info)} архетипів.")
        return jsonify({"success": True, "archetypes": archetypes_info, "log": "\n".join(log_messages_route)}), 200
    except Exception as e:
        log_messages_route.append(f"[ROUTE_PAYLOAD_ARCHETYPES_ERROR] Помилка: {str(e)}")
        return jsonify({"success": False, "error": "Server error retrieving archetypes", "log": "\n".join(log_messages_route)}), 500
