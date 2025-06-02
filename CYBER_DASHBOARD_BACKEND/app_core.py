# app_core.py
# Основний файл ініціалізації Flask-додатку CYBER DASHBOARD

import os
from flask import Flask
from flask_cors import CORS
from datetime import datetime # Додано datetime для health_check

# Імпорт конфігурацій
import config

# Глобальні змінні стану C2 та функція ініціалізації ВИДАЛЕНІ ЗВІДСИ.
# Вони тепер знаходяться та керуються в модулі c2_control.logic

def create_app():
    """
    Створює та налаштовує екземпляр Flask-додатку.
    """
    app = Flask(__name__)
    CORS(app) 

    # Ініціалізація симульованих імплантів відбувається всередині модуля c2_control.logic
    # при його імпорті.

    # Реєстрація Blueprints для кожного модуля
    from payload_generator.routes import payload_bp
    app.register_blueprint(payload_bp) # Префікс /api/payload вже визначено в payload_bp

    from reconnaissance.routes import recon_bp
    app.register_blueprint(recon_bp) # Префікс /api/recon вже визначено в recon_bp

    from c2_control.routes import c2_bp
    app.register_blueprint(c2_bp) # Префікс /api/c2 вже визначено в c2_bp

    from operational_data.routes import ops_bp
    app.register_blueprint(ops_bp) # Префікс /api/data вже визначено в ops_bp


    @app.route('/api/health', methods=['GET'])
    def health_check():
        return {"status": "healthy", "version": config.VERSION_BACKEND, "timestamp": datetime.now().isoformat()}, 200

    print(f"Flask app created. Version: {config.VERSION_BACKEND}")
    return app

if __name__ == '__main__':
    app = create_app()
    
    print("="*60)
    print(f"Syntax Framework - Концептуальний Backend v{config.VERSION_BACKEND} (Refactored Core)")
    print("Запуск Flask-сервера на http://localhost:5000")
    print("Доступні ендпоінти:")
    print("  GET  /api/health (тестовий)")
    print("  POST /api/payload/generate (Модуль Payload Generator)")
    print("  GET  /api/payload/archetypes (Модуль Payload Generator)")
    print("  POST /api/recon/run (Модуль Reconnaissance)")
    print("  GET  /api/recon/types (Модуль Reconnaissance)")
    print("  POST /api/c2/beacon_receiver (Модуль C2 Control)")
    print("  GET  /api/c2/dns_resolver_sim (Модуль C2 Control)")
    print("  GET  /api/c2/implants (Модуль C2 Control)")
    print("  POST /api/c2/task (Модуль C2 Control)")
    print("  GET  /api/data/operational (Модуль Operational Data)")
    print("  POST /api/data/framework_rules (Модуль Operational Data)")
    print("\nПереконайтеся, що 'nmap' встановлено та доступно в системному PATH для використання Nmap-сканувань.")
    print("Для генерації .EXE пейлоадів, 'PyInstaller' має бути встановлений та доступний в системному PATH.")
    print("Для повноцінного використання NVD API (пошук CVE), рекомендується встановити змінну середовища NVD_API_KEY. Без ключа можливі обмеження частоти запитів.")
    print("Натисніть Ctrl+C для зупинки.")
    print("="*60)
    
    app.run(host='localhost', port=5000, debug=False)
