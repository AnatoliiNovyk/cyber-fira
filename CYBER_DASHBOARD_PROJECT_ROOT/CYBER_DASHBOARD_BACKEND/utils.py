# utils.py
# Загальні допоміжні функції для проекту CYBER DASHBOARD

import base64
import random
import string

def xor_cipher(data_str: str, key: str) -> str:
    """
    Виконує операцію XOR-шифрування/дешифрування рядка.

    Args:
        data_str: Рядок для шифрування/дешифрування.
        key: Ключ шифрування.

    Returns:
        Зашифрований або розшифрований рядок.
    """
    if not key: 
        key = "DefaultXOR_Key_v3_Fallback" # Резервний ключ, якщо передано порожній
    return "".join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data_str)])

def b64_encode_str(data_str: str) -> str:
    """
    Кодує рядок у формат Base64.
    Використовує 'latin-1' для збереження всіх можливих байтових значень після XOR.

    Args:
        data_str: Рядок для кодування.

    Returns:
        Рядок, закодований у Base64.
    """
    return base64.b64encode(data_str.encode('latin-1')).decode('utf-8')

def b64_decode_str(b64_data_str: str) -> str:
    """
    Декодує рядок з формату Base64.
    Використовує 'latin-1' для коректного декодування байтів, що можуть бути результатом XOR.

    Args:
        b64_data_str: Рядок у Base64 для декодування.

    Returns:
        Декодований рядок.
    """
    decoded_bytes = base64.b64decode(b64_data_str.encode('utf-8'))
    return decoded_bytes.decode('latin-1')


def generate_random_var_name(length: int = 10, prefix: str = "syn_var_") -> str:
    """
    Генерує випадкове ім'я змінної.

    Args:
        length: Довжина випадкової частини імені (після префіксу).
        prefix: Префікс для імені змінної.

    Returns:
        Випадково згенероване ім'я змінної.
    """
    return prefix + ''.join(random.choice(string.ascii_lowercase + '_') for _ in range(length))

def get_service_name_be(port: int) -> str:
    """
    Повертає назву сервісу за стандартним номером порту (концептуально).

    Args:
        port: Номер порту.

    Returns:
        Назва сервісу або "Unknown".
    """
    services = { 
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
        80: "HTTP", 110: "POP3", 135: "MSRPC", 137: "NetBIOS-NS", 
        138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 443: "HTTPS", 
        445: "Microsoft-DS", 1433: "MSSQL", 3306: "MySQL", 
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 
        8000: "HTTP-Alt", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    return services.get(port, "Unknown")

# Приклад використання (можна закоментувати або видалити для продакшену)
if __name__ == '__main__':
    original_string = "Це тестовий рядок для XOR!"
    xor_key = "MySecretKey123"
    
    encrypted_string = xor_cipher(original_string, xor_key)
    print(f"Оригінал: {original_string}")
    print(f"Ключ XOR: {xor_key}")
    print(f"Зашифровано XOR: {encrypted_string}")
    
    decrypted_string = xor_cipher(encrypted_string, xor_key)
    print(f"Розшифровано XOR: {decrypted_string}")

    b64_encoded = b64_encode_str(encrypted_string)
    print(f"Зашифровано XOR+B64: {b64_encoded}")
    
    b64_decoded_xor_part = b64_decode_str(b64_encoded)
    final_decrypted = xor_cipher(b64_decoded_xor_part, xor_key)
    print(f"Розшифровано з XOR+B64: {final_decrypted}")

    print(f"Випадкове ім'я змінної: {generate_random_var_name()}")
    print(f"Сервіс для порту 80: {get_service_name_be(80)}")
    print(f"Сервіс для порту 9999: {get_service_name_be(9999)}")
