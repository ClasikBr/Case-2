import re
import base64
import codecs
from typing import Any


def find_and_validate_credit_cards(text: str) -> dict[str, list[str]]:
    """Finds bank card numbers and checks them using the Luna algorithm"""
    valid_cards = []
    invalid_cards = []
    pattern=r"(?:\d[ -]?){16}"
    raw_cards=re.findall(pattern, text)

    for card in raw_cards:
        clean=re.sub(r"[ -]", "", card)
        if len(clean)!=16 or not clean.isdigit():
            invalid_cards.append(clean)
            continue
        if Luhn_algorithm(clean):
            valid_cards.append(clean)
        else:
            invalid_cards.append(clean)
    return {
        "valid": valid_cards,
        "invalid": invalid_cards
    }

def Luhn_algorithm(card_num:str)-> bool:
    '''Checks the card number using the Luna algorithm'''
    digits=[int(d) for d in card_num]
    check_sm = 0

    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            doubled = digit * 2
            if doubled > 9:
                doubled -= 9
            check_sm += doubled
        else:
            check_sm += digit
    return check_sm % 10 ==0


def find_secrets(text: str) -> list[str]:
    """
    Ищет API-ключи, токены, пароли.

    Args:
        text (str): Входной текст.

    Returns:
        list[str]: Список найденных секретов.
    """
    secrets = []

    # TODO: реализовать поиск секретов (регулярки)

    return secrets


def find_system_info(text: str) -> dict[str, list[str]]:
    """
    Ищет системную информацию: IP-адреса, email, пути к файлам.

    Args:
        text (str): Входной текст.

    Returns:
        dict[str, list[str]]: Словарь с ключами:
            - "ips": список IP-адресов
            - "files": список путей к файлам
            - "emails": список email-адресов
    """
    ips = []
    files = []
    emails = []

    # TODO: реализовать поиск IP, email, файлов

    return {
        "ips": ips,
        "files": files,
        "emails": emails
    }


def decode_messages(text: str) -> dict[str, list[str]]:
    """
    Находит и расшифровывает сообщения в Base64, Hex, ROT13.

    Args:
        text (str): Входной текст.

    Returns:
        dict[str, list[str]]: Словарь:
            - "base64": список расшифрованных Base64 сообщений
            - "hex": список расшифрованных Hex сообщений
            - "rot13": список расшифрованных ROT13 сообщений
    """
    decoded_base64 = []
    decoded_hex = []
    decoded_rot13 = []

    # TODO: реализовать поиск и декодирование

    return {
        "base64": decoded_base64,
        "hex": decoded_hex,
        "rot13": decoded_rot13
    }


def analyze_logs(log_text: str) -> dict[str, list[str]]:
    """
    Анализирует логи веб-сервера на предмет атак.

    Args:
        log_text (str): Текст логов.

    Returns:
        dict[str, list[str]]: Словарь:
            - "sql_injections": найденные SQL-инъекции
            - "xss_attempts": попытки XSS
            - "suspicious_user_agents": подозрительные User-Agent
            - "failed_logins": неудачные попытки входа
    """
    sql_injections = []
    xss_attempts = []
    suspicious_agents = []
    failed_logins = []

    # TODO: реализовать анализ логов

    return {
        "sql_injections": sql_injections,
        "xss_attempts": xss_attempts,
        "suspicious_user_agents": suspicious_agents,
        "failed_logins": failed_logins
    }


def normalize_and_validate(text: str) -> dict[str, Any]:
    """
    Нормализует телефоны, даты, ИНН, карты.

    Args:
        text (str): Входной текст.

    Returns:
        dict[str, Any]: Словарь:
            - "phones": {"valid": [], "invalid": []}
            - "dates": {"normalized": [], "invalid": []}
            - "inn": {"valid": [], "invalid": []}
            - "cards": {"valid": [], "invalid": []}
    """
    phones = {"valid": [], "invalid": []}
    dates = {"normalized": [], "invalid": []}
    inn = {"valid": [], "invalid": []}
    cards = {"valid": [], "invalid": []}

    # TODO: реализовать нормализацию и валидацию

    return {
        "phones": phones,
        "dates": dates,
        "inn": inn,
        "cards": cards
    }


def generate_comprehensive_report(text: str) -> dict[str, Any]:
    """
    Генерирует полный отчёт о расследовании.

    Args:
        text (str): Входной текст (единый файл).

    Returns:
        dict[str, Any]: Структурированный отчёт.
    """
    return {
        "financial_data": find_and_validate_credit_cards(text),
        "secrets": find_secrets(text),
        "system_info": find_system_info(text),
        "encoded_messages": decode_messages(text),
        "security_threats": analyze_logs(text),
        "normalized_data": normalize_and_validate(text)
    }


def print_report(report: dict[str, Any]) -> None:
    """
    Красиво выводит отчёт в консоль.

    Args:
        report (dict[str, Any]): Сформированный отчёт.
    """
    print("=" * 50)
    print("ОТЧЁТ ОПЕРАЦИИ 'DATA SHIELD'")
    print("=" * 50)

    for title, data in report.items():
        print(f"\n{title.upper()}:")
        print("-" * 30)
        print(data)


def save_artifacts(report: dict[str, Any], filename: str = "all_artifacts.txt") -> None:
    """Saves all unique artifacts to a file"""
    valid: set[str] = set()
    invalid: set[str] = set()

    financial = report.get("financial_data", {})
    valid.update(financial.get("valid", []))
    invalid.update(financial.get("invalid", []))

    with open(filename, "w", encoding="utf-8") as file:
        file.write("=== VALID ARTIFACTS ===\n")
        for item in sorted(valid):
            file.write(f"{item}\n")

        file.write("\n=== INVALID / NOISY ARTIFACTS ===\n")
        for item in sorted(invalid):
            file.write(f"{item}\n")


def main() -> None:
    """beginning of the program"""

    with open("input.txt", "r", encoding="utf-8") as file:
        text = file.read()

    report = generate_comprehensive_report(text)
    print_report(report)
    save_artifacts(report)


if __name__ == "__main__":
    main()
