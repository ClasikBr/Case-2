import re
import base64
import codecs
from typing import Any


def find_and_validate_credit_cards(text: str) -> dict[str, list[str]]:
    """
    Finds bank card numbers and checks them using the Luna algorithm.
    """
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
    """
    Checks the card number using the Luna algorithm.
    """
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


def find_secrets(text: str) -> dict:
    """
    Searches for API and passwords.
    """
    API = []
    PASSWORD = []
    pattern_secret_API = r'\bsk_(?:test|live)_[A-Za-z\d]+\b'
    pattern_public_API = r'\bpk_(?:test|live)_[A-Za-z\d]+\b'
    API.extend(re.findall(pattern_secret_API, text))
    API.extend(re.findall(pattern_public_API, text))

    allowed_pattern = r'[A-Za-z\d!@#$%&*_]{8,}'
    candidates = re.findall(allowed_pattern, text)


    def has_required_classes(pwd):
        return (re.search(r'[a-z]', pwd) and
                re.search(r'[A-Z]', pwd) and
                re.search(r'\d', pwd) and
                re.search(r'[!@#$%&*]', pwd))

    forbidden_substrings = [
        "kirill", "platon", "artemiy", "zhamso",
        "winter", "spring", "summer", "autumn", "fall",
        "qwerty", "q1w2e3r4", "qwerty123", "123456",
        "qazwsx", "password", "admin"
    ]

    for pwd in candidates:
        if not has_required_classes(pwd):
            continue
        lower_pwd = pwd.lower()
        if any(forbidden in lower_pwd for forbidden in forbidden_substrings):
            continue
        PASSWORD.append(pwd)

    API = list(set(API))
    PASSWORD = list(set(PASSWORD))
    return {"API": API, "Passwords": PASSWORD}


def find_system_info(text: str) -> dict[str, list[str]]:
    """
    Searches for API keys, tokens, passwords.
    """
    ips_pattern = r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
    windows_file_pattern = r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+\b"
    linux_file_pattern = r"\b/(?:[^/\s]+/)*[^/\s]+\b"
    email_patter = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"

    ips = re.findall(ips_pattern, text)
    files = re.findall(windows_file_pattern, text)
    files.extend(re.findall(linux_file_pattern, text))
    emails = re.findall(email_patter, text)

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
    """Analyzes web server logs for attacks."""
    sql_patterns = [
        r"'\s+OR\s+'", r"OR\s+1\s*=\s*1", r"UNION\s+SELECT",
        r"--", r";", r"'\s+AND\s+'", r"'\s*="
    ]

    xss_patterns = [
        r"<script", r"alert\s*\(", r"onerror\s*=",
        r"onload\s*=", r"javascript:", r"<[^>]+on\w+\s*="
    ]

    suspicious_agents = [
        "EvilBot", "sqlmap", "nikto", "zgrab", "masscan",
        "nmap", "nessus", "openvas", "python-requests", "go-http-client"
    ]

    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'

    sql_injections = []
    xss_attempts = []
    suspicious_user_agents = []
    failed_logins = []

    lines = log_text.strip().split('\n')
    for line in lines:
        if not line.strip():
            continue
        line = line.strip()

        ip_matches = list(re.finditer(ip_pattern, line))
        if not ip_matches:
            continue

        for i, ip_match in enumerate(ip_matches):
            start = ip_match.start()
            end = ip_matches[i + 1].start() if i + 1 < len(ip_matches) else len(line)
            record = line[start:end].strip()
            if record.endswith(','):
                record = record[:-1]

            ip = ip_match.group(0)

            request_match = re.search(r'"[^"]*"', record)
            request = request_match.group(0) if request_match else ""

            is_sql = False
            for pat in sql_patterns:
                if re.search(pat, record, re.IGNORECASE):
                    sql_injections.append(f"{ip} - {request}")
                    is_sql = True
                    break

            if not is_sql:
                for pat in xss_patterns:
                    if re.search(pat, record, re.IGNORECASE):
                        xss_attempts.append(f"{ip} - {request}")
                        break

            for agent in suspicious_agents:
                if agent.lower() in record.lower():
                    suspicious_user_agents.append(f"{ip} - {agent}")
                    break

            if re.search(r'\s(401|403)\s', record):
                failed_logins.append(f"{ip} - {request}")

    return {
        'sql_injections': sql_injections,
        'xss_attempts': xss_attempts,
        'suspicious_user_agents': suspicious_user_agents,
        'failed_logins': failed_logins
    }


def normalize_and_validate(text: str) -> dict[str, Any]:
    """
    Normalizes telephone numbers, dates, tax identification numbers, and cards.

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
    Generates a full investigation report.
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
    It outputs a report to the console.
    """
    print("=" * 50)
    print("ОТЧЁТ ОПЕРАЦИИ 'DATA SHIELD'")
    print("=" * 50)

    for title, data in report.items():
        print(f"\n{title.upper()}:")
        print("-" * 30)
        print(data)


def save_artifacts(report: dict[str, Any], filename: str = "all_artifacts.txt") -> None:
    """
    Saves all unique artifacts to a file.
    """
    valid: set[str] = set()
    invalid: set[str] = set()

    financial = report.get("financial_data", {})
    secrets = report.get("secrets", {})
    info = report.get("system_info", {})

    valid.update(financial.get("valid", []), info.get('ips', []), info.get('files', []),
                 info.get('emails', []), secrets.get("API", []), secrets.get("Passwords", []))
    invalid.update(financial.get("invalid", []))


    with open(filename, "w", encoding="utf-8") as file:
        file.write("=== VALID ARTIFACTS ===\n")
        for item in sorted(valid):
            file.write(f"{item}\n")

        file.write("\n=== INVALID / NOISY ARTIFACTS ===\n")
        for item in sorted(invalid):
            file.write(f"{item}\n")


def main() -> None:
    """
    Beginning of the program.
    """

    with open("input.txt", "r", encoding="utf-8") as file:
        text = file.read()

    report = generate_comprehensive_report(text)
    print_report(report)
    save_artifacts(report)


if __name__ == "__main__":
    main()

