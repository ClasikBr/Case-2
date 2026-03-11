import re
import base64
import codecs
from typing import Any
from datetime import datetime


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
    Searches for ips, files, emails.
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


def decode_base64(text):
    try:
        text = text.strip()
        text = text + '=' * (-len(text) % 4)
        decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
        return decoded
    except:
        return None

def decode_hex(text):

    """Декодирует Hex строку"""

    try:
        text = text.lower().replace('0x', '').strip()
        text = re.sub(r'[^0-9a-f]', '', text)
        if text and len(text) % 2 == 0:
            decoded = bytes.fromhex(text).decode('utf-8', errors='ignore')
            return decoded
    except:
        pass
    return None

def decode_rot13(text):

    """Декодирует ROT13 строку"""

    try:
        decoded = codecs.decode(text, 'rot_13')
        return decoded
    except:
        return None


def decode_messages(text: str) -> dict[str, list[str]]:

    decoded_base64 = []
    decoded_hex = []
    decoded_rot13 = []

    common_passwords = [
        "password", "pass123", "123456", "qwerty", "admin", "admin123",
        "welcome", "login", "user123", "root", "toor", "12345678",
        "123456789", "12345", "1234", "1234567890", "password123",
        "summer2024", "summer2023", "summer2025", "summer2024!",
        "winter2024", "spring2024", "autumn2024", "fall2024",
        "qwerty123", "qwerty123!", "q1w2e3r4", "q1w2e3r4t5",
        "passw0rd", "p@ssw0rd", "p455w0rd", "password1", "Password1",
        "Pass1234", "pass1234", "admin123!", "Admin123",
        "Summer2024!", "Summer2023!", "Summer2025!", "ROT13"
    ]

    base64_pattern = r'[A-Za-z0-9+/]{11,}+={0,2}'
    base64_matches = re.findall(base64_pattern, text)

    for match in base64_matches:
        common_words = ['the', 'and', 'is', 'in', 'to', 'of', 'for', 'with', 'this', 'that', 'password', 'secret']
        if len(match) >= 8:
            decoded = decode_base64(match)
            if decoded and all(32 <= ord(c) <= 126 for c in decoded[:50]) and \
                    any(word in decoded.lower() for word in common_words):
                if decoded not in decoded_base64:
                    decoded_base64.append(decoded)

    hex_patterns = [
        r'0x[0-9a-fA-F]+',
        r'\b[0-9a-fA-F]{8,}\b'
    ]

    for pattern in hex_patterns:
        hex_matches = re.findall(pattern, text)
        for match in hex_matches:
            decoded = decode_hex(match)
            if decoded and decoded.strip() and all(32 <= ord(c) <= 126 for c in decoded[:50]):
                if decoded not in decoded_hex:
                    decoded_hex.append(decoded)

    def decode_rot13_with_passwords(encoded_text):
        """Декодирует ROT13, но сохраняет пароли в исходном виде"""
        words = encoded_text.split()
        decoded_words = []

        for word in words:
            is_password = False
            word_clean = word.strip('.,!?;:')

            for pwd in common_passwords:
                if pwd.lower() == word_clean.lower() or pwd in word_clean:
                    is_password = True
                    break

            if is_password:
                decoded_words.append(word)
            else:
                decoded = decode_rot13(word)
                if decoded:
                    decoded_words.append(decoded)
                else:
                    decoded_words.append(word)

        return ' '.join(decoded_words)

    rot13_label_pattern = r'ROT13:\s*([A-Za-z0-9\s!@#$%&*_]+)'
    labeled_matches = re.findall(rot13_label_pattern, text, re.IGNORECASE)

    for match in labeled_matches:
        candidate = match.strip()
        decoded = decode_rot13_with_passwords(candidate)
        if decoded and decoded not in decoded_rot13:
            decoded_rot13.append(decoded)

    sentences = re.split(r'[.!?\n\r]+', text)

    for sentence in sentences:
        words = re.findall(r'[A-Za-z0-9!@#$%&*_]+', sentence)
        if len(words) >= 2:
            potential_rot13 = ' '.join(words)
            if any(c.isalpha() for word in words for c in word):
                decoded = decode_rot13_with_passwords(potential_rot13)
                common_words = ['the', 'is', 'are', 'password', 'secret', 'key', 'access']
                decoded_lower = decoded.lower()
                if any(word in decoded_lower for word in common_words) and decoded != potential_rot13:
                    if decoded not in decoded_rot13:
                        decoded_rot13.append(decoded)

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
    """
    phones = {"valid": [], "invalid": []}
    dates = {"normalized": [], "invalid": []}
    inn = {"valid": [], "invalid": []}
    cards = {"valid": [], "invalid": []}

    phone_patterns = [
        r'\+7[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}',
        r'8[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}',
        r'\d{10}',
        r'\d{11}'
    ]

    for pattern in phone_patterns:
        matches = re.findall(pattern, text)
        for phone in matches:
            clean_phone = re.sub(r'[\s-]', '', phone)

            if len(clean_phone) == 10 and clean_phone.isdigit():
                normalized = f"+7{clean_phone}"
                if normalized not in phones['valid'] and normalized not in phones['invalid']:
                    phones['valid'].append(normalized)
            elif len(clean_phone) == 11 and clean_phone.isdigit():
                if clean_phone.startswith('8'):
                    normalized = f"+7{clean_phone[1:]}"
                elif clean_phone.startswith('7'):
                    normalized = f"+{clean_phone}"
                else:
                    normalized = f"+7{clean_phone}"

                if normalized not in phones['valid'] and normalized not in phones['invalid']:
                    phones['valid'].append(normalized)
            else:
                if clean_phone not in phones['invalid']:
                    phones['invalid'].append(clean_phone)

    date_patterns = [
        (r'\d{2}\.\d{2}\.\d{4}', '%d.%m.%Y'),  # DD.MM.YYYY
        (r'\d{4}\.\d{2}\.\d{2}', '%Y.%m.%d'),  # YYYY.MM.DD
        (r'\d{2}-\d{2}-\d{4}', '%d-%m-%Y'),  # DD-MM-YYYY
        (r'\d{4}-\d{2}-\d{2}', '%Y-%m-%d'),  # YYYY-MM-DD
        (r'\d{2}/\d{2}/\d{4}', '%d/%m/%Y'),  # DD/MM/YYYY
        (r'\d{4}/\d{2}/\d{2}', '%Y/%m/%d'),  # YYYY/MM/DD
        (r'\d{2}-[A-Za-z]{3}-\d{4}', '%d-%b-%Y')  # DD-MMM-YYYY
    ]


    for pattern, fmt in date_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for date_str in matches:
            try:
                if '%b' in fmt:
                    date_obj = datetime.strptime(date_str, fmt)
                else:
                    date_obj = datetime.strptime(date_str, fmt)

                normalized = date_obj.strftime('%Y-%m-%d')

                if 1900 <= date_obj.year <= 2100:
                    if normalized not in dates['normalized'] and normalized not in dates['invalid']:
                        dates['normalized'].append(normalized)
                else:
                    if date_str not in dates['invalid']:
                        dates['invalid'].append(date_str)

            except (ValueError, TypeError):
                if date_str not in dates['invalid']:
                    dates['invalid'].append(date_str)

    cards_result = find_and_validate_credit_cards(text)
    cards['valid'] = cards_result['valid']
    cards['invalid'] = cards_result['invalid']

    inn_pattern = r'\b\d{10}\b|\b\d{12}\b'
    inn_matches = re.findall(inn_pattern, text)

    for inn_num in inn_matches:
        if validate_inn(inn_num):
            if inn_num not in inn['valid'] and inn_num not in inn['invalid']:
                inn['valid'].append(inn_num)
        else:
            if inn_num not in inn['invalid']:
                inn['invalid'].append(inn_num)

    cards_result = find_and_validate_credit_cards(text)
    cards['valid'] = cards_result['valid']
    cards['invalid'] = cards_result['invalid']

    return {
        "phones": phones,
        "dates": dates,
        'inn': inn,
        "cards": cards
    }


def validate_inn(inn: str) -> bool:

    if not inn.isdigit():
        return False

    if len(inn) == 10:
        weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        check_sum = sum(int(inn[i]) * weights[i] for i in range(9)) % 11 % 10
        return check_sum == int(inn[9])

    elif len(inn) == 12:
        weights1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        weights2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]

        check_sum1 = sum(int(inn[i]) * weights1[i] for i in range(10)) % 11 % 10
        check_sum2 = sum(int(inn[i]) * weights2[i] for i in range(11)) % 11 % 10

        return check_sum1 == int(inn[10]) and check_sum2 == int(inn[11])

    return False


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

    financial = report.get("financial_data", {})
    secrets = report.get("secrets", {})
    info = report.get("system_info", {})
    logs = report.get("security_threats", {})

    valid.update(financial.get("valid", []), info.get('ips', []), info.get('files', []),
                 info.get('emails', []), secrets.get("API", []), secrets.get("Passwords", []),
                 logs.get('sql_injections', []), logs.get('xss_attempts', []),
                 logs.get('suspicious_user_agents', []), logs.get('failed_logins', [])
                 )


    with open(filename, "w", encoding="utf-8") as file:
        file.write("=== VALID ARTIFACTS ===\n")
        for item in sorted(valid):
            file.write(f"{item}\n")


def count_artifacts(filepath: str) -> None:
    """
    Count valid and invalid artifacts and print totals.
    """
    with open(filepath, "r", encoding="utf-8") as file:
        lines = file.readlines()

    valid_header = "=== VALID ARTIFACTS ==="
    valid_count = 0
    start_counting = False

    for line in lines:
        stripped = line.strip()
        if stripped == valid_header:
            start_counting = True
            continue
        if start_counting and stripped:
            valid_count += 1
    print("\nUNIQUE_ARTIFACTS_COUNT:")
    print("-" * 30)
    print(f"Valid artifacts:   {valid_count}")


def main() -> None:
    """
    Beginning of the program.
    """

    with open("input.txt", "r", encoding="utf-8") as file:
        text = file.read()

    report = generate_comprehensive_report(text)
    print_report(report)
    save_artifacts(report)
    count_artifacts('all_artifacts.txt')


if __name__ == "__main__":
    main()
