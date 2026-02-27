# operation_data_shield.py
import re
import base64
import codecs
# Здесь команда размещает все функции
def generate_comprehensive_report(main_text, log_text, messy_data):
    """ Генерирует полный отчет о расследовании """
    report = { 'financial_data': find_and_validate_credit_cards(main_text),
               'secrets': find_secrets(main_text),
               'system_info': find_system_info(main_text),
               'encoded_messages': decode_messages(main_text),
               'security_threats': analyze_logs(log_text),
               'normalized_data': normalize_and_validate(messy_data)
               }
    return report


def print_report(report):
    """Красиво выводит отчет"""
    print("=" * 50)
    print("ОТЧЕТ ОПЕРАЦИИ 'DATA SHIELD'")
    print("=" * 50)
    # Вывод результатов каждой роли
    sections = [ ("ФИНАНСОВЫЕ ДАННЫЕ", report['financial_data']),
                 ("СЕКРЕТНЫЕ КЛЮЧИ", report['secrets']),
                 ("СИСТЕМНАЯ ИНФОРМАЦИЯ", report['system_info']),
                 ("РАСШИФРОВАННЫЕ СООБЩЕНИЯ", report['encoded_messages']),
                 ("УГРОЗЫ БЕЗОПАСНОСТИ", report['security_threats']),
                 ("НОРМАЛИЗОВАННЫЕ ДАННЫЕ", report['normalized_data']) ]
    for title, data in sections:
        print(f"\n{title}:")
        print("-" * 30)
        # Детальный вывод данных...

if __name__ == "__main__":
    # Чтение файлов с данными
    with open('data_leak_sample.txt', 'r', encoding='utf-8') as f:
        main_text = f.read()
    with open('web_server_logs.txt', 'r', encoding='utf-8') as f:
        log_text = f.read()
    with open('messy_data.txt', 'r', encoding='utf-8') as f:
        messy_data = f.read()
        # Запуск расследования
        report = generate_comprehensive_report(main_text, log_text, messy_data)
        print_report(report)