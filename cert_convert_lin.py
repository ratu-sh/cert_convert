#pip install pyopenssl requests cryptography certifi #pyinstaller

## Определите пути к openssl, libcrypto и libssl, а затем используйте их в команде:
#OPENSSL_BIN_PATH=$(which openssl)
#LIBCRYPTO_PATH=$(ldconfig -p | grep libcrypto.so | awk '{print $4}' | head -1)
#LIBSSL_PATH=$(ldconfig -p | grep libssl.so | awk '{print $4}' | head -1)

##OPENSSL_BIN_PATH=/bin/openssl
##LIBCRYPTO_PATH=/usr/lib/x86_64-linux-gnu/libcrypto.so.3
##LIBSSL_PATH=/usr/lib/x86_64-linux-gnu/libssl.so

## Собираем бинарник с PyInstaller, добавляя найденные файлы
#/usr/local/bin/pyinstaller --onefile --clean \
#--hidden-import ctypes --hidden-import shutil --hidden-import OpenSSL --hidden-import cryptography --hidden-import certifi --hidden-import requests \
#--add-binary "${OPENSSL_BIN_PATH}:." \
#--add-binary "${LIBCRYPTO_PATH}:." \
#--add-binary "${LIBSSL_PATH}:." \
#cert_convert_lin.py

import re
import os
import sys
import ctypes
import subprocess
from OpenSSL import crypto
from shutil import copyfile

## Указываем путь к системным бинарным файлам OpenSSL
os.environ['PATH'] = "/usr/bin:"
## Указываем путь к системным библиотекам OpenSSL
os.environ['LD_LIBRARY_PATH'] = "/usr/lib:/usr/local/lib:"

# # Раскомментить строки ниже вместо 2 строк выше при сборке в Pyinstaller
#
# # Определяем путь к временной директории, куда распаковывается бинарник
# if hasattr(sys, '_MEIPASS'):
#    base_path = sys._MEIPASS
# else:
#    base_path = os.path.dirname(os.path.abspath(__file__))
#
# # Устанавливаем PATH и LD_LIBRARY_PATH для использования локальных библиотек OpenSSL
# os.environ['PATH'] = f"{base_path}:{os.environ.get('PATH', '')}"
# os.environ['LD_LIBRARY_PATH'] = f"{base_path}:{os.environ.get('LD_LIBRARY_PATH', '')}"
#
# #print(f"PATH установлен на: {os.environ['PATH']}")
# #print(f"LD_LIBRARY_PATH установлен на: {os.environ.get('LD_LIBRARY_PATH', '')}")

## Проверка доступности библиотек OpenSSL
try:
    ctypes.CDLL("libcrypto.so.3")
    ctypes.CDLL("libssl.so.3")
    print("-------------------------------------------")
    print("Библиотеки OpenSSL загружены успешно.")
except OSError as e:
    print("-------------------------------------------")
    print(f"Ошибка загрузки библиотек OpenSSL: {e}. Сначала установите openssl.")

# 0 =======================================================================================
def find_cert_files():
    """Находит все файлы сертификатов и ключей в текущей директории."""
    extensions = [
        '.pem', '.crt', '.cer', '.der', '.pfx', '.p12', '.p7b', '.p7c', '.key', 
        '.rsa', '.pvk', '.ppk', '.ssh', '.pub', '.openssh', '.cert', '.p8'
    ]
    files = [f for f in os.listdir('.') if os.path.isfile(f) and any(f.lower().endswith(ext) for ext in extensions)]
    return files

def display_files(files):
    """Отображает список файлов и предлагает пользователю выбрать один из них."""
    if not files:
        print("Сертификаты или ключи не найдены в текущей директории.")
        return None

    print("Найдены следующие файлы сертификатов и ключей:")
    for i, file in enumerate(files, 1):
        print(f"{i}. {file}")

    choice = input("Выберите номер файла: ")
    try:
        return files[int(choice) - 1]
    except (IndexError, ValueError):
        print("Неверный выбор.")
        return None

# 0 =======================================================================================

def is_cer_format(cert_path):
    """Проверяет, является ли файл сертификатом в формате CER."""
    # CER обычно используется для DER-формата, но может быть и в PEM
    return is_der_format(cert_path) or is_pem_format(cert_path)

def is_crt_format(cert_path):
    """Проверяет, является ли файл сертификатом в формате CRT."""
    # CRT обычно используется для PEM-формата
    return is_pem_format(cert_path) or is_der_format(cert_path)

def is_key_format(cert_path):
    """Проверяет, является ли файл ключом в формате PEM или DER."""
    try:
        with open(cert_path, "rb") as key_file:
            key_data = key_file.read()
            # Проверка на PEM-заголовок для ключей
            if b'-----BEGIN' in key_data and b'PRIVATE KEY-----' in key_data:
                return True
            # Проверка с использованием openssl на DER-формат
            result = subprocess.run(['openssl', 'rsa', '-inform', 'DER', '-in', cert_path, '-noout'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
    except Exception:
        return False

def is_pem_format(cert_path):
    """Проверяет, является ли файл сертификатом в формате PEM."""
    try:
        with open(cert_path, "rb") as cert_file:
            cert_data = cert_file.read()
            return b'-----BEGIN CERTIFICATE-----' in cert_data
    except Exception:
        return False

def is_der_format(cert_path):
    """Проверяет, является ли файл сертификатом в формате DER с помощью команды openssl."""
    try:
        result = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-in', cert_path, '-noout', '-text'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except Exception:
        return False

def is_p7b_format(cert_path):
    """Проверяет, является ли файл сертификатом в формате PKCS#7 (P7B/P7C)."""
    try:
        with open(cert_path, "rb") as cert_file:
            cert_data = cert_file.read()
            # Проверка на наличие PEM-заголовков PKCS#7
            if b'-----BEGIN PKCS7-----' in cert_data and b'-----END PKCS7-----' in cert_data:
                return True
            # Проверка с использованием openssl на DER-формат для PKCS#7
            result = subprocess.run(['openssl', 'pkcs7', '-inform', 'DER', '-in', cert_path, '-noout', '-print_certs'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
    except Exception:
        return False

def is_p7c_format(cert_path):
    """Проверяет, является ли файл сертификатом в формате PKCS#7 (P7B/P7C)."""
    return is_p7b_format(cert_path)  # P7B и P7C имеют одинаковую структуру, разница только в расширении


def is_pfx_format(cert_path):
    """Проверяет, является ли файл сертификатом в формате PFX/P12 с помощью команды openssl."""
    try:
        result = subprocess.run(['openssl', 'pkcs12', '-in', cert_path, '-noout'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except Exception:
        return False

def determine_format(filename):
    """Определяет формат сертификата по расширению и проверяет его корректность."""
    extension = filename.lower().split('.')[-1]

    if extension == 'pem':
        return 'PEM' if is_pem_format(filename) else None
    elif extension == 'der':
        return 'DER' if is_der_format(filename) else None
    elif extension == 'p7b':
        return 'P7B' if is_p7b_format(filename) else None
    elif extension == 'p7c':
        return 'P7C' if is_p7c_format(filename) else None
    elif extension == 'crt':
        return 'CRT' if is_crt_format(filename) else None
    elif extension == 'cer':
        return 'CER' if is_cer_format(filename) else None
    elif extension == 'pfx':
        return 'PFX' if is_pfx_format(filename) else None
    elif extension == 'p12':
        return 'P12' if is_pfx_format(filename) else None
    elif extension == 'key':
        return 'KEY'  # Файлы ключей могут не нуждаться в проверке
    elif extension in ['rsa', 'pvk', 'ppk', 'ssh', 'pub', 'openssh']:
        return 'KEY'  # Секретные и публичные ключи различных форматов
    elif extension == 'cert':
        return 'CERT' if is_pem_format(filename) else None
    elif extension == 'p8':
        return 'P8'  # Файлы PKCS8, возможно, содержат ключи, их нужно проверять отдельно
    else:
        print(f"Неизвестное расширение файла: {extension}")
        return None


# 1 =======================================================================================
        
def split_pfx(pfx_file):
    """Разбивает PFX/P12 на закрытый ключ и сертификат."""
    password = input('Введите пароль для PFX/P12: ')
    private_key_file = 'private.key'
    cert_file = 'public.crt'
    
    try:
        # Извлечение закрытого ключа
        subprocess.run(['openssl', 'pkcs12', '-in', pfx_file, '-nocerts', '-out', private_key_file, '-nodes', '-passin', f'pass:{password}'], check=True)
        # Извлечение сертификата
        subprocess.run(['openssl', 'pkcs12', '-in', pfx_file, '-clcerts', '-nokeys', '-out', cert_file, '-passin', f'pass:{password}'], check=True)
        print(f'Закрытый ключ и сертификат успешно извлечены: {private_key_file}, {cert_file}')
    except subprocess.CalledProcessError as e:
        print(f'Ошибка при разбиении PFX/P12: {e}')
        

# 2 =======================================================================================
def find_private_keys():
    """Находит все файлы приватных ключей в текущей директории."""
    key_extensions = ['.key', '.pem', '.rsa', '.pvk', '.ppk', '.ssh', '.openssh', '.p8']
    files = [f for f in os.listdir('.') if os.path.isfile(f) and any(f.lower().endswith(ext) for ext in key_extensions)]
    return files

def select_private_key():
    """Показывает меню для выбора приватного ключа."""
    private_keys = find_private_keys()
    if not private_keys:
        print("Приватные ключи не найдены в текущей директории.")
        return None

    print("Найдены следующие файлы приватных ключей:")
    for i, key_file in enumerate(private_keys, 1):
        print(f"{i}. {key_file}")

    choice = input("Выберите номер файла приватного ключа: ")
    try:
        return private_keys[int(choice) - 1]
    except (IndexError, ValueError):
        print("Неверный выбор.")
        return None

def has_private_key(pem_file):
    """Проверяет, содержит ли файл PEM закрытый ключ."""
    try:
        with open(pem_file, 'rb') as file:
            content = file.read()
            return b'-----BEGIN PRIVATE KEY-----' in content or b'-----BEGIN ENCRYPTED PRIVATE KEY-----' in content
    except Exception as e:
        print(f'Ошибка при проверке закрытого ключа: {e}')
        return False

def convert_certificate(input_file):
    """Конвертирует сертификат в указанный формат."""
    input_format = determine_format(input_file)
    if not input_format:
        print(f"Файл {input_file} не является допустимым сертификатом.")
        return None

    # Определение доступных выходных форматов в зависимости от входного формата
    supported_formats = {
        'PEM': ['DER', 'PFX', 'P12', 'P7B', 'P7C', 'CRT', 'CER'],
        'DER': ['PEM', 'PFX', 'P12', 'CRT', 'CER', 'P7B', 'P7C'],
        'PFX': ['PEM', 'DER', 'P12', 'CRT', 'CER', 'P7B', 'P7C'],
        'P12': ['PEM', 'DER', 'PFX', 'CRT', 'CER', 'P7B', 'P7C'],
        'P7B': ['PEM', 'PFX', 'P12', 'P7C', 'DER', 'CRT', 'CER'],
        'P7C': ['PEM', 'PFX', 'P12', 'P7B', 'DER', 'CRT', 'CER'],
        'CRT': ['PEM', 'DER', 'PFX', 'P12', 'P7B', 'P7C', 'CER'],
        'CER': ['PEM', 'DER', 'PFX', 'P12', 'P7B', 'P7C', 'CRT'],
        'KEY': ['PEM', 'DER']
    }


    available_formats = supported_formats.get(input_format, [])
    if not available_formats:
        print(f"Нет доступных преобразований для формата {input_format}.")
        return None

    print("Выберите формат для преобразования:")
    for i, fmt in enumerate(available_formats, 1):
        print(f"{i}. {fmt}")

    choice = input("Выберите номер формата: ")
    try:
        output_format = available_formats[int(choice) - 1]
    except (IndexError, ValueError):
        print("Неверный выбор.")
        return None

    output_file = os.path.splitext(input_file)[0] + '.' + output_format.lower()
    if os.path.exists(output_file):
        os.remove(output_file)

    try:
        # Логика для конвертации
        if input_format == output_format:
            print(f"Файл уже в формате {output_format}.")
            return None

        # Конвертации PEM в другие форматы
        elif input_format == 'PEM' and output_format == 'DER':
            subprocess.run(['openssl', 'x509', '-in', input_file, '-outform', 'der', '-out', output_file], check=True)
        elif input_format == 'PEM' and output_format in ['CRT', 'CER']:
            # PEM в CRT или CER (CRT и CER эквиваленты, просто копия файла)
            subprocess.run(['openssl', 'x509', '-in', input_file, '-out', output_file], check=True)
        # Конвертации PEM в PFX или P12
        elif input_format == 'PEM' and output_format in ['PFX', 'P12']:
            if has_private_key(input_file):
                # Если закрытый ключ уже присутствует в файле PEM
                subprocess.run(['openssl', 'pkcs12', '-export', '-out', output_file, '-in', input_file], check=True)
            else:
            # Если закрытый ключ отсутствует, запрашиваем у пользователя
                key_file = select_private_key()
                if not key_file:
                    return None
                subprocess.run(['openssl', 'pkcs12', '-export', '-out', output_file, '-inkey', key_file, '-in', input_file], check=True)         
        elif input_format == 'PEM' and output_format in ['P7B', 'P7C']:
            subprocess.run(['openssl', 'crl2pkcs7', '-nocrl', '-certfile', input_file, '-out', output_file], check=True)

        # Конвертации DER в другие форматы
        elif input_format == 'DER' and output_format == 'PEM':
            subprocess.run(['openssl', 'x509', '-in', input_file, '-inform', 'der', '-out', output_file, '-outform', 'pem'], check=True)
        elif input_format == 'DER' and output_format in ['CRT', 'CER']:
            subprocess.run(['openssl', 'x509', '-in', input_file, '-inform', 'der', '-out', output_file], check=True)
        elif input_format == 'DER' and output_format in ['P7B', 'P7C']:
            temp_pem = "temp.pem"
            subprocess.run(['openssl', 'x509', '-in', input_file, '-inform', 'der', '-out', temp_pem, '-outform', 'pem'], check=True)
            subprocess.run(['openssl', 'crl2pkcs7', '-nocrl', '-certfile', temp_pem, '-out', output_file], check=True)
            os.remove(temp_pem)

        # Конвертации PFX/P12 в другие форматы
        elif input_format in ['PFX', 'P12'] and output_format == 'PEM':
            # Преобразование PFX/P12 в PEM
            subprocess.run(['openssl', 'pkcs12', '-in', input_file, '-out', output_file, '-nodes'], check=True)
        elif input_format in ['PFX', 'P12'] and output_format == 'DER':
            # Сначала преобразуем PFX/P12 в PEM
            temp_pem = "temp.pem"
            subprocess.run(['openssl', 'pkcs12', '-in', input_file, '-out', temp_pem, '-nodes'], check=True)   
            # Затем преобразуем PEM в DER
            subprocess.run(['openssl', 'x509', '-in', temp_pem, '-outform', 'DER', '-out', output_file], check=True)
            os.remove(temp_pem)
        elif input_format in ['PFX', 'P12'] and output_format in ['CRT', 'CER']:
            # Сначала преобразуем PFX/P12 в PEM
            temp_pem = "temp.pem"
            subprocess.run(['openssl', 'pkcs12', '-in', input_file, '-out', temp_pem, '-nokeys'], check=True)    
            # Затем преобразуем PEM в CRT или CER
            subprocess.run(['openssl', 'x509', '-in', temp_pem, '-out', output_file], check=True)
            os.remove(temp_pem)
        elif input_format in ['PFX', 'P12'] and output_format in ['P7B', 'P7C']:
            # Сначала преобразуем PFX/P12 в PEM
            temp_pem = "temp.pem"
            subprocess.run(['openssl', 'pkcs12', '-in', input_file, '-out', temp_pem, '-nodes'], check=True)    
            # Затем преобразуем PEM в P7B или P7C
            subprocess.run(['openssl', 'crl2pkcs7', '-nocrl', '-certfile', temp_pem, '-out', output_file], check=True)
            os.remove(temp_pem)

        # Конвертации P7B/P7C в другие форматы
        elif input_format in ['P7B', 'P7C'] and output_format == 'PEM':
            subprocess.run(['openssl', 'pkcs7', '-print_certs', '-in', input_file, '-out', output_file], check=True)
        elif input_format in ['P7B', 'P7C'] and output_format == 'DER':
            temp_pem = "temp.pem"
            subprocess.run(['openssl', 'pkcs7', '-print_certs', '-in', input_file, '-out', temp_pem], check=True)
            subprocess.run(['openssl', 'x509', '-in', temp_pem, '-outform', 'DER', '-out', output_file], check=True)
            os.remove(temp_pem)
        elif input_format in ['P7B', 'P7C'] and output_format in ['CRT', 'CER']:
            temp_pem = "temp.pem"
            subprocess.run(['openssl', 'pkcs7', '-print_certs', '-in', input_file, '-out', temp_pem], check=True)
            subprocess.run(['openssl', 'x509', '-in', temp_pem, '-out', output_file], check=True)
            os.remove(temp_pem)
        elif input_format in ['P7B', 'P7C'] and output_format in ['PFX', 'P12']:
            temp_pem = "temp.pem"
            subprocess.run(['openssl', 'pkcs7', '-print_certs', '-in', input_file, '-out', temp_pem], check=True)
            key_file = select_private_key()
            if not key_file:
                return None
            subprocess.run(['openssl', 'pkcs12', '-export', '-in', temp_pem, '-inkey', key_file, '-out', output_file], check=True)
            os.remove(temp_pem)

        # Конвертация между PFX и P12
        elif (input_format == 'PFX' and output_format == 'P12') or (input_format == 'P12' and output_format == 'PFX'):
            copyfile(input_file, output_file)
            print(f"Файл сохранен как {output_file}")

        # Конвертация между P7B и P7C, а также CRT и CER
        elif (input_format in ['P7B', 'P7C'] and output_format in ['P7B', 'P7C']) or \
             (input_format in ['CRT', 'CER'] and output_format in ['CRT', 'CER']):
            copyfile(input_file, output_file)
            print(f"Файл сохранен как {output_file}")

        # Конвертации CRT/CER в другие форматы
        elif input_format in ['CRT', 'CER'] and output_format == 'PEM':
            # Конвертация из CRT/CER в PEM
            subprocess.run(['openssl', 'x509', '-in', input_file, '-out', output_file, '-outform', 'PEM'], check=True)
        elif input_format in ['CRT', 'CER'] and output_format == 'DER':
            # Конвертация из CRT/CER в DER
            subprocess.run(['openssl', 'x509', '-in', input_file, '-out', output_file, '-outform', 'DER'], check=True)
        elif input_format in ['CRT', 'CER'] and output_format in ['PFX', 'P12']:
            # Конвертация из CRT/CER в PFX или P12
            key_file = select_private_key()
            if not key_file:
                return None
            subprocess.run(['openssl', 'pkcs12', '-export', '-in', input_file, '-inkey', key_file, '-out', output_file], check=True)
        elif input_format in ['CRT', 'CER'] and output_format in ['P7B', 'P7C']:
            # Конвертация из CRT/CER в P7B или P7C
            subprocess.run(['openssl', 'crl2pkcs7', '-nocrl', '-certfile', input_file, '-out', output_file], check=True)

        # Конвертации KEY в другие форматы
        elif input_format == 'KEY' and output_format == 'PEM':
            subprocess.run(['openssl', 'rsa', '-in', input_file, '-out', output_file, '-outform', 'PEM'], check=True)
        elif input_format == 'KEY' and output_format == 'DER':
            subprocess.run(['openssl', 'rsa', '-in', input_file, '-outform', 'DER', '-out', output_file], check=True)
        else:
            print(f'Невозможно преобразовать из {input_format} в {output_format}.')
            return None

        print(f'Сертификат преобразован и сохранен в {output_file}')
        return output_file

    except subprocess.CalledProcessError as e:
        print(f'Ошибка преобразования сертификата: {e}')
    except FileNotFoundError:
        print(f"Не удалось найти файл {input_file} для переименования.")
    return None


# 3 =======================================================================================

def merge_pem_to_pfx(cert_file, key_file):
    """Собирает два файла в контейнер PFX/P12."""
    password = input('Введите пароль для нового PFX/P12 контейнера: ')
    output_name = input('Введите желаемое имя для файла: ') or 'output'
    
    # Меню выбора формата
    print("Выберите формат файла:")
    print("1. PFX")
    print("2. P12")
    format_choice = input("Выберите номер формата: ")

    if format_choice == '1':
        output_format = 'pfx'
    elif format_choice == '2':
        output_format = 'p12'
    else:
        print("Неверный выбор формата.")
        return

    output_pfx = f'{output_name}.{output_format}'

    try:
        # Убедимся, что файл ключа существует и читается
        if not os.path.isfile(key_file):
            print(f"Файл закрытого ключа {key_file} не найден.")
            return
        if not os.path.isfile(cert_file):
            print(f"Файл сертификата {cert_file} не найден.")
            return

        # Команда для создания контейнера PFX/P12
        subprocess.run(['openssl', 'pkcs12', '-export', '-out', output_pfx,
                        '-inkey', key_file, '-in', cert_file,
                        '-password', f'pass:{password}'], check=True)
        print(f'Контейнер {output_format.upper()} успешно создан: {output_pfx}')
    except subprocess.CalledProcessError as e:
        print(f'Ошибка при создании {output_format.upper()}: {e}')
    except Exception as e:
        print(f'Общая ошибка: {e}')

# 4 =======================================================================================
def change_cert_format(cert_path):
    """
    Конвертирует сертификат из одного формата в другой (PEM <-> DER).
    """
    try:
        # Определение выходного пути
        base_name = os.path.splitext(cert_path)[0]

        if is_pem_format(cert_path):
            print("Сертификат в формате PEM. Преобразуем в DER.")
            output_path = f"{base_name}.der"
            subprocess.run(['openssl', 'x509', '-outform', 'DER', '-in', cert_path, '-out', output_path], check=True)
            print(f"Сертификат сохранен в формате DER как {output_path}")

        elif is_der_format(cert_path):
            print("Сертификат в формате DER. Преобразуем в PEM.")
            output_path = f"{base_name}.pem"
            subprocess.run(['openssl', 'x509', '-inform', 'DER', '-in', cert_path, '-out', output_path, '-outform', 'PEM'], check=True)
            print(f"Сертификат сохранен в формате PEM как {output_path}")

        else:
            print("Файл не является допустимым сертификатом в формате PEM или DER.")
            return

    except subprocess.CalledProcessError as e:
        print(f"Ошибка при конвертации сертификата: {e}")
        print("Проверьте, является ли файл действительно сертификатом в формате DER или PEM и доступен ли он для чтения.")
    except Exception as e:
        print(f"Ошибка: {e}")


# 5 =======================================================================================

def split_certificate_chain(cert_path):
    """
    Разбивает цепочку сертификатов в файле на отдельные сертификаты.
    """
    input_format = determine_format(cert_path)
    if not input_format:
        print(f"Файл {cert_path} не является допустимым сертификатом.")
        return None

    temp_pem = "temp_cert_chain.pem"
    try:
        # Преобразуем файл в PEM, если он не в PEM
        if input_format == 'PEM':
            copyfile(cert_path, temp_pem)
        elif input_format == 'DER':
            subprocess.run(['openssl', 'x509', '-inform', 'DER', '-in', cert_path, '-out', temp_pem, '-outform', 'PEM'], check=True)
        elif input_format in ['P7B', 'P7C']:
            subprocess.run(['openssl', 'pkcs7', '-print_certs', '-in', cert_path, '-out', temp_pem], check=True)
        elif input_format in ['PFX', 'P12']:
            subprocess.run(['openssl', 'pkcs12', '-in', cert_path, '-out', temp_pem, '-nodes'], check=True)
        else:
            print(f'Невозможно обработать формат {input_format} для разбивки цепочки.')
            return None

        # Открываем и читаем все содержимое PEM файла
        with open(temp_pem, "rb") as pem_file:
            pem_data = pem_file.read()

        # Удаляем строки, содержащие приватный ключ
        pem_data = re.sub(b"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----\n?", b"", pem_data, flags=re.DOTALL)

        # Если сертификат находится в одной секции BEGIN/END CERTIFICATE, извлекаем каждый сертификат
        if pem_data.count(b"-----BEGIN CERTIFICATE-----") == 1:
            # Используем openssl для разбора сертификата и извлечения отдельных частей
            result = subprocess.run(['openssl', 'x509', '-in', temp_pem, '-text', '-noout'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # Проверка на наличие ошибок при выполнении команды
            if result.returncode != 0:
                print("Ошибка: Не удалось прочитать файл сертификата.")
                os.remove(temp_pem)
                return None

            cert_text = result.stdout
            certificates = cert_text.split(b"-----END CERTIFICATE-----")
            certificates = [cert + b"-----END CERTIFICATE-----\n" for cert in certificates if b"-----BEGIN CERTIFICATE-----" in cert]
        else:
            # Разделяем на отдельные сертификаты
            certificates = pem_data.split(b"-----END CERTIFICATE-----")
            certificates = [cert + b"-----END CERTIFICATE-----\n" for cert in certificates if b"-----BEGIN CERTIFICATE-----" in cert]

        # Если меньше одного сертификата, значит нет цепочки
        if len(certificates) < 1:
            print("Ошибка: не удалось найти сертификаты в файле.")
            os.remove(temp_pem)
            return None

        # Спросить пользователя формат для сохранения
        formats = ['PEM', 'DER', 'CRT', 'CER']
        print("Выберите формат для сохранения отдельных сертификатов:")
        for i, fmt in enumerate(formats, 1):
            print(f"{i}. {fmt}")

        choice = input("Выберите номер формата: ")
        try:
            output_format = formats[int(choice) - 1]
        except (IndexError, ValueError):
            print("Неверный выбор.")
            os.remove(temp_pem)
            return None

        output_files = []

        # Разбиваем и сохраняем каждый сертификат
        for i, cert in enumerate(certificates):
            output_path = f"{os.path.splitext(cert_path)[0]}_split_{i+1}.{output_format.lower()}"
            with open(output_path, "wb") as output_file:
                output_file.write(cert)
            output_files.append(output_path)

        # Очистка временных файлов
        os.remove(temp_pem)

        if output_files:
            print(f"Цепочка сертификатов разбита на {len(output_files)} частей: {', '.join(output_files)}")
        else:
            print("Ошибка: Не удалось разбить цепочку сертификатов.")

    except subprocess.CalledProcessError as e:
        print(f'Ошибка при разбивке цепочки сертификатов: {e}')
    except FileNotFoundError:
        print(f"Не удалось найти файл {cert_path} для обработки.")
    return None



# 6 =======================================================================================

def natural_sort_key(s):
    """Функция для сортировки строк в естественном порядке (с учетом чисел)."""
    return [int(text) if text.isdigit() else text.lower() for text in re.split('([0-9]+)', s)]

def merge_cert_chain():
    """Собирает цепочку сертификатов из отдельных файлов и конвертирует в выбранный формат."""
    files = [f for f in find_cert_files() if f.lower().endswith(('.pem', '.crt', '.cer', '.der'))]

    if not files:
        print("Сертификаты для сборки цепочки не найдены.")
        return

    # Сортировка файлов в естественном порядке
    files.sort(key=natural_sort_key)

    print("Найдены следующие файлы сертификатов:")
    for i, file in enumerate(files, 1):
        print(f"{i}. {file}")

    # Ввод номеров или диапазона
    print("Введите номера сертификатов для сборки цепочки (например, 1-3 или 1 3 5):")
    choice = input("Ваш выбор: ")

    selected_files = []
    try:
        if '-' in choice:
            start, end = map(int, choice.split('-'))
            selected_files = files[start-1:end]
        else:
            indices = map(int, choice.split())
            selected_files = [files[i - 1] for i in indices]
    except (IndexError, ValueError):
        print("Неверный выбор.")
        return

    # Выбор формата для сохранения
    formats = ['PEM', 'DER', 'CRT', 'CER', 'P7B', 'P7C']
    print("Выберите формат для сохранения цепочки сертификатов:")
    for i, fmt in enumerate(formats, 1):
        print(f"{i}. {fmt}")

    choice = input("Выберите номер формата: ")
    try:
        output_format = formats[int(choice) - 1]
    except (IndexError, ValueError):
        print("Неверный выбор.")
        return None

    # Создание файла в формате PEM
    pem_file = 'certificate_chain.pem'
    with open(pem_file, 'wb') as out_file:
        for cert in selected_files:
            with open(cert, 'rb') as in_file:
                out_file.write(in_file.read())

    # Преобразование в выбранный формат
    output_file = f'certificate_chain.{output_format.lower()}'

    try:
        if output_format == 'PEM':
            print(f'Цепочка сертификатов собрана и сохранена в {output_file}')
            return output_file
        elif output_format == 'DER':
            subprocess.run(['openssl', 'x509', '-in', pem_file, '-outform', 'der', '-out', output_file], check=True)
        elif output_format in ['CRT', 'CER']:
            subprocess.run(['openssl', 'x509', '-in', pem_file, '-out', output_file], check=True)
        elif output_format in ['P7B', 'P7C']:
            subprocess.run(['openssl', 'crl2pkcs7', '-nocrl', '-certfile', pem_file, '-out', output_file], check=True)
        else:
            print(f"Преобразование в формат {output_format} не поддерживается.")
            return None

        print(f'Цепочка сертификатов собрана и сохранена в {output_file}')
        return output_file

    except subprocess.CalledProcessError as e:
        print(f'Ошибка преобразования сертификата: {e}')
        return None


# 7 =======================================================================================

def extract_root_certificate(cert_file):
    """Извлекает корневой сертификат из файла сертификата."""
    input_format = determine_format(cert_file)
    if not input_format:
        print(f"Файл {cert_file} не является допустимым сертификатом.")
        return None

    temp_pem = "temp_cert_chain.pem"
    try:
        # Преобразуем файл в PEM, если он не в PEM
        if input_format == 'PEM':
            copyfile(cert_file, temp_pem)
        elif input_format == 'DER':
            subprocess.run(['openssl', 'x509', '-inform', 'DER', '-in', cert_file, '-out', temp_pem, '-outform', 'PEM'], check=True)
        elif input_format in ['P7B', 'P7C']:
            subprocess.run(['openssl', 'pkcs7', '-print_certs', '-in', cert_file, '-out', temp_pem], check=True)
        elif input_format in ['PFX', 'P12']:
            subprocess.run(['openssl', 'pkcs12', '-in', cert_file, '-out', temp_pem, '-nodes'], check=True)
        else:
            print(f'Невозможно обработать формат {input_format} для извлечения корневого сертификата.')
            return None

        # Открываем и читаем все содержимое PEM файла
        with open(temp_pem, "rb") as pem_file:
            pem_data = pem_file.read()

        # Если сертификат находится в одной секции BEGIN/END CERTIFICATE, извлекаем каждый сертификат
        if pem_data.count(b"-----BEGIN CERTIFICATE-----") == 1:
            # Используем openssl для разбора сертификата и извлечения корневого сертификата
            result = subprocess.run(['openssl', 'x509', '-in', temp_pem, '-text', '-noout'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                print("Ошибка: Не удалось прочитать файл сертификата.")
                os.remove(temp_pem)
                return None

            cert_text = result.stdout
            certificates = cert_text.split(b"-----END CERTIFICATE-----")
            certificates = [cert + b"-----END CERTIFICATE-----\n" for cert in certificates if b"-----BEGIN CERTIFICATE-----" in cert]
        else:
            # Разделяем на отдельные сертификаты
            certificates = pem_data.split(b"-----END CERTIFICATE-----")
            certificates = [cert + b"-----END CERTIFICATE-----\n" for cert in certificates if b"-----BEGIN CERTIFICATE-----" in cert]

        # Если меньше одного сертификата, значит нет цепочки
        if len(certificates) < 1:
            print("Ошибка: не удалось найти сертификаты в файле.")
            os.remove(temp_pem)
            return None

        # Извлекаем последний сертификат в цепочке (корневой)
        root_certificate = certificates[-1]

        # Выбор выходного формата
        formats = ['PEM', 'DER', 'CRT', 'CER']
        print("Выберите формат для сохранения корневого сертификата:")
        for i, fmt in enumerate(formats, 1):
            print(f"{i}. {fmt}")

        choice = input("Выберите номер формата: ")
        try:
            output_format = formats[int(choice) - 1]
        except (IndexError, ValueError):
            print("Неверный выбор.")
            os.remove(temp_pem)
            return None

        output_file = f"root_certificate.{output_format.lower()}"

        # Сохранение корневого сертификата в выбранном формате
        with open("temp_root.pem", "wb") as root_file:
            root_file.write(root_certificate)

        if output_format == 'PEM':
            copyfile("temp_root.pem", output_file)
        elif output_format == 'DER':
            subprocess.run(['openssl', 'x509', '-inform', 'PEM', '-in', "temp_root.pem", '-outform', 'DER', '-out', output_file], check=True)
        elif output_format in ['CRT', 'CER']:
            subprocess.run(['openssl', 'x509', '-in', "temp_root.pem", '-out', output_file], check=True)

        # Очистка временных файлов
        os.remove(temp_pem)
        os.remove("temp_root.pem")

        print(f'Корневой сертификат успешно извлечен и сохранен в {output_file}')
        return output_file

    except subprocess.CalledProcessError as e:
        print(f'Ошибка при извлечении корневого сертификата: {e}')
    except FileNotFoundError:
        print(f"Не удалось найти файл {cert_file} для обработки.")
    return None


# 8 =======================================================================================

def generate_ca_and_certificate():
    """Генерация собственного корневого CA и сертификата RSA."""
    key_lengths = ['1024', '2048', '4096']
    print("Выберите длину ключа:")
    for i, length in enumerate(key_lengths, 1):
        print(f"{i}. {length}")
    
    try:
        key_length = key_lengths[int(input("Введите номер длины ключа (по умолчанию 2048): ") or 2) - 1]
    except (IndexError, ValueError):
        print("Неверный выбор длины ключа.")
        return

    days = input("Введите срок действия в днях, например, 365 (по умолчанию 365): ") or "365"

    # Выбор алгоритма хеширования
    hash_algorithms = ['sha256', 'sha384', 'sha512']
    print("Выберите алгоритм хеширования:")
    for i, algo in enumerate(hash_algorithms, 1):
        print(f"{i}. {algo}")

    try:
        default_md = hash_algorithms[int(input("Введите номер алгоритма хеширования (по умолчанию sha256): ") or 1) - 1]
    except (IndexError, ValueError):
        print("Неверный выбор алгоритма хеширования.")
        return

    c = input("C (страна, по умолчанию RU): ") or "RU"
    st = input("ST (регион, по умолчанию Moscow): ") or "Moscow"
    l = input("L (город, по умолчанию Moscow): ") or "Moscow"
    o = input("O (организация, по умолчанию Company): ") or "Company"
    ou = input("OU (подразделение, по умолчанию IT): ") or "IT"
    cn = input("CN (доменное имя, по умолчанию domain.net): ") or "domain.net"

    alt_names = input("Введите альтернативные DNS-имена через пробел (по умолчанию www.domain.net *.domain.net domain.net): ") or "www.domain.net *.domain.net domain.net"

    # Создаем server.conf
    with open("server.conf", "w") as conf:
        conf.write(f"""[ req ]
default_bits = {key_length}
prompt = no
default_md = {default_md}
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = {c}
ST = {st}
L = {l}
O = {o}
OU = {ou}
CN = {cn}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
""")
        for i, dns in enumerate(alt_names.split(), 1):
            conf.write(f"DNS.{i} = {dns}\n")

        conf.write(f"""\n[ v3_ext ]
authorityKeyIdentifier=keyid,issuer:always
basicConstraints=CA:TRUE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=@alt_names
""")

    try:
        # Генерация ключа и сертификатов
        subprocess.run(['openssl', 'genrsa', '-out', 'cert.key', key_length], check=True)
        subprocess.run(['openssl', 'req', '-x509', '-new', '-nodes', '-key', 'cert.key', '-days', days, '-out', 'cert.crt', '-config', 'server.conf', '-extensions', 'req_ext'], check=True)
        
        # Создание PFX файла без пароля
        subprocess.run(['openssl', 'pkcs12', '-export', '-out', 'cert.pfx', '-inkey', 'cert.key', '-in', 'cert.crt', '-password', 'pass:'], check=True)
        
        print("Сертификаты и ключи успешно сгенерированы:")
        print("1. 'cert.key' - приватный ключ")
        print("2. 'cert.crt' - открытый сертификат")
        print("3. 'cert.pfx' - PFX контейнер без пароля")

    except subprocess.CalledProcessError as e:
        print(f"Ошибка генерации сертификатов: {e}")


# 9 =======================================================================================

def fetch_certificate_from_server():
    """Получение сертификата с сервера."""
    server = input("Введите IP или FQDN сервера: ")
    output_file = f'{server}_certificates.pem'

    try:
        # Открываем процесс для команды openssl
        process = subprocess.Popen(
            ['openssl', 's_client', '-showcerts', '-servername', server, '-connect', f'{server}:443'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True
        )

        # Отправляем EOF сразу после запуска команды
        stdout, stderr = process.communicate(input='\n', timeout=10)  # Ждем завершения до 10 секунд

        # Проверяем, успешно ли завершилось выполнение команды
        if process.returncode != 0:
            print(f"Ошибка получения сертификатов: {stderr}")
            return

        # Сохраняем сертификаты в файл
        with open(output_file, 'w') as cert_file:
            cert_file.write(stdout)
        
        print(f"Сертификаты успешно получены и сохранены в файл {output_file}.")

    except subprocess.TimeoutExpired:
        print("Команда OpenSSL заняла слишком много времени и была прервана.")
    except subprocess.CalledProcessError as e:
        print(f"Ошибка получения сертификатов: {e}")
    except Exception as e:
        print(f"Произошла ошибка: {e}")
        
# MENU ====================================================================================

def main():
    while True:
        print("===========================================")
        print("Конвертор сертификатов и ключей")
        print("-------------------------------------------")
        print("1. Разбить контейнер PFX/P12 на 2 части PEM")
        print("2. Преобразовать из одного формата в другой")
        print("3. Собрать 2 части в контейнер PFX/P12")
        print("4. CER/CRT - смена формата PEM/DER")
        print("5. Разбить цепочку сертификатов")
        print("6. Сбор сертификатов в цепочку")
        print("7. Извлечение корневого сертификата")
        print("8. Генерация самоподписанного сертификата RSA")
        print("9. Получение сертификата с сервера")
        print("-------------------------------------------")
        print("0. Выход")
        print("===========================================")
        choice = input("Выберите номер меню: ")

        if choice == '0':
            print("Выход из программы.")
            break

        files = find_cert_files()

        if choice == '1':
            pfx_files = [f for f in files if f.lower().endswith(('.pfx', '.p12'))]
            pfx_file = display_files(pfx_files)
            if pfx_file:
                split_pfx(pfx_file)

        elif choice == '2':
            cert_file = display_files(files)
            if cert_file:
                convert_certificate(cert_file)

        elif choice == '3':
            cert_files = [f for f in files if f.lower().endswith(('.pem', '.crt', '.cer', '.der'))]
            cert_file = display_files(cert_files)
            key_files = [f for f in files if f.lower().endswith(('.key', '.pem', '.rsa', '.pvk', '.ppk', '.ssh', '.openssh', '.p8'))]
            key_file = display_files(key_files)
            if cert_file and key_file:
                merge_pem_to_pfx(cert_file, key_file)

        elif choice == '4':
            cert_files = [f for f in files if f.lower().endswith(('.pem', '.der', '.crt', '.cer'))]
            cert_file = display_files(cert_files)
            if cert_file:
                change_cert_format(cert_file)

        elif choice == '5':
            chain_files = [f for f in files if f.lower().endswith(('.pem', '.crt', '.cer', '.p7b', '.p7c'))]
            chain_file = display_files(chain_files)
            if chain_file:
                split_certificate_chain(chain_file)

        elif choice == '6':
            merge_cert_chain()

        elif choice == '7':
            cert_file = display_files(files)
            if cert_file:
                extract_root_certificate(cert_file)

        elif choice == '8':
            generate_ca_and_certificate()

        elif choice == '9':
            fetch_certificate_from_server()

        else:
            print("Неверный выбор. Пожалуйста, выберите правильный номер.")

        input("Нажмите Enter для возврата в главное меню...")

if __name__ == "__main__":
    main()
