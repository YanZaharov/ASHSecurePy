from Crypto.Cipher import AES  # Импортируем AES для шифрования данных.
from Crypto.Protocol.KDF import scrypt  # Импортируем scrypt для генерации ключей на основе пароля.
from Crypto.Random import get_random_bytes  # Импортируем функцию для генерации случайных байтов.
from Crypto.Hash import HMAC, SHA256  # Импортируем HMAC для проверки целостности данных и SHA256 для хеширования.

def generate_key(passphrase, salt, key_length=32):
    """
    Генерация ключа на основе пароля (passphrase) с использованием соли (salt).
    Используем алгоритм scrypt, чтобы сделать ключ более защищённым от атак перебора.

    :param passphrase: Пароль, который вводит пользователь.
    :param salt: Соль — случайная строка, которая добавляется к паролю для уникальности.
    :param key_length: Длина ключа. По умолчанию 32 байта (256 бит).
    :return: Возвращает криптографически стойкий ключ.
    """
    return scrypt(passphrase.encode(), salt, key_length, N=2 ** 14, r=8, p=1)

def pad_message(message, block_size):
    """
    Добавляет символы в конец сообщения, чтобы его длина стала кратной размеру блока.
    Это необходимо, так как AES работает только с блоками фиксированной длины.

    :param message: Сообщение, которое нужно дополнить.
    :param block_size: Размер блока (для AES это 16 байт).
    :return: Дополненное сообщение.
    """
    padding_len = block_size - len(message) % block_size  # Считаем, сколько байтов нужно добавить.
    padding = bytes([padding_len] * padding_len)  # Создаем байт-строку с нужным количеством добавочных байтов.
    return message + padding  # Добавляем нужное количество символов (в виде байтов).

def unpad_message(padded_message):
    """
    Убирает дополненные символы из сообщения после расшифровки.
    Это необходимо, чтобы вернуть сообщение к исходной длине.

    :param padded_message: Сообщение с дополнением.
    :return: Оригинальное сообщение без дополнения.
    """
    padding_len = padded_message[-1]  # Определяем, сколько символов было добавлено.
    return padded_message[:-padding_len]  # Убираем добавленные символы.

def encrypt_message(message, passphrase):
    """
    Шифрует сообщение с использованием AES.
    Шифрование состоит из нескольких шагов:
    1. Генерация случайной соли и вектора инициализации (IV).
    2. Преобразование пароля в ключ с помощью scrypt.
    3. Шифрование сообщения с использованием AES в режиме CBC (Cipher Block Chaining).
    4. Создание HMAC для проверки целостности данных.

    :param message: Сообщение для шифрования.
    :param passphrase: Пароль, который будет использован для генерации ключа.
    :return: Возвращает зашифрованное сообщение вместе с солью, IV и HMAC.
    """
    salt = get_random_bytes(16)  # Генерация соли для scrypt.
    iv = get_random_bytes(16)  # Генерация вектора инициализации (IV).
    key = generate_key(passphrase, salt)  # Генерация ключа на основе пароля и соли.
    padded_message = pad_message(message.encode(), AES.block_size)  # Подготовка сообщения (дополнение до длины, кратной размеру блока).

    cipher = AES.new(key, AES.MODE_CBC, iv)  # Инициализация AES в режиме CBC.
    ciphertext = cipher.encrypt(padded_message)  # Шифруем дополненное сообщение.

    hmac = HMAC.new(key, digestmod=SHA256)  # Создание HMAC для проверки целостности данных.
    hmac.update(ciphertext)  # Обновляем HMAC с зашифрованным текстом.

    return salt + iv + ciphertext + hmac.digest()  # Возвращаем зашифрованное сообщение, соль, IV и HMAC.

def decrypt_message(encrypted_message, passphrase):
    """
    Расшифровывает сообщение, проверяя целостность данных с помощью HMAC.
    1. Извлечение соли, IV и HMAC из зашифрованного сообщения.
    2. Генерация ключа на основе пароля и соли.
    3. Проверка целостности сообщения с использованием HMAC.
    4. Расшифровка сообщения с использованием AES в режиме CBC.

    :param encrypted_message: Зашифрованное сообщение (включает соль, IV и HMAC).
    :param passphrase: Пароль для генерации ключа.
    :return: Расшифрованное сообщение.
    """
    salt = encrypted_message[:16]  # Первые 16 байт — это соль.
    iv = encrypted_message[16:32]  # Следующие 16 байт — это IV.
    hmac_received = encrypted_message[-32:]  # Последние 32 байта — это HMAC.
    ciphertext = encrypted_message[32:-32]  # Оставшаяся часть — это зашифрованное сообщение.

    key = generate_key(passphrase, salt)  # Генерация ключа на основе пароля и соли.

    hmac = HMAC.new(key, digestmod=SHA256)  # Инициализация HMAC с использованием того же ключа.
    hmac.update(ciphertext)  # Обновляем HMAC с зашифрованным текстом.

    try:
        hmac.verify(hmac_received)  # Проверяем, совпадает ли рассчитанный HMAC с тем, что мы извлекли из сообщения.
    except ValueError:
        raise ValueError("Сообщение было изменено или повреждено!")  # Сообщение не целостное.

    cipher = AES.new(key, AES.MODE_CBC, iv)  # Инициализация AES для расшифровки.
    padded_message = cipher.decrypt(ciphertext)  # Расшифровываем и преобразуем в байты.
    return unpad_message(padded_message)  # Убираем добавленные символы и возвращаем оригинальное сообщение.

# Пример использования
if __name__ == "__main__":
    message = "Привет, мир!"  # Исходное сообщение, которое мы хотим зашифровать.
    passphrase = "МойПароль"  # Пароль, с которым мы будем шифровать сообщение.

    # Шифруем сообщение.
    encrypted = encrypt_message(message, passphrase)
    print(f"Зашифрованное сообщение: {encrypted}")

    # Расшифровываем сообщение.
    decrypted = decrypt_message(encrypted, passphrase)
    print(f"Расшифрованное сообщение: {decrypted.decode('utf-8')}")  # Расшифровываем и выводим как строку.
