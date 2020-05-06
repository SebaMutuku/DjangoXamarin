import base64
import logging
import traceback

from cryptography.fernet import Fernet
from django.conf import settings


def encrypt(rawParam):
    try:
        value = str(rawParam)
        cipher_suite = Fernet(settings.ENCRYPTION_KEY)
        cipher_suite = cipher_suite.encrypt(value.encode('ascii'))
        encrypted_value = base64.urlsafe_b64encode(cipher_suite).decode("ascii")
    except Exception as e:
        logging.getLogger(str(e.args)).error(traceback.format_exc())
        encrypted_value = None
    return encrypted_value


def decrypt(encrypted_value):
    try:
        raw_value = base64.urlsafe_b64decode(encrypted_value)
        cipher_suite = Fernet(settings.ENCRYPT_KEY)
        decoded_value = cipher_suite.decrypt(raw_value).decode("ascii")
    except Exception as e:
        logging.getLogger(str(e.args)).error(traceback.format_exc())
        decoded_value = None
    return decoded_value
