import base64
import logging
import traceback

from Crypto.Cipher import AES
from cryptography.fernet import Fernet
from django.conf import settings


# secret = os.urandom(settings.ENCRYPTION_BLOCK_SIZE)


def encryptToken(rawParam):
    try:
        value = str(rawParam)
        cipher_suite = Fernet(settings.ENCRYPTION_KEY)
        cipher_suite = cipher_suite.encrypt(value.encode('ascii'))
        encrypted_value = base64.urlsafe_b64encode(cipher_suite).decode("ascii")
    except Exception as e:
        logging.getLogger(str(e.args)).error(traceback.format_exc())
        encrypted_value = None
    return encrypted_value


def decryptToken(encrypted_value):
    try:
        raw_value = base64.urlsafe_b64decode(encrypted_value)
        cipher_suite = Fernet(settings.ENCRYPTION_KEY)
        decoded_value = cipher_suite.decrypt(raw_value).decode("ascii")
    except Exception as e:
        logging.getLogger(str(e.args)).error(traceback.format_exc())
        decoded_value = None
    return decoded_value


def encryptRawValues(rawValue):
    pad = lambda s: s + (settings.ENCRYPTION_BLOCK_SIZE - len(s) % settings.ENCRYPTION_BLOCK_SIZE) * settings.PADDING
    encode = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    secret = base64.b64decode(settings.USER_PASS_KEY)
    cipher = AES.new(secret)
    encodedString = str(encode(cipher, rawValue))[1:].replace('\'', '')
    print("Encoded String is:", encodedString)
    return encodedString


def decryptRawValues(encryptedValue):
    secret = base64.b64decode(settings.USER_PASS_KEY)
    decode = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(settings.PADDING)
    cipher = AES.new(secret)
    decodeString = decode(cipher, encryptedValue)
    print("This is the encoded String", decodeString)
    return decodeString
