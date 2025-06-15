import hashlib
import random
import time
import requests
import json
import configparser
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def common_get_sign(timestamp: int, seq: str) -> str:
    """
    generate cosmos_sgn
    :param timestamp: int
    :param seq: str
    :return: str
    """
    md5_timestamp = hashlib.md5(str(timestamp).encode('utf-8')).hexdigest()
    md5_seq = hashlib.md5(str(seq).encode('utf-8')).hexdigest()
    combined_string = md5_timestamp + md5_seq
    final_sign = hashlib.md5(combined_string.encode('utf-8')).hexdigest()
    return final_sign


def encrypt_password(password: str, account: str, timestamp: int) -> str:
    """
    encrypt MD5 + AES(ECB) return Base64 result
    :param password: str
    :param account: str
    :param timestamp: int
    :return: str
    """
    # 1. password md5 hash (32-bit lowercase)
    password_md5 = hashlib.md5(password.encode('utf-8')).hexdigest()

    # 2. AES key: md5(account + timestamp)
    key_str = f"{account}{timestamp}"
    key = hashlib.md5(key_str.encode('utf-8')).hexdigest().encode('utf-8')

    # 3. AES: ECB + PKCS7
    cipher = AES.new(key, AES.MODE_ECB)

    # encrypt md5 password <- bytes
    encrypted_bytes = cipher.encrypt(pad(password_md5.encode('utf-8'), AES.block_size))

    # 4. base64
    encrypted_password_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')

    return encrypted_password_b64


def get_captcha_and_id():
    """
    download captcha and store in device
    """
    print("--- getting captcha ---")
    url = 'https://sso.suat-sz.edu.cn/cosmos/corona/auth/v1/get/captcha'
    headers = {
        'Content-Type': 'application/json'
    }
    timestamp = int(time.time() * 1000)
    seq = str(random.random())[2:]
    data = {"seq": seq, "timestamp": timestamp}
    headers['cosmos_sgn'] = common_get_sign(timestamp, seq)

    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)
        response.raise_for_status()
        response_data = response.json()

        img_base64_full = response_data.get("data", {}).get("img")
        captcha_id = response_data.get("data", {}).get("id")

        if not img_base64_full or not captcha_id:
            print("Error: Unable to get captcha image or ID from the response.")
            exit(1)

        # decode and save captcha
        _header, encoded = img_base64_full.split(",", 1)
        with open("captcha.png", "wb") as f:
            f.write(base64.b64decode(encoded))

        print("captcha saved as captcha.png")
        return captcha_id
    except requests.exceptions.RequestException as e:
        print(f"failed to get captcha {e}")
        return None


def perform_login(account, password, captcha, captcha_id):
    print("\n--- preparing login req ---")
    url = 'https://sso.suat-sz.edu.cn/cosmos/corona/oauth2/v1/web_login'

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0',
        'Content-Type': 'application/json',
        'Origin': 'https://sso.suat-sz.edu.cn',
        'Referer': 'https://sso.suat-sz.edu.cn/gravity-login/',
    }

    # outer timestamp + seq
    outer_timestamp = int(time.time() * 1000)
    outer_seq = str(random.random())[2:]

    encrypted_pwd = encrypt_password(password, account, outer_timestamp)

    # 内层
    inner_data = {
        "loginType": 0,
        "appId": "1793178146138746881",
        "account": account,
        "password": encrypted_pwd,
        "passwordType": 1,
        "captcha": captcha,
        "captchaId": captcha_id,
    }


    final_payload = {
        "data": inner_data,
        "seq": outer_seq,
        "timestamp": outer_timestamp
    }

    # cosmos_sgn !!!important
    headers['cosmos_sgn'] = common_get_sign(outer_timestamp, outer_seq)

    print(f"account: {account}")
    # print(f"encrypted password (base64): {encrypted_pwd[:30]}...")
    # print(f"cosmos_sgn: {headers['cosmos_sgn']}")

    try:
        response = requests.post(url, headers=headers, json=final_payload, timeout=10)
        print("\n--- response ---")
        print(f"code from server: {response.status_code}")
        # print(json.dumps(response.json(), indent=2, ensure_ascii=False))
    except requests.exceptions.RequestException as e:
        print(f"login failed: {e}")



if __name__ == "__main__":

    captcha_id = get_captcha_and_id()
    config = configparser.ConfigParser()
    user_account, user_password = '', ''
    try:
        config.read('config.ini')
        user_account = config.get('credentials', 'username')
        user_password = config.get('credentials', 'password')
    except (configparser.NoSectionError, configparser.NoOptionError, FileNotFoundError):
        print("Unable to read configuration file 'config.ini' or the file is missing the 'credentials' section and 'username'/'password' options.")
        print("Please ensure that the 'config.ini' file is in the same directory as the script and that its content is correctly formatted.")

    if captcha_id:
        # print(f"captcha ID: {captcha_id}")
        print("\nPlease enter your login information below:")

        if not user_account:
            user_account = input("account: ")
        if not user_password:
            user_password = input("password: ")

        captcha_code = input("Please see the captcha.png file and enter the captcha from the image: ")

        perform_login(user_account, user_password, captcha_code, captcha_id)
