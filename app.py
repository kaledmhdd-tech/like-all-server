from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import CSLikeProfile_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
from datetime import datetime, timedelta
import secrets
import string
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import os

app = Flask(__name__)

# JSON file for API key storage
API_KEYS_FILE = "api_keys.json"

# Initialize scheduler for daily reset
scheduler = BackgroundScheduler(daemon=True)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

def load_api_keys():
    """Load API keys from JSON file"""
    if not os.path.exists(API_KEYS_FILE):
        return {}
    try:
        with open(API_KEYS_FILE, "r") as f:
            data = json.load(f)
            # Convert string dates back to datetime objects
            for key in data.values():
                for field in ['created_at', 'expires_at', 'last_reset', 'last_used']:
                    if field in key and isinstance(key[field], str):
                        key[field] = datetime.fromisoformat(key[field])
            return data
    except Exception as e:
        app.logger.error(f"Error loading API keys: {e}")
        return {}

def save_api_keys(keys):
    """Save API keys to JSON file"""
    try:
        with open(API_KEYS_FILE, "w") as f:
            # Convert datetime objects to strings for JSON serialization
            keys_to_save = {}
            for key, value in keys.items():
                keys_to_save[key] = value.copy()
                for field in ['created_at', 'expires_at', 'last_reset', 'last_used']:
                    if field in keys_to_save[key] and isinstance(keys_to_save[key][field], datetime):
                        keys_to_save[key][field] = keys_to_save[key][field].isoformat()
            json.dump(keys_to_save, f, indent=2)
    except Exception as e:
        app.logger.error(f"Error saving API keys: {e}")

def reset_remaining_requests():
    """Reset remaining requests for all active keys to their total_requests"""
    try:
        now = datetime.now()
        keys = load_api_keys()
        updated = False
        
        for key_data in keys.values():
            if key_data.get('is_active', True) and key_data.get('expires_at', now) > now:
                key_data['remaining_requests'] = key_data['total_requests']
                key_data['last_reset'] = now
                updated = True
        
        if updated:
            save_api_keys(keys)
        app.logger.info(f"Successfully reset requests at {now}")
    except Exception as e:
        app.logger.error(f"Error in reset_remaining_requests: {e}")

# Schedule daily reset at midnight
scheduler.add_job(
    reset_remaining_requests,
    'cron',
    hour=0,
    minute=0,
    second=0,
    timezone='UTC'
)

# ✅ جلب التوكن من الرابطين حسب السيرفر
def load_tokens(server_name):
    if server_name == "IND":
        url = "https://auto-token-n5t7.onrender.com/api/get_jwt"
    elif server_name == "ME":
        url = "https://auto-token-me.onrender.com/api/get_jwt"
    else:
        print(f"Unsupported server: {server_name}")
        return []
    try:
        res = requests.get(url, timeout=50)
        js = res.json()
        tokens = js.get("tokens", {})
        return [{"token": t} for t in tokens.values()]
    except Exception as e:
        print(f"Error fetching tokens: {e}")
        return []

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = CSLikeProfile_pb2.CSLikeProfileReq()
        message.target_id = int(user_id)
        message.target_region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None
        tasks = []
        tokens = load_tokens(server_name)
        if tokens is None or not tokens:
            app.logger.error("Failed to load tokens.")
            return None
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.ujjaiwal_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name == "ME":
            url = "https://clientbp.freefiremobile.com/GetPlayerPersonalShow"
        else:
            print(f"Unsupported server: {server_name}")
            return None

        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }

        response = requests.post(url, data=edata, headers=headers, verify=False)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
        return decode

    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

# باقي الكود بدون تغيير ...

if __name__ == '__main__':
    app.run(debug=True)
