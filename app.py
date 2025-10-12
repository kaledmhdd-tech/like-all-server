from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
import time
from collections import defaultdict
from datetime import datetime
import random

app = Flask(__name__)

# إعداد حدّ الاستخدام لكل مفتاح
KEY_LIMIT = 1000
token_tracker = defaultdict(lambda: [0, time.time()])  # token: [count, last_reset_time]


# ✅ وقت منتصف اليوم
def get_today_midnight_timestamp():
    now = datetime.now()
    midnight = datetime(now.year, now.month, now.day)
    return midnight.timestamp()


# ✅ جلب التوكنات من الـ API
def load_tokens(server_name):
    if server_name == "IND":
        url = "https://auto-token-ind.onrender.com/api/get_jwt"
    else:
        url = "https://aauto-token.onrender.com/api/get_jwt"
    try:
        res = requests.get(url, timeout=30)
        js = res.json()
        tokens = js.get("tokens", {})
        return [{"token": t} for t in tokens.values()]
    except Exception as e:
        print(f"[ERROR] Failed to fetch tokens: {e}")
        return []


# ✅ تشفير البيانات بـ AES CBC
def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')


# ✅ إنشاء بروتوباف لللايك
def create_protobuf_message(user_id, region):
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()


# ✅ إرسال طلب async
async def send_request(encrypted_uid, token, url):
    edata = bytes.fromhex(encrypted_uid)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; Android 9; ASUS_Z01QD)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': "2018.4.11f1",
        'ReleaseVersion': "OB50"
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                return response.status
    except Exception as e:
        print(f"[ERROR] send_request: {e}")
        return None


# ✅ إرسال عدة طلبات بشكل متوازي
async def send_multiple_requests(uid, server_name, url):
    region = server_name
    protobuf_message = create_protobuf_message(uid, region)
    encrypted_uid = encrypt_message(protobuf_message)
    tokens = load_tokens(server_name)
    if not tokens:
        print("[ERROR] No tokens loaded!")
        return []
    tasks = [send_request(encrypted_uid, random.choice(tokens)["token"], url) for _ in range(200)]
    return await asyncio.gather(*tasks, return_exceptions=True)


# ✅ إنشاء protobuf لملف uid_generator
def create_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.krishna_ = int(uid)
    message.teamXdarks = 1
    return message.SerializeToString()


def enc(uid):
    protobuf_data = create_protobuf(uid)
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid


# ✅ جلب بيانات اللاعب (info)
def make_request(encrypt, server_name, token):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

    edata = bytes.fromhex(encrypt)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; Android 9; ASUS_Z01QD)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': "2018.4.11f1",
        'ReleaseVersion': "OB50"
    }

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=30)
        binary = response.content
        return decode_protobuf(binary)
    except Exception as e:
        print(f"[ERROR] make_request: {e}")
        return None


# ✅ فك التشفير من Protobuf
def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        print(f"[ERROR] decode_protobuf: {e}")
        return None


# ✅ وظيفة آمنة لجلب معلومات اللايك
def safe_get_likes(encrypt, server_name, token):
    data = make_request(encrypt, server_name, token)
    if data is None:
        return None
    try:
        jsone = MessageToJson(data)
        parsed = json.loads(jsone)
        acc = parsed.get('AccountInfo', {})
        return {
            "likes": int(acc.get('Likes', 0)),
            "uid": int(acc.get('UID', 0)),
            "name": acc.get('PlayerNickname', 'Unknown')
        }
    except Exception as e:
        print("[ERROR] safe_get_likes:", e)
        return None


# ✅ المسار الرئيسي
@app.route('/like', methods=['POST'])
async def handle_like():
    start_time = time.time()

    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    key = request.args.get("key")

    if key != "BNGXX":
        return jsonify({"error": "Invalid or missing API key 🔑"}), 403

    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    tokens = load_tokens(server_name)
    if not tokens:
        return jsonify({"error": "Failed to load tokens"}), 500

    token = tokens[0]['token']
    encrypt = enc(uid)

    today_midnight = get_today_midnight_timestamp()
    count, last_reset = token_tracker[token]

    if last_reset < today_midnight:
        token_tracker[token] = [0, time.time()]
        count = 0

    if count >= KEY_LIMIT:
        return jsonify({
            "error": "Daily request limit reached for this key.",
            "status": 429,
            "remains": f"(0/{KEY_LIMIT})"
        }), 429

    before_info = safe_get_likes(encrypt, server_name, token)
    if not before_info:
        return jsonify({"error": "Failed to fetch player info before sending likes"}), 500

    # تحديد رابط السيرفر
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/LikeProfile"
    else:
        url = "https://clientbp.ggblueshark.com/LikeProfile"

    await send_multiple_requests(uid, server_name, url)

    after_info = safe_get_likes(encrypt, server_name, token)
    if not after_info:
        return jsonify({"error": "Failed to fetch player info after sending likes"}), 500

    like_given = after_info["likes"] - before_info["likes"]
    if like_given > 0:
        token_tracker[token][0] += 1
        count += 1

    remains = KEY_LIMIT - count

    result = {
        "PlayerNickname": after_info["name"],
        "UID": after_info["uid"],
        "LikesBefore": before_info["likes"],
        "LikesAfter": after_info["likes"],
        "LikesGivenByAPI": like_given,
        "status": 1 if like_given > 0 else 2,
        "remains": f"({remains}/{KEY_LIMIT})",
        "elapsed_time": f"{round(time.time() - start_time, 3)} sec",
        "executed_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    }

    return jsonify(result)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
