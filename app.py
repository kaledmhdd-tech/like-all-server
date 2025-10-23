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

app = Flask(__name__)

KEY_LIMIT = 5000
token_tracker = defaultdict(lambda: [0, time.time()])


def get_today_midnight_timestamp():
    now = datetime.now()
    midnight = datetime(now.year, now.month, now.day)
    return midnight.timestamp()


def load_tokens(server_name):
    if server_name == "IND":
        url = "https://auto-token-n5t7.onrender.com/api/get_jwt"
    else:
        url = "https://auto-token-n5t7.onrender.com/api/get_jwt"
    try:
        res = requests.get(url, timeout=10)
        js = res.json()
        tokens = js.get("tokens", {})
        return [{"token": t} for t in tokens.values()]
    except Exception as e:
        print(f"Error fetching tokens: {e}")
        return []


def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')


def create_protobuf_message(user_id, region):
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()


async def send_request(encrypted_uid, token, url):
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
            return response.status


async def send_multiple_requests(uid, server_name, url):
    region = server_name
    protobuf_message = create_protobuf_message(uid, region)
    encrypted_uid = encrypt_message(protobuf_message)
    tasks = []
    tokens = load_tokens(server_name)
    for i in range(100):
        token = tokens[i % len(tokens)]["token"]
        tasks.append(send_request(encrypted_uid, token, url))
    results = await asyncio.gather(*tasks)
    return results


def create_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.krishna_ = int(uid)
    message.teamXdarks = 1
    return message.SerializeToString()


def enc(uid):
    protobuf_data = create_protobuf(uid)
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid


# ============================
#      FIXED SECTION
# ============================
def make_request(encrypt, server_name, token):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

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

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        content = response.content
    except Exception as e:
        print(f"[make_request] HTTP Error: {e}")
        return None

    # --- محاولة فك البروتوباف أولاً ---
    info = decode_protobuf(content)
    if info is not None:
        print(f"[make_request] ✅ Protobuf response decoded successfully from {server_name}")
        return info

    # --- تجربة JSON إذا فشل البروتوباف ---
    try:
        js = response.json()
        if "AccountInfo" in js:
            print(f"[make_request] ⚠️ Server {server_name} returned JSON instead of protobuf.")
            fake = like_count_pb2.Info()
            acc = js["AccountInfo"]
            fake.AccountInfo.UID = int(acc.get("UID", 0))
            fake.AccountInfo.PlayerNickname = str(acc.get("PlayerNickname", "Unknown"))
            fake.AccountInfo.Likes = int(acc.get("Likes", 0))
            return fake
    except Exception as e:
        text = content.decode("utf-8", errors="ignore")
        print(f"[make_request] ❌ Unknown response format from {server_name}. Raw: {text[:200]}...")

    return None


def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception:
        return None


# ============================
#         /like route
# ============================
@app.route('/like', methods=['GET'])
def handle_requests():
    start_time = time.time()
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    key = request.args.get("key")

    if key != "BNGXX":
        return jsonify({"error": "Invalid or missing API key 🔑"}), 403

    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    def process_request():
        data = load_tokens(server_name)
        if not data:
            return {"error": "Failed to load tokens."}
        token = data[0]['token']

        encrypt = enc(uid)
        today_midnight = get_today_midnight_timestamp()
        count, last_reset = token_tracker[token]

        if last_reset < today_midnight:
            token_tracker[token] = [0, time.time()]
            count = 0

        if count >= KEY_LIMIT:
            return {
                "error": "Daily request limit reached for this key.",
                "status": 429,
                "remains": f"(0/{KEY_LIMIT})"
            }

        before = make_request(encrypt, server_name, token)
        if before is None:
            return {"error": "Failed to fetch player info (before likes)."}

        jsone = MessageToJson(before)
        data = json.loads(jsone)
        before_like = int(data['AccountInfo'].get('Likes', 0))

        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"

        asyncio.run(send_multiple_requests(uid, server_name, url))

        after = make_request(encrypt, server_name, token)
        if after is None:
            return {"error": "Failed to fetch player info (after likes)."}

        jsone = MessageToJson(after)
        data = json.loads(jsone)
        after_like = int(data['AccountInfo'].get('Likes', 0))
        id = int(data['AccountInfo'].get('UID', 0))
        name = str(data['AccountInfo'].get('PlayerNickname', 'Unknown'))
        like_given = after_like - before_like
        status = 1 if like_given != 0 else 2

        if like_given > 0:
            token_tracker[token][0] += 1
            count += 1

        remains = KEY_LIMIT - count
        result = {
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": name,
            "UID": id,
            "status": status,
            "remains": f"({remains}/{KEY_LIMIT})",
            "elapsed_time": f"{round(time.time() - start_time, 3)} sec",
            "executed_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        }
        return result

    result = process_request()
    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
