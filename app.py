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
import threading
import schedule
import psutil
import os

app = Flask(__name__)

# ✅ Per-key rate limit setup
KEY_LIMIT = 150
token_tracker = defaultdict(lambda: [0, time.time()])  # token: [count, last_reset_time]

# Multiple JWT API endpoints for rotation
JWT_APIS = [
    "https://ff-jwt-api.onrender.com/token?uid={uid}&password={password}",
    "https://jwt-api-unknown.vercel.app/token?uid={uid}&password={password}",
    # Add more APIs here as needed
]

# Track current API index for rotation
current_api_index = 0
api_lock = threading.Lock()

# CPU load monitoring
CPU_COOLDOWN_THRESHOLD = 80  # Percentage
CPU_NORMAL_THRESHOLD = 60    # Percentage
COOLDOWN_DELAY = 5           # Seconds
last_cpu_check = 0
cpu_check_interval = 10      # Check CPU every 10 seconds

# Token processing state
token_processing = False
processed_tokens = 0
total_tokens_to_process = 0
current_processing_uid = ""
token_start_time = 0

def get_cpu_load():
    """Get current CPU load percentage"""
    return psutil.cpu_percent(interval=1)

def should_cooldown():
    """Check if system needs cooldown based on CPU load"""
    global last_cpu_check
    current_time = time.time()
    
    # Only check CPU periodically to avoid overhead
    if current_time - last_cpu_check < cpu_check_interval:
        return False
        
    cpu_load = get_cpu_load()
    last_cpu_check = current_time
    
    print(f"🖥️ CPU Load: {cpu_load}%")
    
    if cpu_load >= CPU_COOLDOWN_THRESHOLD:
        print(f"🔥 High CPU load detected ({cpu_load}%), initiating cooldown...")
        return True
    return False

def cooldown_if_needed():
    """Wait if CPU load is high"""
    if should_cooldown():
        print(f"⏳ Cooling down for {COOLDOWN_DELAY} seconds...")
        time.sleep(COOLDOWN_DELAY)
        
        # Check again after cooldown
        while should_cooldown():
            print(f"🔄 Still high CPU load, cooling down for another {COOLDOWN_DELAY} seconds...")
            time.sleep(COOLDOWN_DELAY)

def get_today_midnight_timestamp():
    now = datetime.now()
    midnight = datetime(now.year, now.month, now.day)
    return midnight.timestamp()

def load_tokens(server_name):
    if server_name == "IND":
        with open("token_ind.json", "r") as f:
            return json.load(f)
    elif server_name in {"BR", "US", "SAC", "NA"}:
        with open("token_br.json", "r") as f:
            return json.load(f)
    else:
        with open("token_bd.json", "r") as f:
            return json.load(f)

def extract_uid_password_pairs(data, current_path=""):
    """
    Extract all UID:password pairs from any JSON structure
    Handles nested objects, arrays, and various formats
    """
    pairs = {}

    if isinstance(data, dict):
        # Check if this is a direct UID:password pair
        if len(data) == 1:
            key = list(data.keys())[0]
            value = data[key]
            if key.isdigit() and isinstance(value, str):
                pairs[key] = value
                return pairs
        
        # Check for nested UID:password pairs
        for key, value in data.items():
            if isinstance(value, str) and key.isdigit():
                # Direct UID:password pair
                pairs[key] = value
            elif key in ["uid", "user_id", "account_id"] and isinstance(value, (str, int)):
                # Look for password in adjacent keys
                uid = str(value)
                password_key = next((k for k in data.keys() if k in ["password", "pass", "pwd"]), None)
                if password_key and isinstance(data[password_key], str):
                    pairs[uid] = data[password_key]
            elif isinstance(value, (dict, list)):
                # Recursively search nested structures
                nested_pairs = extract_uid_password_pairs(value, f"{current_path}.{key}")
                pairs.update(nested_pairs)
                
    elif isinstance(data, list):
        for index, item in enumerate(data):
            if isinstance(item, (dict, list)):
                nested_pairs = extract_uid_password_pairs(item, f"{current_path}[{index}]")
                pairs.update(nested_pairs)
            elif isinstance(item, str) and index % 2 == 0 and index + 1 < len(data):
                # Handle array format: [uid1, password1, uid2, password2, ...]
                next_item = data[index + 1]
                if item.isdigit() and isinstance(next_item, str):
                    pairs[item] = next_item
    
    return pairs

def load_ind_ids():
    """Load UID and password pairs from ind_id.json - works with any JSON structure"""
    try:
        with open("ind_id.json", "r") as f:
            raw_data = json.load(f)

        print(f"📁 Raw JSON structure type: {type(raw_data)}")
        
        # Extract all UID:password pairs from any JSON structure
        pairs = extract_uid_password_pairs(raw_data)
        
        print(f"✅ Found {len(pairs)} UID-password pairs in total")
        if pairs:
            print("📋 Sample pairs:")
            for i, (uid, pwd) in enumerate(list(pairs.items())[:5]):
                print(f"   {uid}: {pwd}")
        
        return pairs
        
    except FileNotFoundError:
        print("❌ ind_id.json not found")
        return {}
    except json.JSONDecodeError as e:
        print(f"❌ JSON parsing error: {e}")
        # Try to read the file as text to see what's wrong
        try:
            with open("ind_id.json", "r") as f:
                content = f.read()
                print(f"📄 File content (first 500 chars): {content[:500]}...")
        except:
            pass
        return {}
    except Exception as e:
        print(f"❌ Unexpected error loading ind_id.json: {e}")
        return {}

def get_next_jwt_api():
    """Get next JWT API endpoint in rotation"""
    global current_api_index
    with api_lock:
        api_url = JWT_APIS[current_api_index]
        current_api_index = (current_api_index + 1) % len(JWT_APIS)
        return api_url

def get_jwt_token(uid, password):
    """Get JWT token from external API with rotation"""
    api_url = get_next_jwt_api()
    url = api_url.format(uid=uid, password=password)
    
    try:
        print(f"🔗 Using API: {api_url.split('/')[2]}")  # Show which API is being used
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            token = data.get('token')
            if token:
                print(f"✅ Success from {api_url.split('/')[2]} for UID {uid}")
                return token
            else:
                print(f"❌ No token in response from {api_url.split('/')[2]} for UID {uid}")
                return None
        else:
            print(f"❌ Failed from {api_url.split('/')[2]} for UID {uid}: HTTP {response.status_code}")
            return None
    except requests.exceptions.Timeout:
        print(f"⏰ Timeout from {api_url.split('/')[2]} for UID {uid}")
        return None
    except Exception as e:
        print(f"❌ Error from {api_url.split('/')[2]} for UID {uid}: {e}")
        return None

def get_jwt_token_with_fallback(uid, password, max_retries=3):
    """Get JWT token with retry logic and API rotation"""
    for attempt in range(max_retries):
        # Check CPU load before each attempt
        cooldown_if_needed()
        
        token = get_jwt_token(uid, password)
        if token:
            return token
        print(f"🔄 Retry {attempt + 1}/{max_retries} for UID {uid}")
        time.sleep(1)  # Wait before retry
    
    print(f"💥 All retries failed for UID {uid}")
    return None

def save_token_immediately(token_data):
    """Save token immediately to file (append or create new)"""
    try:
        # Read existing tokens
        try:
            with open("token_ind.json", "r") as f:
                existing_tokens = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            existing_tokens = []
        
        # Add new token
        existing_tokens.append(token_data)
        
        # Save back to file
        with open("token_ind.json", "w") as f:
            json.dump(existing_tokens, f, indent=2)
            
        print(f"💾 Immediately saved token for UID {token_data.get('uid', 'unknown')}")
        return True
    except Exception as e:
        print(f"❌ Error saving token immediately: {e}")
        return False

def update_tokens_sequential():
    """Update tokens one by one with immediate saving and CPU monitoring"""
    global token_processing, processed_tokens, total_tokens_to_process, current_processing_uid, token_start_time
    
    try:
        uid_password_pairs = load_ind_ids()
        if not uid_password_pairs:
            print("❌ No UID-password pairs found in ind_id.json")
            # Create empty token file to prevent crashes
            with open("token_ind.json", "w") as f:
                json.dump([{"token": "dummy_token"}], f)
            return

        print(f"🔄 Starting sequential token processing for {len(uid_password_pairs)} UID-password pairs...")
        print(f"🔧 Using {len(JWT_APIS)} JWT APIs in rotation")
        print(f"🖥️ CPU monitoring: Cooldown at {CPU_COOLDOWN_THRESHOLD}%")
        
        # Initialize processing state
        token_processing = True
        processed_tokens = 0
        total_tokens_to_process = len(uid_password_pairs)
        token_start_time = time.time()
        
        success_count = 0
        failed_count = 0
        api_usage = {api: 0 for api in JWT_APIS}
        
        # Clear existing token file
        with open("token_ind.json", "w") as f:
            json.dump([], f)
        
        # Process all pairs sequentially with immediate saving
        for i, (uid, password) in enumerate(uid_password_pairs.items(), 1):
            current_processing_uid = uid
            
            # Check CPU load before processing each token
            cooldown_if_needed()
            
            print(f"📡 [{i}/{len(uid_password_pairs)}] Getting token for UID: {uid}")
            
            token = get_jwt_token_with_fallback(uid, password)
            if token:
                token_data = {
                    "token": token,
                    "uid": uid,
                    "generated_at": datetime.now().isoformat(),
                    "sequence": i
                }
                
                # Save immediately
                if save_token_immediately(token_data):
                    success_count += 1
                    # Track which API was successful (approximate)
                    current_api = JWT_APIS[(i-1) % len(JWT_APIS)]
                    api_usage[current_api] += 1
                    print(f"✅ Successfully got and saved token for UID: {uid}")
                else:
                    failed_count += 1
                    print(f"❌ Failed to save token for UID: {uid}")
            else:
                failed_count += 1
                print(f"❌ Failed to get token for UID: {uid}")
            
            processed_tokens = i
            
            # Rate limiting - wait 1 second between requests to avoid overwhelming the API
            if i < len(uid_password_pairs):  # Don't wait after the last request
                time.sleep(1)

        # Final summary
        processing_time = time.time() - token_start_time
        print(f"🎉 Sequential token processing completed!")
        print(f"📊 Stats: {success_count} successful, {failed_count} failed")
        print(f"⏱️ Total processing time: {processing_time:.2f} seconds")
        print("🔧 API Usage:")
        for api, count in api_usage.items():
            print(f"   {api.split('/')[2]}: {count} tokens")
        
        # Save summary
        summary = {
            "total_accounts": len(uid_password_pairs),
            "successful_tokens": success_count,
            "failed_tokens": failed_count,
            "api_usage": api_usage,
            "apis_used": len(JWT_APIS),
            "processing_time_seconds": processing_time,
            "completion_time": datetime.now().isoformat()
        }
        with open("token_update_summary.json", "w") as f:
            json.dump(summary, f, indent=2)
            
    except Exception as e:
        print(f"❌ Error in sequential token processing: {e}")
    finally:
        token_processing = False
        current_processing_uid = ""

def update_tokens():
    """Wrapper for backward compatibility - starts sequential processing"""
    update_tokens_sequential()

def schedule_token_updates():
    """Schedule token updates every 6 hours"""
    schedule.every(6).hours.do(update_tokens_sequential)
    
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute

def start_scheduler():
    """Start the scheduler in a separate thread"""
    scheduler_thread = threading.Thread(target=schedule_token_updates, daemon=True)
    scheduler_thread.start()
    print("✅ Token update scheduler started (runs every 6 hours)")

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
    
    # Send exactly 100 requests to give 100 likes
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

def make_request(encrypt, server_name, token):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
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
    response = requests.post(url, data=edata, headers=headers, verify=False)
    hex_data = response.content.hex()
    binary = bytes.fromhex(hex_data)
    return decode_protobuf(binary)

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        print(f"Error decoding Protobuf data: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    key = request.args.get("key")

    if key != "diamondxpress":
        return jsonify({"error": "Invalid or missing API key 🔑"}), 403
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    def process_request():
        data = load_tokens(server_name)
        if not data:
            return {
                "error": "No tokens available for this server",
                "status": 500
            }

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
            return {
                "error": "Failed to get initial like count",
                "status": 500
            }

        jsone = MessageToJson(before)
        data = json.loads(jsone)
        before_like = int(data['AccountInfo'].get('Likes', 0))

        # Select URL
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"

        # Send exactly 100 requests to give 100 likes
        print(f"🎯 Sending 100 like requests to UID: {uid}")
        asyncio.run(send_multiple_requests(uid, server_name, url))

        after = make_request(encrypt, server_name, token)
        if after is None:
            return {
                "error": "Failed to get final like count",
                "status": 500
            }

        jsone = MessageToJson(after)
        data = json.loads(jsone)
        after_like = int(data['AccountInfo']['Likes'])
        id = int(data['AccountInfo']['UID'])
        name = str(data['AccountInfo']['PlayerNickname'])
        like_given = after_like - before_like
        status = 1 if like_given != 0 else 2

        # Initialize remains with current count
        remains = KEY_LIMIT - count

        if like_given > 0:
            token_tracker[token][0] += 1
            count += 1
            remains = KEY_LIMIT - count  # Update remains after incrementing count

        result = {
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": name,
            "UID": id,
            "status": status,
            "remains": f"({remains}/{KEY_LIMIT})",
            "message": f"Successfully sent 100 like requests! Received {like_given} new likes."
        }
        return result

    result = process_request()
    return jsonify(result)

@app.route('/update-tokens', methods=['GET'])
def manual_update_tokens():
    """Manual endpoint to trigger token update"""
    key = request.args.get("key")

    if key != "diamondxpress":
        return jsonify({"error": "Invalid or missing API key 🔑"}), 403
    
    print("🔄 Manual token update triggered...")
    
    # Start token processing in a separate thread to avoid blocking
    def start_processing():
        update_tokens_sequential()
    
    processing_thread = threading.Thread(target=start_processing, daemon=True)
    processing_thread.start()
    
    return jsonify({
        "message": "Token update process started in background",
        "status": "processing",
        "started_at": datetime.now().isoformat()
    })

@app.route('/token-status', methods=['GET'])
def token_status():
    """Check current token processing status"""
    key = request.args.get("key")

    if key != "diamondxpress":
        return jsonify({"error": "Invalid or missing API key 🔑"}), 403
    
    current_time = time.time()
    elapsed_time = current_time - token_start_time if token_start_time > 0 else 0
    
    if token_processing:
        progress_percentage = (processed_tokens / total_tokens_to_process * 100) if total_tokens_to_process > 0 else 0
        estimated_total_time = (elapsed_time / processed_tokens * total_tokens_to_process) if processed_tokens > 0 else 0
        estimated_remaining = estimated_total_time - elapsed_time if estimated_total_time > elapsed_time else 0
        
        status = {
            "status": "processing",
            "processed": processed_tokens,
            "total": total_tokens_to_process,
            "progress": f"{progress_percentage:.1f}%",
            "current_uid": current_processing_uid,
            "elapsed_time_seconds": round(elapsed_time, 2),
            "estimated_remaining_seconds": round(estimated_remaining, 2),
            "cpu_load": f"{get_cpu_load()}%"
        }
    else:
        try:
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
            token_count = len(tokens)
        except:
            token_count = 0
            
        status = {
            "status": "idle",
            "total_tokens_available": token_count,
            "last_processing_time": round(elapsed_time, 2) if token_start_time > 0 else 0,
            "cpu_load": f"{get_cpu_load()}%"
        }
    
    return jsonify(status)

@app.route('/check-tokens', methods=['GET'])
def check_tokens():
    """Check available tokens"""
    key = request.args.get("key")

    if key != "diamondxpress":
        return jsonify({"error": "Invalid or missing API key 🔑"}), 403
    
    try:
        with open("token_ind.json", "r") as f:
            tokens = json.load(f)
        return jsonify({
            "token_count": len(tokens),
            "tokens": tokens[:10]  # Return first 10 to avoid huge response
        })
    except Exception as e:
        return jsonify({"error": f"Failed to read tokens: {e}"})

@app.route('/check-accounts', methods=['GET'])
def check_accounts():
    """Check available UID-password pairs"""
    key = request.args.get("key")

    if key != "diamondxpress":
        return jsonify({"error": "Invalid or missing API key 🔑"}), 403
    
    accounts = load_ind_ids()
    return jsonify({
        "account_count": len(accounts),
        "accounts": dict(list(accounts.items())[:10])  # Return first 10 to avoid huge response
    })

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get statistics about tokens and accounts"""
    key = request.args.get("key")

    if key != "diamondxpress":
        return jsonify({"error": "Invalid or missing API key 🔑"}), 403
    
    accounts = load_ind_ids()
    
    try:
        with open("token_ind.json", "r") as f:
            tokens = json.load(f)
        token_count = len(tokens)
    except:
        token_count = 0
    
    try:
        with open("token_update_summary.json", "r") as f:
            summary = json.load(f)
    except:
        summary = {"last_updated": "Never"}
    
    return jsonify({
        "total_accounts": len(accounts),
        "available_tokens": token_count,
        "coverage_percentage": round((token_count / len(accounts)) * 100, 2) if accounts else 0,
        "last_update": summary.get("last_updated", "Never"),
        "rate_limit_per_token": KEY_LIMIT,
        "jwt_apis_configured": len(JWT_APIS),
        "current_api_rotation": JWT_APIS,
        "cpu_monitoring": {
            "cooldown_threshold": f"{CPU_COOLDOWN_THRESHOLD}%",
            "cooldown_delay": f"{COOLDOWN_DELAY} seconds",
            "current_cpu_load": f"{get_cpu_load()}%"
        }
    })

@app.route('/add-jwt-api', methods=['POST'])
def add_jwt_api():
    """Add a new JWT API endpoint"""
    key = request.args.get("key")
    api_url = request.json.get("api_url")

    if key != "diamondxpress":
        return jsonify({"error": "Invalid or missing API key 🔑"}), 403
    
    if not api_url:
        return jsonify({"error": "api_url is required"}), 400
    
    # Validate the URL format
    if not api_url.startswith("http"):
        return jsonify({"error": "Invalid URL format"}), 400
    
    # Check if API already exists
    if api_url in JWT_APIS:
        return jsonify({"error": "API already exists"}), 400
    
    # Add the new API
    JWT_APIS.append(api_url)
    
    return jsonify({
        "message": "JWT API added successfully",
        "total_apis": len(JWT_APIS),
        "apis": JWT_APIS
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "cpu_load": f"{get_cpu_load()}%",
        "memory_usage": f"{psutil.virtual_memory().percent}%"
    })

if __name__ == '__main__':
    # Start the scheduler when the app starts
    start_scheduler()

    # Perform initial token update in background
    print("🔄 Starting initial token update in background...")
    print(f"🔧 Using {len(JWT_APIS)} JWT APIs:")
    for i, api in enumerate(JWT_APIS, 1):
        print(f"   {i}. {api}")
    print(f"🖥️ CPU monitoring: Cooldown at {CPU_COOLDOWN_THRESHOLD}%")
    print("🎯 Like system: Will send exactly 100 likes per request")
    
    # Start initial token processing in background
    initial_token_thread = threading.Thread(target=update_tokens_sequential, daemon=True)
    initial_token_thread.start()
    
    # Run on port 14062
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=14062)