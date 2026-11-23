from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)

AES_KEY = bytes([
    89, 103, 38, 116, 99, 37, 68, 69,
    117, 104, 54, 37, 90, 99, 94, 56
])

AES_IV = bytes([
    54, 111, 121, 90, 68, 114, 50, 50,
    69, 51, 121, 99, 104, 106, 77, 37
])

FREEFIRE_VERSION = "OB55"

JWT_API_BASE = "https://jwt-bot-by-anurag-singh.vercel.app/token"

REGION_URLS = {
    "BD":     "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo",
    "BR":     "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "EUROPE": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo",
    "ID":     "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo",
    "IND":    "https://clientbp.freefireind.in/UpdateSocialBasicInfo",
    "ME":     "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo",
    "NA":     "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "PK":     "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo",
    "TW":     "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo",
    "VN":     "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo"
}

HEADERS = {
    "X-Unity-Version":  "2018.4.11f1",
    "X-GA":             "v1 1",
    "ReleaseVersion":   FREEFIRE_VERSION,
    "Content-Type":     "application/x-www-form-urlencoded",
    "User-Agent":       "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F)",
    "Connection":       "Keep-Alive",
    "Accept-Encoding":  "gzip"
}


# ─── protobuf helpers ────────────────────────────────────────────────────────

def varInt(n: int) -> bytes:
    result = []
    while True:
        byte = n & 127
        n >>= 7
        if n:
            byte |= 128
        result.append(byte)
        if not n:
            break
    return bytes(result)


def buildField(field_num: int, value) -> bytes:
    if isinstance(value, int):
        return varInt((field_num << 3) | 0) + varInt(value)
    if isinstance(value, (str, bytes)):
        if isinstance(value, str):
            value = value.encode("utf-8")
        return varInt((field_num << 3) | 2) + varInt(len(value)) + value
    raise ValueError("Unsupported protobuf field type")


def buildBioPacket(bio: str) -> bytes:
    p = bytearray()
    p.extend(buildField(2,  17))
    p.extend(buildField(5,  b""))
    p.extend(buildField(6,  b""))
    p.extend(buildField(8,  bio))
    p.extend(buildField(9,  1))
    p.extend(buildField(11, b""))
    p.extend(buildField(12, b""))
    return bytes(p)


def aesEncrypt(data: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))


# ─── JWT fetcher ─────────────────────────────────────────────────────────────

def fetchJWT(uid: str, password: str):
    """Returns (token_str, None) on success, (None, error_str) on failure."""
    try:
        resp = requests.get(
            JWT_API_BASE,
            params={"uid": uid, "password": password},
            timeout=15
        )
        if resp.status_code != 200:
            return None, f"JWT API returned HTTP {resp.status_code}"

        data  = resp.json()
        token = (
            data.get("token")
            or data.get("jwt")
            or data.get("access_token")
            or data.get("JWT")
        )
        if not token:
            return None, f"JWT API gave no token. Raw: {data}"

        return str(token).strip(), None

    except requests.Timeout:
        return None, "JWT API timed out"
    except requests.RequestException as e:
        return None, f"JWT API connection error: {e}"
    except Exception as e:
        return None, f"JWT API parse error: {e}"


# ─── bio sender ──────────────────────────────────────────────────────────────

def sendBio(jwt: str, region: str, bio: str):
    """Returns (response_dict, http_status_int)."""
    try:
        encrypted = aesEncrypt(buildBioPacket(bio))
        headers   = {**HEADERS, "Authorization": f"Bearer {jwt}"}

        resp = requests.post(
            REGION_URLS[region],
            headers=headers,
            data=encrypted,
            timeout=15
        )

        if resp.status_code == 200:
            return {"status": "success", "region": region, "bio": bio,
                    "message": "Bio updated successfully"}, 200

        return {"status": "failed", "region": region,
                "http_code": resp.status_code,
                "message": "FF server rejected the request"}, 502

    except requests.Timeout:
        return {"status": "error", "message": "FF server timed out"}, 502
    except requests.RequestException as e:
        return {"status": "error", "message": f"FF server error: {e}"}, 502
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500


# ─── routes ──────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "name":          "FF Bio API",
        "status":        "online",
        "endpoint":      "/rbc",
        "method":        "GET",
        "params":        {
            "uid":    "Free Fire UID",
            "pass":   "Account password",
            "bio":    "Bio text (max 100 chars)",
            "region": f"One of: {', '.join(REGION_URLS.keys())} (default: BD)"
        },
        "total_regions": len(REGION_URLS)
    })


@app.route("/rbc", methods=["GET"])
def rbc():
    """
    Auto-fetch JWT → encrypt → set FF bio.

    GET /rbc?uid=&pass=&bio=&region=
    """

    uid    = request.args.get("uid",    "").strip()
    passwd = request.args.get("pass",   "").strip()
    bio    = request.args.get("bio",    "").strip()
    region = request.args.get("region", "BD").upper().strip()

    # validation
    if not uid:
        return jsonify({"status": "error", "message": "uid is required"}), 400
    if not passwd:
        return jsonify({"status": "error", "message": "pass is required"}), 400
    if not bio:
        return jsonify({"status": "error", "message": "bio is required"}), 400
    if region not in REGION_URLS:
        return jsonify({
            "status":            "error",
            "message":           "Invalid region",
            "supported_regions": list(REGION_URLS.keys())
        }), 400
    if len(bio) > 100:
        return jsonify({"status": "error", "message": "Bio exceeds 100 characters"}), 400

    # fetch JWT
    jwt, err = fetchJWT(uid, passwd)
    if err:
        return jsonify({"status": "error", "step": "jwt_fetch", "message": err}), 502

    # send bio
    result, status = sendBio(jwt, region, bio)
    if result.get("status") == "success":
        result["uid"] = uid

    return jsonify(result), status

