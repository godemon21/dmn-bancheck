"""
Free Fire Ban Check API (Flask) v4 — BriefInfo only · ultra-fast
Primary source: GetPlayerBriefInfo field 81

Ban rules (field meanings):
  1.24                   → last login
  1.44                   → account create
  1.81 present           → BANNED
  1.81.4                 → ban start timestamp
  1.81.6                 → ban active flag (1)
  1.81.7                 → ban duration (seconds) → ban_end = 81.4 + 81.7
  1.81.7 missing         → PERMANENT (when 81 present)
  1.86                    → NOT used alone (can be 1 on temp bans)
  1.66                    → NOT used (false positives)

Endpoints:
  GET /bancheck?uid=UID[&region=bd|ind|us]
  GET /jwt-token[?region=bd]     → force refresh JWT(s)
  GET /jwt-status
  GET /health

Local:  python ban_api.py   → port 8001
"""

import time
import threading
import base64
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests
import urllib3
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as crypto_padding

import BriefInfo_pb2 as brief_pb  # compiled from BriefInfo.proto

urllib3.disable_warnings()

# ── Config ──────────────────────────────────────────────────────────────────
AES_KEY = b"Yg&tc%DEuh6%Zc^8"
AES_IV = b"6oyZDr22E3ychjM%"
JWT_URL = "https://as-jwt.vercel.app/token"
TIMEOUT = 5

JWT_TTL_SECONDS = 7 * 60 * 60
JWT_REFRESH_BEFORE = 20 * 60

REGION_ORDER = ("bd", "ind", "us")

REGION_CONFIG = {
    "bd": {
        "base_url": "https://clientbp.ppmainecoonghj.com",
        "uid": "7986980990",
        "password": "C3712D89D0AE9B6DD2D070BC582A94EA6EA5706BC808ACA4CF67B6D245AEE84E",
    },
    "ind": {
        "base_url": "https://client.ind.freefiremobile.com",
        "uid": "8000503863",
        "password": "6EC710DBC845C6FD50EFC0E36836013CBB4C7D23C4ADA6FB8087C2974A807788",
    },
    "us": {
        "base_url": "https://client.us.freefiremobile.com",
        "uid": "7989166692",
        "password": "57E1DA2D4C380C2545178643C2E3039333263A0E7CF7EFE9BBE92F6D9DD32A8D",
    },
}

REGION_NAME_MAP = {
    "IND": "ind", "BD": "bd", "SG": "bd", "TH": "bd", "ID": "bd",
    "VN": "bd", "MY": "bd", "PK": "bd", "CIS": "bd", "TW": "bd",
    "ME": "bd", "EUROPE": "bd", "EU": "bd",
    "US": "us", "NA": "us", "BR": "us", "SAC": "us",
}

HEADERS_BASE = {
    "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
    "Accept": "*/*",
    "Accept-Encoding": "identity",
    "X-GA": "v1 1",
    "ReleaseVersion": "OB55",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Unity-Version": "2018.4.12f1",
}

# ── Shared session (connection pool for speed) ──────────────────────────────
_session = requests.Session()
_session.verify = False
_adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=0)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)

_jwt_lock = threading.Lock()
_jwt_cache = {r: {"token": None, "expires_at": 0.0} for r in REGION_CONFIG}

_uid_region_lock = threading.Lock()
_uid_region_cache = {}

_pool = ThreadPoolExecutor(max_workers=12)

# ── Response cache (ultra-fast repeat lookups) ───────────────────────────────
RESULT_CACHE_TTL = 45  # seconds
_result_cache = {}
_result_cache_lock = threading.Lock()


def _result_cache_get(uid: str):
    with _result_cache_lock:
        entry = _result_cache.get(uid)
        if not entry:
            return None
        if time.time() >= entry["expires_at"]:
            _result_cache.pop(uid, None)
            return None
        return entry["payload"]


def _result_cache_set(uid: str, payload: dict):
    with _result_cache_lock:
        _result_cache[uid] = {
            "payload": payload,
            "expires_at": time.time() + RESULT_CACHE_TTL,
        }
        if len(_result_cache) > 5000:
            items = sorted(_result_cache.items(), key=lambda x: x[1]["expires_at"])
            for k, _ in items[: max(1, len(items) // 5)]:
                _result_cache.pop(k, None)


app = Flask(__name__)


# ── JWT ─────────────────────────────────────────────────────────────────────
def _decode_jwt_exp(token: str) -> float:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        payload = json.loads(base64.urlsafe_b64decode(part))
        if "exp" in payload:
            return float(payload["exp"])
    except Exception:
        pass
    return time.time() + JWT_TTL_SECONDS


def _fetch_fresh_jwt(region: str):
    cfg = REGION_CONFIG[region]
    try:
        r = _session.get(
            f"{JWT_URL}?uid={cfg['uid']}&password={cfg['password']}",
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return None, 0.0
        data = r.json()
        token = data.get("token") or data.get("jwt_token")
        if not token:
            return None, 0.0
        return token, _decode_jwt_exp(token)
    except Exception:
        return None, 0.0


def get_jwt(region: str, force_refresh: bool = False):
    region = region.lower()
    if region not in REGION_CONFIG:
        return None
    with _jwt_lock:
        entry = _jwt_cache[region]
        now = time.time()
        if force_refresh or not entry["token"] or now >= entry["expires_at"] - JWT_REFRESH_BEFORE:
            token, exp = _fetch_fresh_jwt(region)
            if token:
                entry["token"] = token
                entry["expires_at"] = exp
            elif not entry["token"] or now >= entry["expires_at"]:
                return None
        return entry["token"]


def refresh_all_jwts():
    results = {}
    def _one(region):
        token = get_jwt(region, force_refresh=True)
        return region, bool(token)
    futs = [_pool.submit(_one, r) for r in REGION_CONFIG]
    for f in as_completed(futs):
        region, ok = f.result()
        results[region] = ok
    return results


# ── Crypto / protobuf ───────────────────────────────────────────────────────
def aes_encrypt(data: bytes) -> bytes:
    padder = crypto_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV)).encryptor()
    return enc.update(padded) + enc.finalize()


def aes_decrypt(data: bytes) -> bytes:
    try:
        dec = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV)).decryptor()
        decrypted = dec.update(data) + dec.finalize()
        unpadder = crypto_padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()
    except Exception:
        return data


def encode_varint(n: int) -> bytes:
    res = bytearray()
    while n >= 0x80:
        res.append((n & 0x7F) | 0x80)
        n >>= 7
    res.append(n)
    return bytes(res)


def decode_varint(data: bytes, pos: int = 0):
    result = shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def build_uid_payload(uid: str) -> bytes:
    # field1=uid, field2=1 (required — without field2 server often omits ban block 81)
    return aes_encrypt(b"\x08" + encode_varint(int(uid)) + b"\x10\x01")


def make_headers(jwt: str) -> dict:
    return {**HEADERS_BASE, "Authorization": f"Bearer {jwt}", "X-GA-SV": str(int(time.time()))}


def walk_protobuf(data: bytes, max_depth: int = 6) -> dict:
    fields = {}
    if max_depth < 0 or not data:
        return fields
    pos = 0
    while pos < len(data):
        try:
            tag, pos = decode_varint(data, pos)
            field = tag >> 3
            wire = tag & 7
            key = str(field)
            if wire == 0:
                val, pos = decode_varint(data, pos)
                fields[key] = val
            elif wire == 2:
                length, pos = decode_varint(data, pos)
                chunk = data[pos:pos + length]
                pos += length
                try:
                    s = chunk.decode("utf-8")
                    if 1 <= len(s) <= 100 and all(c.isprintable() or ord(c) > 127 for c in s):
                        fields[key] = s
                        continue
                except Exception:
                    pass
                nested = walk_protobuf(chunk, max_depth - 1)
                for nk, nv in nested.items():
                    fields[f"{key}.{nk}"] = nv
            elif wire == 5:
                pos += 4
            elif wire == 1:
                pos += 8
            else:
                break
        except Exception:
            break
    return fields


def format_ts(ts):
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%B %d, %Y %I:%M %p UTC")
    except Exception:
        return None


def format_duration(seconds):
    if not seconds or seconds <= 0:
        return None
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    mins = (seconds % 3600) // 60
    parts = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if mins and not days:
        parts.append(f"{mins} min")
    return " ".join(parts) if parts else f"{seconds}s"


# ── Parse BriefInfo ─────────────────────────────────────────────────────────


# ── Garena antihack (fallback only) ─────────────────────────────────────────
# Session + cookie auto-refresh (like shop2game pattern). On fail → reset session & retry.
GARENA_BASE = "https://ff.garena.com"
GARENA_URL = "https://ff.garena.com/api/antihack/check_banned"
GARENA_CACHE_TTL = 10 * 60          # result cache per uid (seconds)
GARENA_MIN_INTERVAL = 0.3           # soft rate limit between calls
GARENA_SESSION_TTL = 25 * 60        # refresh session cookies every 25 min
GARENA_MAX_RETRIES = 2

_garena_cache = {}                   # uid -> {data, expires_at}
_garena_lock = threading.Lock()
_garena_last_call = 0.0
_garena_session = None
_garena_session_created = 0.0


def _garena_browser_headers(for_html=False):
    if for_html:
        return {
            "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
    return {
        "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Origin": GARENA_BASE,
        "Referer": f"{GARENA_BASE}/en/support/",
        "X-Requested-With": "B6FksShzIgjfrYImLpTsadjS86sddhFH",
        "Connection": "keep-alive",
        "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }


def create_garena_session():
    """Visit Garena homepage/support to obtain cookies (fresh session)."""
    session = requests.Session()
    try:
        session.get(
            f"{GARENA_BASE}/en/support/",
            headers=_garena_browser_headers(for_html=True),
            timeout=15,
        )
    except Exception:
        pass
    return session


def get_garena_session(force_refresh=False):
    """Cached session; auto-refresh every GARENA_SESSION_TTL or on force."""
    global _garena_session, _garena_session_created
    with _garena_lock:
        now = time.time()
        need = (
            force_refresh
            or _garena_session is None
            or (now - _garena_session_created) > GARENA_SESSION_TTL
        )
        if need:
            _garena_session = create_garena_session()
            _garena_session_created = now
        return _garena_session


def check_garena_ban(uid: str, retry_count=0):
    """
    Fallback ban check via Garena official API.
    - Caches successful results per uid
    - Soft rate limit
    - On error / whitelist / empty → force session refresh and retry (like shop2game cookie flow)
    Returns: {is_banned, period, source} or None
    """
    global _garena_last_call
    now = time.time()

    with _garena_lock:
        entry = _garena_cache.get(uid)
        if entry and now < entry["expires_at"]:
            return entry["data"]
        wait = GARENA_MIN_INTERVAL - (now - _garena_last_call)
        if wait > 0.05:
            time.sleep(min(wait, 0.15))
        _garena_last_call = time.time()

    session = get_garena_session(force_refresh=(retry_count > 0))
    try:
        r = session.get(
            GARENA_URL,
            params={"uid": uid, "lang": "en"},
            headers=_garena_browser_headers(for_html=False),
            timeout=12,
        )
        try:
            body = r.json() if r.content else {}
        except Exception:
            body = {}

        # Fail patterns → refresh session & retry (no permanent block)
        msg = str(body.get("msg", "")).lower()
        status = str(body.get("status", "")).lower()
        failed = (
            r.status_code in (401, 403, 429, 503)
            or status == "error"
            or "whitelist" in msg
            or "invalid" in msg
            or "expired" in msg
            or "unauthorized" in msg
            or not isinstance(body.get("data"), dict)
        )

        if failed and retry_count < GARENA_MAX_RETRIES:
            # reset session like the openid example
            with _garena_lock:
                global _garena_session, _garena_session_created
                _garena_session = None
                _garena_session_created = 0.0
            time.sleep(1)
            return check_garena_ban(uid, retry_count + 1)

        if failed:
            return None

        data_block = body.get("data") or {}
        is_banned = int(data_block.get("is_banned") or 0) == 1
        period = int(data_block.get("period") or 0)
        result = {
            "is_banned": is_banned,
            "period": period,
            "source": "GarenaAntihack",
        }
        with _garena_lock:
            _garena_cache[uid] = {
                "data": result,
                "expires_at": time.time() + GARENA_CACHE_TTL,
            }
        return result
    except Exception:
        if retry_count < GARENA_MAX_RETRIES:
            with _garena_lock:
                _garena_session = None
                _garena_session_created = 0.0
            time.sleep(1)
            return check_garena_ban(uid, retry_count + 1)
        return None


def apply_garena_fallback(data: dict, uid: str) -> dict:
    """If BriefInfo did not mark banned, try Garena (cached/rate-limited)."""
    if data.get("is_banned"):
        return data
    g = check_garena_ban(uid)
    if not g or not g.get("is_banned"):
        return data
    period = g.get("period") or 0
    data["is_banned"] = True
    data["source"] = "GarenaAntihack"
    # period 1 ≈ short/temp-ish; 3+ long/permanent-style (no exact dates from Garena)
    if period <= 1:
        data["ban_type"] = "temporary"
        data["ban_status"] = "TEMP_BANNED"
    else:
        data["ban_type"] = "permanent"
        data["ban_status"] = "PERMANENT_BANNED"
    # Garena has no ban_start / ban_end
    data["ban_start"] = None
    data["ban_start_ts"] = None
    data["ban_end"] = None
    data["ban_end_ts"] = None
    data["ban_duration"] = f"{period} period(s)" if period else None
    data["ban_duration_sec"] = None
    data["time_remaining"] = None
    data["time_remaining_sec"] = None
    data["garena_period"] = period
    return data


def parse_brief_info(raw: bytes) -> dict:
    """Parse decrypted GetPlayerBriefInfo body using BriefInfo_pb2 (from BriefInfo.proto)."""
    info = {
        "account_id": "",
        "nickname": None,
        "level": None,
        "region": None,
        "last_login_ts": None,
        "create_at_ts": None,
        "is_banned": False,
        "ban_type": None,
        "ban_status": "NOT_BANNED",
        "ban_ts": None,
        "ban_duration_sec": None,
        "ban_end_ts": None,
    }

    msg = brief_pb.BriefInfoResponse()
    try:
        msg.ParseFromString(raw)
    except Exception:
        return info

    p = msg.player
    if not p.account_id and not p.nickname:
        return info

    info["account_id"] = str(p.account_id) if p.account_id else ""
    info["nickname"] = p.nickname or None
    info["level"] = p.level if p.level else None
    info["region"] = p.region or None
    info["last_login_ts"] = p.last_login if p.last_login else None
    info["create_at_ts"] = p.create_at if p.create_at else None

    # ONLY reliable ban source: field 81 (BanInfo)
    #  - 81.4 present → banned
    #  - 81.7 present → temporary (ban_end = start + duration)
    #  - 81.7 missing → permanent
    # Field 86 alone is NOT permanent (JOKER 18460155565 is temp but has 86=1)
    # Field 66 alone is unreliable (false positives)
    if p.HasField("ban_info"):
        ban = p.ban_info
        info["is_banned"] = True
        info["ban_ts"] = ban.ban_start if ban.ban_start else None
        if ban.ban_duration and ban.ban_duration > 0:
            info["ban_type"] = "temporary"
            info["ban_status"] = "TEMP_BANNED"
            info["ban_duration_sec"] = ban.ban_duration
            if ban.ban_start:
                info["ban_end_ts"] = int(ban.ban_start) + int(ban.ban_duration)
        else:
            info["ban_type"] = "permanent"
            info["ban_status"] = "PERMANENT_BANNED"

    return info



# ── Network ─────────────────────────────────────────────────────────────────
def fetch_brief_info(uid: str, region: str):
    jwt = get_jwt(region)
    if not jwt:
        return None
    base = REGION_CONFIG[region]["base_url"]
    try:
        r = _session.post(
            f"{base}/GetPlayerBriefInfo",
            headers=make_headers(jwt),
            data=build_uid_payload(uid),
            timeout=TIMEOUT,
        )
        if r.status_code != 200 or not r.content or len(r.content) < 16:
            return None
        decrypted = aes_decrypt(r.content)
        if len(decrypted) < 30:
            return None
        return parse_brief_info(decrypted)
    except Exception:
        return None


def detect_region(uid: str):
    """Probe regions in parallel, return (region, brief_info)."""
    with _uid_region_lock:
        cached = _uid_region_cache.get(uid)
        if cached:
            info = fetch_brief_info(uid, cached)
            if info and info.get("nickname"):
                return cached, info

    result = {"region": None, "info": None}
    lock = threading.Lock()

    def _probe(region):
        info = fetch_brief_info(uid, region)
        if info and info.get("nickname"):
            game_r = (info.get("region") or "").upper()
            mapped = REGION_NAME_MAP.get(game_r, region)
            final = mapped if mapped in REGION_CONFIG else region
            with lock:
                if result["region"] is None:
                    result["region"] = final
                    result["info"] = info
            return True
        return False

    futs = [_pool.submit(_probe, r) for r in REGION_ORDER]
    try:
        for f in as_completed(futs, timeout=TIMEOUT + 1):
            try:
                if f.result() and result["region"]:
                    break
            except Exception:
                continue
    except Exception:
        pass
    for f in futs:
        f.cancel()

    region = result["region"] or "bd"
    info = result["info"]
    if info and info.get("nickname"):
        with _uid_region_lock:
            _uid_region_cache[uid] = region
    return region, info


def fetch_ban_info(uid: str, region=None, use_garena=True):
    t0 = time.time()

    if region:
        brief = fetch_brief_info(uid, region)
        if not brief or not brief.get("nickname"):
            region, brief = detect_region(uid)
    else:
        region, brief = detect_region(uid)

    if not brief:
        return {
            "success": False,
            "uid": uid,
            "region": region,
            "message": "Failed to fetch BriefInfo",
            "data": None,
            "ms": int((time.time() - t0) * 1000),
        }, None

    data = {
        "uid": uid,
        "nickname": brief.get("nickname"),
        "level": brief.get("level"),
        "region": brief.get("region") or region.upper(),
        "is_banned": brief["is_banned"],
        "ban_status": brief["ban_status"],
        "ban_type": brief["ban_type"],
        "ban_start": format_ts(brief.get("ban_ts")),
        "ban_start_ts": brief.get("ban_ts"),
        "ban_end": format_ts(brief.get("ban_end_ts")),
        "ban_end_ts": brief.get("ban_end_ts"),
        "ban_duration": format_duration(brief.get("ban_duration_sec")),
        "ban_duration_sec": brief.get("ban_duration_sec"),
        "time_remaining": None,
        "time_remaining_sec": None,
        "last_login": format_ts(brief.get("last_login_ts")),
        "last_login_ts": brief.get("last_login_ts"),
        "create_at": format_ts(brief.get("create_at_ts")),
        "create_at_ts": brief.get("create_at_ts"),
        "source": "GetPlayerBriefInfo",
    }

    # time remaining = ban_end - now (if temp ban still active)
    if data.get("ban_end_ts"):
        remaining = int(data["ban_end_ts"]) - int(time.time())
        if remaining > 0:
            data["time_remaining_sec"] = remaining
            data["time_remaining"] = format_duration(remaining)
        else:
            data["time_remaining_sec"] = 0
            data["time_remaining"] = "expired"

    # Garena fallback only when BriefInfo has no ban block (old bans etc.)
    if use_garena:
        data = apply_garena_fallback(data, uid)

    return {
        "success": True,
        "uid": uid,
        "region": region,
        "data": data,
        "message": "Ban check completed",
        "ms": int((time.time() - t0) * 1000),
    }, None


# ── Routes ──────────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "ban-check-api", "version": "4.0"})



@app.route("/garena-status")
def garena_status():
    now = time.time()
    with _garena_lock:
        cache_n = len(_garena_cache)
        session_age = int(now - _garena_session_created) if _garena_session else None
        has_session = _garena_session is not None
    return jsonify({
        "ok": True,
        "session_active": has_session,
        "session_age_sec": session_age,
        "session_ttl_sec": GARENA_SESSION_TTL,
        "cache_entries": cache_n,
        "cache_ttl_sec": GARENA_CACHE_TTL,
        "min_interval_sec": GARENA_MIN_INTERVAL,
        "max_retries": GARENA_MAX_RETRIES,
    })

@app.route("/garena-refresh", methods=["POST", "GET"])
def garena_refresh():
    """Force Garena session reset (next call creates fresh cookies)."""
    global _garena_session, _garena_session_created
    with _garena_lock:
        _garena_session = None
        _garena_session_created = 0.0
        # optional: clear result cache
        clear = request.args.get("clear_cache", "0") == "1"
        if clear:
            _garena_cache.clear()
    return jsonify({"success": True, "message": "Garena session will refresh on next request"})

@app.route("/jwt-status")
def jwt_status():
    out = {}
    now = time.time()
    with _jwt_lock:
        for region, entry in _jwt_cache.items():
            has = bool(entry["token"])
            remaining = max(0, int(entry["expires_at"] - now)) if has else 0
            out[region] = {
                "cached": has,
                "expires_in_seconds": remaining,
                "expires_in_hours": round(remaining / 3600, 2) if has else 0,
            }
    with _uid_region_lock:
        out["uid_region_cache_size"] = len(_uid_region_cache)
    return jsonify(out)


@app.route("/jwt-token", methods=["GET"])
def jwt_token():
    """Force refresh JWT cache. ?region=bd for one region, or all if omitted."""
    region_arg = request.args.get("region", "").strip().lower() or None
    if region_arg:
        if region_arg not in REGION_CONFIG:
            return jsonify({"success": False, "message": f"Unknown region: {region_arg}"}), 400
        token = get_jwt(region_arg, force_refresh=True)
        return jsonify({
            "success": bool(token),
            "region": region_arg,
            "cached": bool(token),
            "message": "JWT refreshed" if token else "JWT refresh failed",
        })
    results = refresh_all_jwts()
    return jsonify({
        "success": all(results.values()),
        "regions": results,
        "message": "JWT refresh completed",
    })


@app.route("/bancheck", methods=["GET"])
def bancheck():
    uid = request.args.get("uid", "").strip()
    region_arg = request.args.get("region", "").strip().lower() or None
    nocache = request.args.get("nocache", "").strip() in ("1", "true", "yes")
    no_garena = request.args.get("garena", "1").strip() in ("0", "false", "no")

    if not uid:
        return jsonify({"success": False, "uid": "", "data": None, "message": "Missing uid"}), 400
    if not uid.isdigit() or not (5 <= len(uid) <= 15):
        return jsonify({"success": False, "uid": uid, "data": None, "message": "UID must be numeric 5-15 digits"}), 400
    if region_arg and region_arg not in REGION_CONFIG:
        return jsonify({
            "success": False,
            "uid": uid,
            "data": None,
            "message": f"Unknown region. Use: {', '.join(REGION_CONFIG)}",
        }), 400

    if not nocache:
        cached = _result_cache_get(uid)
        if cached is not None:
            out = dict(cached)
            out["ms"] = 0
            out["cached"] = True
            return jsonify(out)

    result, error = fetch_ban_info(uid, region_arg, use_garena=not no_garena)
    if error:
        return jsonify(result), 502
    if result and result.get("success") and not nocache:
        _result_cache_set(uid, result)
    if result is not None:
        result = dict(result)
        result["cached"] = False
    return jsonify(result)


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "Free Fire Ban Check API",
        "version": "4.0",
        "endpoints": {
            "/bancheck": "GET ?uid=UID [&region=bd|ind|us] [&nocache=1] [&garena=0]",
            "/jwt-token": "GET [?region=bd] — force refresh JWT cache",
            "/jwt-status": "GET",
            "/garena-status": "GET",
            "/garena-refresh": "GET/POST",
            "/health": "GET",
        },
        "ban_detection": {
            "source": "GetPlayerBriefInfo only (no external web checks)",
            "field_81": "ban block — start (81.4) + duration (81.7); 86=1 permanent",
            "field_86": "permanent flag",
            "field_66": "removed (unreliable)",
        },
    })


# Warm JWT cache on startup
def _warm_cache():
    try:
        refresh_all_jwts()
        # warm TCP/TLS to game hosts
        for region, cfg in REGION_CONFIG.items():
            try:
                _session.head(cfg["base_url"], timeout=3)
            except Exception:
                pass
        get_garena_session(force_refresh=True)
    except Exception:
        pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001, debug=False, threaded=True)
