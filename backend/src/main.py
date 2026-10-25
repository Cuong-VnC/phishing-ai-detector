import os
import sys
import json
import pickle
import numpy as np
import xgboost as xgb
import requests
import re
from urllib.parse import urlparse
import socket
import ipaddress
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

# --- CẤU HÌNH KERAS ---
os.environ["KERAS_BACKEND"] = "tensorflow"

from keras.models import load_model

# Thiết lập đường dẫn
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(SRC_DIR)
MODEL_DIR = os.path.join(BACKEND_DIR, "models")
if SRC_DIR not in sys.path: sys.path.insert(0, SRC_DIR)

from features import (extract_features, registrable_domain, get_advanced_insights,
                      load_tokenizer_json, texts_to_char_sequences, pad_post, FEATURE_NAMES)
from database import check_url_in_db

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Load Models (pipeline notebook dataset_url_05: NN -> XGBoost stack)
# 5 artifacts trong backend/models: phishing_nn.keras, xgb_model.json,
# tokenizer.json, scaler.pkl, meta.json
model_nn = None
model_xgb = None
tokenizer_index = None  # (word_index, oov_index)
tokenizer_oov = None
scaler = None
META = {"threshold": 0.5, "max_len": 200, "trusted_domains": set(), "feature_names": FEATURE_NAMES}


def load_all_models():
    global model_nn, model_xgb, tokenizer_index, tokenizer_oov, scaler, META
    try:
        with open(os.path.join(MODEL_DIR, "meta.json"), encoding="utf-8") as f:
            meta = json.load(f)
        META = {
            "threshold": float(meta.get("threshold", 0.5)),
            "max_len": int(meta.get("max_len", 200)),
            "trusted_domains": set(meta.get("trusted_domains", [])),
            "feature_names": meta.get("feature_names", FEATURE_NAMES),
        }
        if len(META["feature_names"]) != 18:
            print(f"⚠️ Cảnh báo: meta.json có {len(META['feature_names'])} features, kỳ vọng 18")
        tokenizer_index, tokenizer_oov = load_tokenizer_json(os.path.join(MODEL_DIR, "tokenizer.json"))
        with open(os.path.join(MODEL_DIR, "scaler.pkl"), "rb") as f:
            scaler = pickle.load(f)
        model_xgb = xgb.XGBClassifier()
        model_xgb.load_model(os.path.join(MODEL_DIR, "xgb_model.json"))
        model_nn = load_model(os.path.join(MODEL_DIR, "phishing_nn.keras"))
        print(f"✅ Đã nạp pipeline mới: NN + XGBoost, threshold={META['threshold']}, "
              f"whitelist={len(META['trusted_domains'])} domains")
        return True
    except Exception as e:
        print(f"❌ LỖI NẠP MODEL: {e}")
        return False


load_all_models()


@app.get("/health")
async def health():
    """Kiểm tra nhanh service và trạng thái nạp model (dùng cho Render health check)."""
    loaded = all(v is not None for v in [model_nn, model_xgb, tokenizer_index, scaler])
    return {"status": "ok" if loaded else "degraded",
            "models_loaded": loaded,
            "threshold": META["threshold"]}


# --- 🛡️ BẢO MẬT: OWASP TOP 10 (SSRF & Input Validation) ---
def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]: return False
        hostname = parsed.hostname
        if not hostname: return False
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local)
    except: return False


class URLRequest(BaseModel):
    url: str
    @field_validator('url')
    @classmethod
    def validate_input(cls, v):
        v = v.strip()
        if not v or len(v) > 2048: raise ValueError('URL invalid or too long')
        v = re.sub(r'[<>\"\'\s]', '', v)
        return v


# --- 🔍 TẦNG TRUY VẤN: URLHAUS API (CHUYÊN DỤNG) ---
def check_urlhaus(url: str):
    """Truy vấn URLhaus API sử dụng Auth-Key bắt buộc."""
    api_key = os.getenv("URLHAUS_API_KEY")
    if not api_key:
        print("⚠️ Cảnh báo: Thiếu URLHAUS_API_KEY trong .env")
        return None

    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {'Auth-Key': api_key}
    data = {'url': url}

    try:
        response = requests.post(endpoint, data=data, headers=headers, timeout=5)
        res_json = response.json()
        if res_json.get('query_status') == 'ok':
            return {
                "status": "Phishing/Malicious",
                "probability": 1.0,
                "risk_level": "High",
                "technical_report": {
                    "threat": res_json.get('threat', 'unknown'),
                    "urlhaus_reference": res_json.get('urlhaus_reference'),
                    "status": res_json.get('url_status')
                },
                "source": "urlhaus_database"
            }
        return None
    except: return None


# --- 🔍 TẦNG TRUY VẤN: GOOGLE SAFE BROWSING ---
def check_google_safe_browsing(url: str):
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not api_key: return None
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        r = requests.post(endpoint, json=payload, timeout=5)
        data = r.json()
        if "matches" in data:
            return {
                "status": "Phishing", "probability": 1.0, "risk_level": "High",
                "technical_report": {"threat_type": data["matches"][0]["threatType"]},
                "source": "google_safe_browsing"
            }
        return None
    except: return None


def predict_with_pipeline(url: str):
    """Đúng logic predict_url của notebook: whitelist -> 18 features -> scaler
    -> NN -> XGBoost stack -> ngưỡng trong meta.json. Trả về (status, prob, nn_prob)."""
    u = str(url).strip().lower()
    rd = registrable_domain(u)
    if rd in META["trusted_domains"]:  # whitelist: so sánh domain đăng ký, không dùng substring
        return "Safe", 0.0, 0.0, "whitelist"
    feats = np.array([extract_features(u)], dtype=np.float32)
    scaled = scaler.transform(feats)
    seq = pad_post(texts_to_char_sequences([u], tokenizer_index, tokenizer_oov),
                   META["max_len"])
    nn_p = float(model_nn.predict([np.array(seq), scaled], verbose=0).ravel()[0])
    stack = np.column_stack([[nn_p], scaled])  # [nn_prob, 18 features đã chuẩn hóa]
    p = float(model_xgb.predict_proba(stack)[0][1])
    status = "Phishing" if p >= META["threshold"] else "Safe"
    return status, p, nn_p, "ai_analysis"


def normalize_db_record(record, raw_url):
    """Chuẩn hóa row Supabase về đúng shape chuẩn của API.
    check_url_in_db trả nguyên row DB (field không xác định) nên FE không đọc
    được -> hiển thị sai. Chỉ tin 2 nguồn đã biết; shape lạ thì trả None để
    rơi xuống các tầng sau thay vì trả verdict không rõ ràng."""
    source = record.get("source", "")
    if source == "database_blacklist":
        status, prob, risk = "Phishing", 1.0, "High"
    elif source == "database_whitelist":
        status, prob, risk = "Safe", 0.0, "Low"
    else:
        return None
    tr = record.get("technical_report") or {}
    return {
        "url": record.get("url", raw_url),
        "status": status, "probability": prob, "risk_level": risk,
        "technical_report": {
            "domain_age": tr.get("domain_age", "N/A"),
            "dns_status": tr.get("dns_status", "Unknown"),
            "impersonation_risk": tr.get("impersonation_risk", "Low"),
            "is_shortened": bool(tr.get("is_shortened", False)),
        },
        "source": source,
    }


@app.post("/predict")
async def predict(request: URLRequest):
    raw_url = request.url
    processed_url = raw_url.lower() if raw_url.startswith("http") else "http://" + raw_url.lower()

    if not is_safe_url(processed_url):
        # Lỗi phải trả HTTP status thật, không trả 200 kèm {"status": "Error"}
        # vì FE đọc response.ok sẽ tưởng là kết quả hợp lệ.
        raise HTTPException(status_code=400, detail="URL blocked for security reasons")

    # 1. DB Nội bộ (đã chuẩn hóa về shape chuẩn; shape lạ thì bỏ qua)
    db_record = check_url_in_db(raw_url)
    if db_record:
        normalized = normalize_db_record(db_record, raw_url)
        if normalized: return normalized

    # 2. URLhaus API (Chuyên dụng với Auth-Key)
    urlhaus_res = check_urlhaus(processed_url)
    if urlhaus_res: return urlhaus_res

    # 3. Google Safe Browsing
    google_res = check_google_safe_browsing(processed_url)
    if google_res: return google_res

    # 4. AI Analysis (pipeline mới)
    if model_nn is None or model_xgb is None or tokenizer_index is None or scaler is None:
        raise HTTPException(status_code=503, detail="Models not loaded")
    try:
        status, prob, nn_prob, source = predict_with_pipeline(processed_url)

        if source == "whitelist":
            return {
                "url": raw_url, "status": status, "probability": 0.0, "risk_level": "Low",
                "technical_report": {
                    "domain_age": "N/A",
                    "dns_status": "Unknown",
                    "impersonation_risk": "Low",
                    "is_shortened": False
                },
                "source": "whitelist"
            }

        adv = get_advanced_insights(processed_url)
        risk = "High" if prob >= 0.7 else ("Medium" if prob >= 0.4 else "Low")

        return {
            "url": raw_url, "status": status, "probability": round(prob, 4), "risk_level": risk,
            "technical_report": {
                "domain_age": adv.get('domain_age_days', "N/A"),
                "dns_status": adv.get('dns_status', "Unknown"),
                "impersonation_risk": adv.get('impersonation_risk', "Low"),
                "is_shortened": adv.get('is_shortened', False),
                "nn_probability": round(nn_prob, 4)
            },
            "source": "ai_analysis"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    import os
    # Lấy cổng từ hệ thống
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
