import os
import sys
import types
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

# --- 🚀 CẤU HÌNH KERAS 3 & VÁ LỖI LEGACY ---
os.environ["KERAS_BACKEND"] = "tensorflow" 

try:
    import keras
    m = types.ModuleType('keras.src.legacy')
    sys.modules['keras.src.legacy'] = m
    sys.modules['keras.src.legacy.preprocessing'] = m
    import keras.preprocessing.text as txt
    import keras.preprocessing.sequence as seq
    sys.modules['keras.src.legacy.preprocessing.text'] = txt
    sys.modules['keras.src.legacy.preprocessing.sequence'] = seq
    print("✅ Keras 3 đã sẵn sàng với bản vá Legacy")
except Exception as e:
    print(f"⚠️ Cảnh báo Keras: {e}")

from keras.models import load_model
from keras.preprocessing.sequence import pad_sequences

# Thiết lập đường dẫn
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(SRC_DIR)
MODEL_DIR = os.path.join(BACKEND_DIR, "models")
if SRC_DIR not in sys.path: sys.path.insert(0, SRC_DIR)

from features import extract_basic_features, get_advanced_insights
from database import check_url_in_db

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Load Models
model_xgb = None
model_lstm = None
tokenizer = None

def load_all_models():
    global model_xgb, model_lstm, tokenizer
    try:
        with open(os.path.join(MODEL_DIR, "tokenizer.pickle"), "rb") as f:
            tokenizer = pickle.load(f)
        model_xgb = xgb.XGBClassifier()
        model_xgb.load_model(os.path.join(MODEL_DIR, "phishing_xgboost.json"))
        model_lstm = load_model(os.path.join(MODEL_DIR, "phishing_lstm.keras"))
        return True
    except Exception as e:
        print(f"❌ LỖI NẠP MODEL: {e}")
        return False

load_all_models()

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
        v = re.sub(r'[<>"\'\s]', '', v)
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

@app.post("/predict")
async def predict(request: URLRequest):
    raw_url = request.url
    processed_url = raw_url.lower() if raw_url.startswith("http") else "http://" + raw_url.lower()

    if not is_safe_url(processed_url):
        return {"status": "Error", "detail": "URL blocked for security reasons"}

    # 1. DB Nội bộ
    db_record = check_url_in_db(raw_url)
    if db_record: return db_record

    # 2. URLhaus API (Chuyên dụng với Auth-Key)
    urlhaus_res = check_urlhaus(processed_url)
    if urlhaus_res: return urlhaus_res

    # 3. Google Safe Browsing
    google_res = check_google_safe_browsing(processed_url)
    if google_res: return google_res

    # 4. AI Analysis
    try:
        adv = get_advanced_insights(processed_url)
        feats = np.array([extract_basic_features(processed_url)], dtype=float)
        prob_xgb = float(model_xgb.predict_proba(feats)[0][1])
        seqs = tokenizer.texts_to_sequences([processed_url])
        padded = pad_sequences(seqs, maxlen=200)
        prob_lstm = float(model_lstm.predict(padded, verbose=0)[0][0])
        
        final_prob = (prob_xgb * 0.4) + (prob_lstm * 0.6)
        if adv.get('is_new_domain'): final_prob = min(0.99, final_prob + 0.15)
        
        status = "Phishing" if final_prob >= 0.7 else ("Suspicious" if final_prob >= 0.4 else "Safe")
        risk = "High" if final_prob >= 0.7 else ("Medium" if final_prob >= 0.4 else "Low")
        
        return {
            "url": raw_url, "status": status, "probability": round(final_prob, 4), "risk_level": risk,
            "technical_report": {
                "domain_age": adv.get('domain_age_days', "N/A"),
                "dns_status": adv.get('dns_status', "Unknown"),
                "impersonation_risk": adv.get('impersonation_risk', "Low"),
                "is_shortened": adv.get('is_shortened', False)
            },
            "source": "ai_analysis"
        }
    except Exception as e:
        return {"status": "Error", "detail": str(e)}

if __name__ == "__main__":
    import uvicorn
    import os
    # Lấy cổng từ hệ thống
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
