import os
import sys
import types

# --- 🚀 CẤU HÌNH KERAS 3 & VÁ LỖI LEGACY ---
os.environ["KERAS_BACKEND"] = "tensorflow" 

try:
    import keras
    # Vá lỗi để nạp Tokenizer từ Keras 2 sang Keras 3
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

import pickle
import pandas as pd
import numpy as np
import xgboost as xgb
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Import Keras 3 components
from keras.models import load_model
from keras.preprocessing.sequence import pad_sequences

# Thiết lập đường dẫn
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(SRC_DIR)
MODEL_DIR = os.path.join(BACKEND_DIR, "models")
if SRC_DIR not in sys.path: sys.path.insert(0, SRC_DIR)

from features import extract_basic_features, get_advanced_insights
from database import get_cached_url, save_to_cache

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

model_xgb = None
model_lstm = None
tokenizer = None

def load_all_models():
    global model_xgb, model_lstm, tokenizer
    print("\n--- 📂 ĐANG NẠP MODELS TRÊN KERAS 3 ---")
    try:
        # 1. Nạp Tokenizer
        with open(os.path.join(MODEL_DIR, "tokenizer.pickle"), "rb") as f:
            tokenizer = pickle.load(f)
        
        # 2. Nạp XGBoost
        model_xgb = xgb.XGBClassifier()
        model_xgb.load_model(os.path.join(MODEL_DIR, "phishing_xgboost.json"))
        
        # 3. Nạp LSTM (Keras 3 nạp file .keras)
        model_lstm = load_model(os.path.join(MODEL_DIR, "phishing_lstm.keras"))
        
        print("✅ TRẠNG THÁI: TẤT CẢ MODEL ĐÃ SẴN SÀNG PHỤC VỤ!")
        return True
    except Exception as e:
        print(f"❌ LỖI NẠP MODEL: {e}")
        return False

load_all_models()

class URLRequest(BaseModel):
    url: str

@app.get("/")
async def root():
    return {"status": "online", "message": "Phishing Guardian AI API is running!"}
@app.post("/predict")
async def predict(request: URLRequest):
    url = request.url.strip()
    if not url: return {"status": "Error", "detail": "URL trống"}
    
    # 1. Check Database Cache
    cached = get_cached_url(url)
    if cached: return {**cached, "source": "database_cache"}

    # 2. Chuẩn hóa URL
    processed_url = url.lower() if url.startswith("http") else "http://" + url.lower()
    
    try:
        adv = get_advanced_insights(processed_url)
        
        # AI Inference
        # XGBoost
        feats = np.array([extract_basic_features(processed_url)], dtype=float)
        prob_xgb = float(model_xgb.predict_proba(feats)[0][1])
        
        # LSTM (Keras 3)
        seqs = tokenizer.texts_to_sequences([processed_url])
        padded = pad_sequences(seqs, maxlen=200)
        prob_lstm = float(model_lstm.predict(padded, verbose=0)[0][0])
        
        # Ensemble (40/60)
        final_prob = (prob_xgb * 0.4) + (prob_lstm * 0.6)
        if adv.get('is_new_domain'): final_prob = min(0.99, final_prob + 0.15)
        
        status = "Phishing" if final_prob >= 0.7 else ("Suspicious" if final_prob >= 0.4 else "Safe")
        risk = "High" if final_prob >= 0.7 else ("Medium" if final_prob >= 0.4 else "Low")
        
        res = {
            "status": status, 
            "probability": round(float(final_prob), 4), 
            "risk_level": risk,
            "technical_report": {
                "domain_age": adv.get('domain_age_days', "N/A"),
                "dns_status": adv.get('dns_status', "Unknown"),
                "impersonation_risk": adv.get('impersonation_risk', "Low"),
                "is_shortened": adv.get('is_shortened', False)
            }
        }
        save_to_cache(url, status, final_prob, risk, res["technical_report"])
        return {**res, "source": "ai_analysis"}
    except Exception as e:
        print(f"❌ Lỗi khi quét: {e}")
        return {"status": "Error", "detail": str(e)}

if __name__ == "__main__":
    import uvicorn
    import os
    # Lấy cổng từ hệ thống
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
