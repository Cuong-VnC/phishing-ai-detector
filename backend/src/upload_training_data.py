import pandas as pd
import os
from supabase import create_client, Client
from dotenv import load_dotenv
import math

# Load cấu hình
load_dotenv()
url: str = os.getenv("SUPABASE_URL")
key: str = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(url, key)

def upload_csv_to_supabase(file_path: str):
    print(f"📂 Đang đọc file: {file_path}")
    
    # Đọc CSV
    df = pd.read_csv(file_path)
    
    # --- MAPPING DỮ LIỆU TỪ ẢNH ---
    # Chuyển đổi cột 'Type' của bạn thành các cột mà API yêu cầu
    # Giả sử trong file của bạn: 'Phishing' -> 1.0 (High), 'Benign' -> 0.0 (Low)
    
    processed_data = []
    for _, row in df.iterrows():
        is_phishing = row['Type'].lower() == 'phishing'
        
        processed_data.append({
            "url": row['url'].strip().lower(),
            "type": row['Type'],
            "status": "Phishing" if is_phishing else "Safe",
            "probability": 1.0 if is_phishing else 0.0,
            "risk_level": "High" if is_phishing else "Low",
            "technical_report": {"source": "training_data_upload"}
        })

    # Chia nhỏ để upload (batch size 500)
    batch_size = 500
    for i in range(0, len(processed_data), batch_size):
        batch = processed_data[i : i + batch_size]
        try:
            supabase.table("url_cache").upsert(batch).execute()
            print(f"✅ Đã tải lên dòng {i} đến {i + len(batch)}")
        except Exception as e:
            print(f"❌ Lỗi tại dòng {i}: {e}")

if __name__ == "__main__":
    # Đổi tên này thành tên file CSV thật của bạn
    upload_csv_to_supabase("Phishing_URLs_Cleaned.csv")