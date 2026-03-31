import os
from supabase import create_client, Client
from dotenv import load_dotenv

# --- 1. LOAD CẤU HÌNH BIẾN MÔI TRƯỜNG ---
load_dotenv()

SUPABASE_URL = os.getenv("EXPO_PUBLIC_SUPABASE_URL")
SUPABASE_KEY = os.getenv("EXPO_PUBLIC_SUPABASE_KEY")

# --- 2. KHỞI TẠO KẾT NỐI ---
try:
    if not SUPABASE_URL or not SUPABASE_KEY:
        print("⚠️ CẢNH BÁO: Chưa cấu hình SUPABASE_URL hoặc SUPABASE_KEY trong .env")
        supabase: Client = None
    else:
        supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
        print("✅ Kết nối Database Supabase thành công!")
except Exception as e:
    print(f"❌ Lỗi kết nối Database: {e}")
    supabase = None

# --- 3. CÁC HÀM TRA CỨU DANH SÁCH ---

def check_url_in_db(url: str):
    """
    Kiểm tra URL có nằm trong danh sách Phishing hoặc Safe đã có sẵn không.
    Trả về dữ liệu nếu tìm thấy, ngược lại trả về None.
    """
    if not supabase:
        return None
        
    try:
        clean_url = url.strip().lower()
        
        # 1. Tra cứu trong bảng Phishing (Blacklist)
        res_phishing = supabase.table("phishing_urls").select("*").eq("url", clean_url).execute()
        if res_phishing.data and len(res_phishing.data) > 0:
            result = res_phishing.data[0]
            return {**result, "source": "database_blacklist"}
            
        # 2. Tra cứu trong bảng Safe (Whitelist)
        res_safe = supabase.table("safe_urls").select("*").eq("url", clean_url).execute()
        if res_safe.data and len(res_safe.data) > 0:
            result = res_safe.data[0]
            return {**result, "source": "database_whitelist"}
            
        return None
    except Exception as e:
        print(f"⚠️ Lỗi khi tra cứu Database: {e}")
        return None
