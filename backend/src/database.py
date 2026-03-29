import os
from supabase import create_client, Client
from dotenv import load_dotenv

# --- 1. LOAD CẤU HÌNH BIẾN MÔI TRƯỜNG ---
# File .env nên nằm ở thư mục gốc của dự án
load_dotenv()

SUPABASE_URL = os.getenv("EXPO_PUBLIC_SUPABASE_URL")
SUPABASE_KEY = os.getenv("EXPO_PUBLIC_SUPABASE_KEY")

# --- 2. KHỞI TẠO KẾT NỐI ---
# Kiểm tra xem đã có đủ cấu hình chưa để tránh sập app khi deploy
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

# --- 3. CÁC HÀM XỬ LÝ CACHE ---

def get_cached_url(url: str):
    """
    Kiểm tra xem URL đã có trong Database chưa.
    Trả về dữ liệu nếu có, ngược lại trả về None.
    """
    if not supabase:
        return None
        
    try:
        # Tìm kiếm URL trong bảng 'url_cache'
        # .strip().lower() để đảm bảo tính đồng nhất
        clean_url = url.strip().lower()
        response = supabase.table("url_cache").select("*").eq("url", clean_url).execute()
        
        if response.data and len(response.data) > 0:
            return response.data[0]
        return None
    except Exception as e:
        print(f"⚠️ Lỗi khi truy vấn Cache: {e}")
        return None

def save_to_cache(url: str, status: str, probability: float, risk_level: str, technical_report: dict):
    """
    Lưu kết quả phân tích AI vào Database để lần sau truy xuất nhanh.
    """
    if not supabase:
        return None

    try:
        clean_url = url.strip().lower()
        data = {
            "url": clean_url,
            "status": status,
            "probability": float(probability),
            "risk_level": risk_level,
            "technical_report": technical_report # Lưu dưới dạng JSON
        }
        
        # Sử dụng upsert: Nếu đã có thì cập nhật, chưa có thì thêm mới
        response = supabase.table("url_cache").upsert(data).execute()
        return response.data
    except Exception as e:
        print(f"⚠️ Không thể lưu vào Cache: {e}")
        return None