import tldextract
import re
import math
import socket
import whois
from datetime import datetime
import Levenshtein

# --- DANH SÁCH THƯƠNG HIỆU ĐỐI CHỨNG ---
TOP_BRANDS = [
    "google", "facebook", "amazon", "apple", "microsoft", "netflix", 
    "paypal", "binance", "metamask", "misa", "shopee", "lazada", 
    "vietcombank", "techcombank", "zalo", "telegram", "twitter", "instagram"
]

def get_entropy(text):
    """Tính toán độ hỗn loạn của chuỗi (Shannon Entropy)."""
    if not text:
        return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def extract_basic_features(url):
    """
    Trích xuất 11 đặc trưng số học cho XGBoost.
    LƯU Ý: Thứ tự trả về trong list này PHẢI khớp với lúc Train Model.
    """
    url = str(url).lower().strip()
    ext = tldextract.extract(url)
    
    # 1. Độ dài URL
    url_len = len(url)
    # 2. Số dấu chấm
    dots = url.count('.')
    # 3. Số dấu gạch ngang
    hyphens = url.count('-')
    # 4. Có HTTPS hay không
    is_https = 1 if url.startswith('https') else 0
    # 5. Tỷ lệ chữ số
    digit_ratio = sum(c.isdigit() for c in url) / url_len if url_len > 0 else 0
    # 6. TLD rủi ro cao
    bad_tlds = ['icu', 'top', 'xyz', 'bid', 'gq', 'tk', 'ml', 'cf', 'ga', 'club', 'lol', 'click']
    is_bad_tld = 1 if ext.suffix in bad_tlds else 0
    # 7. Độ dài subdomain
    sub_len = len(ext.subdomain)
    # 8. Subdomain chỉ chứa số/gạch ngang
    is_numeric_sub = 1 if re.match(r'^[0-9\-]+$', ext.subdomain) and len(ext.subdomain) > 0 else 0
    # 9. Entropy của domain chính
    dom_entropy = get_entropy(ext.domain)
    # 10. Entropy của subdomain
    sub_entropy = get_entropy(ext.subdomain)
    # 11. Chứa từ khóa nhạy cảm
    keywords = ['login', 'verify', 'update', 'secure', 'bank', 'id', 'account', 'signin', 'wp-admin']
    has_key = 1 if any(k in url for k in keywords) else 0

    # TRẢ VỀ DƯỚI DẠNG LIST ĐỂ CỐ ĐỊNH THỨ TỰ CỘT CHO XGBOOST
    return [
        url_len,       # col 0
        dots,          # col 1
        hyphens,       # col 2
        is_https,      # col 3
        digit_ratio,   # col 4
        is_bad_tld,    # col 5
        sub_len,       # col 6
        is_numeric_sub,# col 7
        dom_entropy,   # col 8
        sub_entropy,   # col 9
        has_key        # col 10
    ]

def get_advanced_insights(url):
    """Truy vấn mạng thực tế (WHOIS, DNS) để hiển thị báo cáo Web."""
    url = str(url).lower().strip()
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    
    insights = {
        "domain_age_days": "N/A",
        "is_new_domain": False,
        "dns_status": "Invalid",
        "impersonation_risk": "Low",
        "is_shortened": False
    }

    # 1. Kiểm tra rút gọn link
    shorteners = ['bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'is.gd']
    if any(s in url for s in shorteners):
        insights['is_shortened'] = True

    # 2. Truy vấn WHOIS
    try:
        # Timeout 5s để tránh treo server nếu API WHOIS chậm
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date and isinstance(creation_date, datetime):
            age = (datetime.now() - creation_date).days
            insights['domain_age_days'] = age
            # Domain < 6 tháng được coi là mới/nguy hiểm
            if age < 180:
                insights['is_new_domain'] = True
    except:
        # Nếu không lấy được WHOIS, thường là domain rác/mới đăng ký chưa cập nhật
        insights['is_new_domain'] = True

    # 3. Kiểm tra DNS
    try:
        socket.gethostbyname(domain)
        insights['dns_status'] = "Valid"
    except:
        insights['dns_status'] = "No DNS record"

    # 4. Độ tương đồng thương hiệu (Levenshtein)
    min_dist = 999
    matched_brand = ""
    for brand in TOP_BRANDS:
        dist = Levenshtein.distance(ext.domain, brand)
        if dist < min_dist:
            min_dist = dist
            matched_brand = brand
            
    if 0 < min_dist <= 2:
        insights['impersonation_risk'] = f"High (Similar to {matched_brand.capitalize()})"
    
    return insights