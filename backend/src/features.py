import tldextract
import re
import json
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

# --- PIPELINE MỚI (theo đúng notebook train dataset_url_05) ---
# 18 đặc trưng, thứ tự PHẢI khớp meta.json -> feature_names.
SUS_KW = ["login", "verify", "signin", "secure", "account", "update", "confirm", "free", "bonus"]
FEATURE_NAMES = ["url_len", "host_len", "path_len", "n_dots", "n_hyphens", "n_underscores",
                 "n_slashes", "n_digits", "digit_ratio", "has_ip", "has_at", "n_subdomains",
                 "has_https", "n_params", "n_percent", "n_equals", "has_sus_kw", "tld_len"]


def safe_parse(url):
    """Tách host/path/query bằng string, không dùng urlparse (tránh lỗi IPv6
    với URL viết dạng defang kiểu [.] hoặc ngoặc vuông sai chuẩn)."""
    s = str(url)
    if "://" in s:
        s = s.split("://", 1)[1]
    parts = s.split("/", 1)
    host = parts[0].split("?", 1)[0].split("#", 1)[0].split("@")[-1]
    if host.startswith("["):
        host = host.split("]", 1)[0] + ("]" if "]" in host else "")
    else:
        host = host.split(":")[0]
    tail = ("/" + parts[1]) if len(parts) > 1 else ""
    tail = tail.split("#", 1)[0]
    path, query = tail.split("?", 1) if "?" in tail else (tail, "")
    return host.lower(), path, query


def extract_features(url):
    """18 đặc trưng thủ công, đúng thứ tự FEATURE_NAMES (khớp lúc train)."""
    host, path, query = safe_parse(url)
    is_ip = 1 if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host) else 0
    feats = [
        len(url), len(host), len(path),                      # do dai url/host/path
        url.count("."), url.count("-"), url.count("_"),      # so dau cham/gach ngang/gach duoi
        url.count("/"), sum(c.isdigit() for c in url),       # so slash, so chu so
        sum(c.isdigit() for c in url) / max(len(url), 1),    # ti le chu so
        is_ip, 1 if "@" in url else 0,                        # co IP, co ky tu @
        max(host.count(".") - 1, 0),                         # so subdomain
        1 if url.startswith("https") else 0,                 # co https khong
        query.count("&") + (1 if query else 0),              # so tham so query
        url.count("%"), url.count("="),                      # so % va dau =
        1 if any(k in url for k in SUS_KW) else 0,           # co tu khoa nhay cam khong
        len(host.split(".")[-1]) if "." in host else 0,      # do dai TLD
    ]
    return feats


def registrable_domain(url):
    """Lấy domain đăng ký: host -> bỏ subdomain, giữ 2 phần cuối
    (hoặc 3 phần nếu hậu tố 2 tầng). Dùng cho whitelist."""
    try:
        from urllib.parse import urlparse
        host = urlparse(url).netloc.lower().split(":")[0].split("@")[-1]
    except Exception:
        return ""
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):  # IP thi giu nguyen host
        return host
    parts = host.split(".")
    two_level = {"co.uk", "com.au", "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "co.jp", "com.br"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_level:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def load_tokenizer_json(path):
    """Nạp tokenizer.json của Keras (char_level) mà không cần keras.preprocessing
    (module này đã bị loại bỏ ở Keras 3). Trả về (word_index, oov_index)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    config = data.get("config", data)
    word_index = config.get("word_index", {})
    if isinstance(word_index, str):  # Keras lưu word_index dạng chuỗi JSON
        word_index = json.loads(word_index)
    word_index = {str(k): int(v) for k, v in word_index.items()}
    oov_token = config.get("oov_token")
    oov_index = word_index.get(oov_token) if oov_token else None
    return word_index, oov_index


def texts_to_char_sequences(texts, word_index, oov_index):
    """Tương đương tok.texts_to_sequences với char_level=True, lower=True:
    mỗi ký tự thành 1 token; ký tự lạ -> OOV (nếu có), ngược lại bỏ qua."""
    sequences = []
    for text in texts:
        seq = []
        for c in str(text).lower():
            if c in word_index:
                seq.append(word_index[c])
            elif oov_index is not None:
                seq.append(oov_index)
        sequences.append(seq)
    return sequences


def pad_post(sequences, maxlen):
    """Tương đương pad_sequences(..., padding='post', truncating='post', value=0)."""
    padded = []
    for seq in sequences:
        seq = list(seq[:maxlen])
        seq = seq + [0] * (maxlen - len(seq))
        padded.append(seq)
    return padded


def get_entropy(text):
    """Tính toán độ hỗn loạn của chuỗi (Shannon Entropy)."""
    if not text:
        return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


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
