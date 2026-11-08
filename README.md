# ScamShield-AI — Kiểm tra link lừa đảo bằng học máy

ScamShield-AI nhận một URL, phân tích bằng mô hình học máy (mạng nơ-ron CNN+BiLSTM
xếp chồng XGBoost) kết hợp tra cứu tên miền thực tế (DNS, WHOIS, TLS, HTTP) và trả về
kết luận rõ ràng: **An toàn / Nghi ngờ / Nguy hiểm / Tên miền không tồn tại /
Tên miền không hoạt động**.

> Dự án học tập (nhóm ICTLab, USTH). Kết quả chỉ mang tính tham khảo — luôn cẩn trọng
> trước khi nhập mật khẩu, mã OTP hay chuyển tiền trên bất kỳ trang web nào.

## Tính năng

### Kiểm tra bằng AI (`POST /predict`)
- 18 đặc trưng thủ công của URL (độ dài, ký tự đáng ngờ, subdomain, từ khóa nhạy cảm…)
  + chuỗi ký tự đưa qua mạng CNN+BiLSTM, rồi xếp chồng XGBoost.
- Danh sách tin cậy (whitelist) các domain lớn; tra cứu cơ sở dữ liệu nội bộ (Supabase),
  URLhaus và Google Safe Browsing khi có API key.
- Ngưỡng mặc định 0.5 (xem `backend/models/meta.json`).

### Thông tin tên miền chi tiết (mới)
Mọi response của `/predict` đều kèm thêm key `domain_info` (và `domain_status`,
`warning`) — không đổi các trường cũ:
- **DNS** (dnspython): bản ghi A / AAAA / MX / NS / TXT, trạng thái phân giải.
- **WHOIS** (python-whois): ngày đăng ký / hết hạn, nhà đăng ký, tuổi domain (ngày).
- **TLS** (ssl + socket): chứng chỉ có hợp lệ không, tổ chức cấp, ngày hết hạn, số ngày còn lại.
- **HTTP** (requests): mã trạng thái, URL cuối cùng, chuỗi chuyển hướng (tối đa 5, chặn
  redirect về IP nội bộ), header `Server`, thời gian phản hồi.
- Có endpoint riêng: `GET /domain-info?url=<url>`.

### Logic tên miền không tồn tại / không hoạt động (mới, nằm ở backend)
1. **URL sai định dạng** (thiếu scheme, thiếu hostname, tên miền thiếu phần mở rộng,
   cổng sai…) → HTTP 400 với lý do rõ ràng bằng tiếng Việt.
2. **DNS NXDOMAIN** → kết luận `DomainNotFound` (“Tên miền không tồn tại”), **không chạy
   model**, trả kèm `domain_info` (WHOIS có thể cho biết domain đã đăng ký nhưng chưa
   có bản ghi DNS). Ngoại lệ: URL đã có trong cơ sở dữ liệu đen/trắng nội bộ thì vẫn
   trả kết quả theo cơ sở dữ liệu.
3. **DNS phân giải được nhưng HTTP(S) không phản hồi** (timeout / lỗi kết nối / quá
   nhiều redirect) → `domain_status: "inactive"` + `warning`, **vẫn trả kết quả model**
   nếu tính được.
4. DNS timeout / lỗi tra cứu → `domain_status: "unknown"`, vẫn chạy model bình thường.

Mọi tra cứu đều có timeout ngắn (DNS 3s, WHOIS/TLS/HTTP 4s, tổng 6s) và **fail-soft**:
tra cứu nào lỗi thì mục đó trả `"unknown"`, không làm hỏng cả request.

### Giao diện web (mới)
- Hiện đại, responsive (mobile + desktop), tiếng Việt.
- Đồng hồ đo mức độ rủi ro (gauge), nhãn kết luận nổi bật, banner cảnh báo khi tên miền
  không hoạt động.
- Chi tiết mở rộng: báo cáo kỹ thuật + toàn bộ thông tin tên miền (DNS/WHOIS/TLS/HTTP).
- Lịch sử kiểm tra gần đây (chỉ lưu trên trình duyệt của bạn — localStorage), URL mẫu
  bấm là thử ngay, tự nhận biết môi trường local (`http://localhost:8000`) hay Render.

## Chạy local

```bash
# 1. Cài đặt (Python 3.11+ khuyến nghị; xem mục Lưu ý triển khai)
python -m venv .venv
.venv/bin/pip install -r requirements.txt

# 2. Chạy backend (cổng mặc định 8000)
.venv/bin/uvicorn backend.src.main:app --host 0.0.0.0 --port 8000
# hoặc: cd backend/src && python main.py

# 3. Mở frontend (thư mục tĩnh, không cần build)
python -m http.server 8080 --directory frontend
# Mở http://localhost:8080 — frontend tự trỏ API về http://localhost:8000
```

Kiểm tra nhanh:

```bash
curl http://localhost:8000/health
curl -X POST http://localhost:8000/predict -H 'Content-Type: application/json' \
  -d '{"url": "https://www.google.com"}'
curl "http://localhost:8000/domain-info?url=https://www.google.com"
```

## Cấu hình (biến môi trường)

| Biến | Mô tả |
| --- | --- |
| `PORT` | Cổng backend (mặc định `8000`; Render tự đặt). |
| `URLHAUS_API_KEY` | (Tùy chọn) Khóa URLhaus — không có thì bỏ qua tầng này. |
| `GOOGLE_SAFE_BROWSING_API_KEY` | (Tùy chọn) Khóa Google Safe Browsing — không có thì bỏ qua. |
| `EXPO_PUBLIC_SUPABASE_URL` / `EXPO_PUBLIC_SUPABASE_KEY` | (Tùy chọn) Supabase cho tra cứu DB nội bộ — không có thì bỏ qua. |

Timeout tra cứu tên miền (trong `backend/src/domain_info.py`):
`DNS_TIMEOUT = 3s`, `WHOIS_TIMEOUT = 4s`, `TLS_TIMEOUT = 4s`,
`HTTP_TIMEOUT = 4s`, `OVERALL_TIMEOUT = 6s` (deadline chung cho WHOIS+TLS+HTTP chạy song song).

## API

### `POST /predict`
Request: `{"url": "https://..."}`.
Response (giữ nguyên các trường cũ, thêm 3 trường mới):

```json
{
  "url": "https://www.google.com",
  "status": "Safe",
  "probability": 0.0,
  "risk_level": "Low",
  "technical_report": {"domain_age": "N/A", "dns_status": "Unknown",
                       "impersonation_risk": "Low", "is_shortened": false},
  "source": "whitelist",
  "domain_info": {
    "domain": "google.com", "host": "www.google.com", "is_ip_host": false,
    "dns": {"status": "resolved", "a": ["142.250.x.x"], "aaaa": [], "mx": [], "ns": [], "txt": []},
    "whois": {"status": "ok", "created": "1997-09-15", "expires": "2028-09-14",
              "registrar": "MarkMonitor Inc.", "age_days": 10200},
    "tls": {"checked": true, "valid": true, "issuer": "Google Trust Services",
            "subject": "Google Trust Services", "expires": "2026-11-01", "days_left": 90},
    "http": {"reachable": true, "status_code": 200, "final_url": "https://www.google.com/",
             "redirects": [], "server": "gws", "response_time_ms": 180},
    "status": "active", "reachable": true
  },
  "domain_status": "active",
  "warning": null
}
```

Các giá trị `status` có thể gặp: `Safe`, `Phishing`, `Phishing/Malicious`,
`DomainNotFound` (tên miền không tồn tại), `Error`. `domain_status`: `active` /
`inactive` / `nonexistent` / `unknown`.

### `GET /health`
`{"status": "ok"|"degraded", "models_loaded": true, "threshold": 0.5}`

### `GET /domain-info?url=<url>`
`{"url": "...", "domain_info": {...}}` — cùng cấu trúc `domain_info` như trên.

## Cấu trúc repo

```
├── frontend/            # Giao diện tĩnh (index.html, style.css, script.js)
├── backend/
│   ├── models/          # 5 artifacts model 05: phishing_nn.keras, xgb_model.json,
│   │                    # tokenizer.json, scaler.pkl, meta.json
│   └── src/
│       ├── main.py      # FastAPI: /predict, /health, /domain-info
│       ├── features.py  # 18 đặc trưng (thứ tự PHẢI khớp model — không đổi)
│       ├── domain_info.py  # NEW: DNS / WHOIS / TLS / HTTP (fail-soft)
│       ├── brands.py    # (trống)
│       └── database.py  # Tra cứu Supabase (tùy chọn)
├── requirements.txt
└── IMPROVEMENT-REPORT.md  # Báo cáo cải tiến (giao diện + domain_info + logic)
```

## Lưu ý triển khai (Render)

- **Không cần cài thêm gì ngoài `requirements.txt`** — thư viện mới duy nhất là
  `dnspython` (WHOIS/TLS/HTTP dùng thư viện đã có hoặc thư viện chuẩn).
- **Phiên bản Python:** `tensorflow-cpu==2.16.1` không có wheel cho Python 3.14 —
  đặt `PYTHON_VERSION=3.11.9` trong cấu hình Render (Environment) để build được.
- DNS/WHOIS/TLS/HTTP trên Render dùng mạng thật nên cho kết quả đúng; trong môi
  trường sandbox (DNS sinkhole) chúng sẽ trả về kết quả giả — xem
  `IMPROVEMENT-REPORT.md` mục “Hạn chế khi test trong sandbox”.
- Model đang serve là **model 05** (18 đặc trưng). Model 06/07 (37/165 đặc trưng)
  chưa thay thế — khi đổi model, cập nhật `backend/models/` + `features.py` theo
  đúng thứ tự đặc trưng trong `meta.json` mới.
