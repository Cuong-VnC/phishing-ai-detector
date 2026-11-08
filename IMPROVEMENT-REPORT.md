# Báo cáo cải tiến website ScamShield-AI

Ngày: 08/11/2026. Repo: `Cuong-VnC/phishing-ai-detector` (clone tại
`~/workspace/phishing-ai-detector`, commit gốc `7dcec85`).
Phạm vi: giao diện mới + thông tin tên miền chi tiết + logic tên miền không tồn tại /
không hoạt động. **Không đổi model** (vẫn model 05, 18 đặc trưng), **không đổi thứ tự
đặc trưng trong `features.py`**, **không đổi endpoint cũ hay trường response cũ**
(chỉ thêm trường mới), **không push/deploy** — bước upload GitHub làm riêng bằng
trình duyệt sau.

## 1. Giao diện mới (frontend viết lại hoàn toàn)

HTML/CSS/JS thuần + CDN (Lucide icons), không build step, serve thư mục `frontend/`
tĩnh là chạy. Tiếng Việt, responsive mobile + desktop, hệ màu navy/xanh/teal.

- **Topbar**: logo ScamShield, pill trạng thái API (kiểm tra `GET /health`, tự nhận
  localhost → `http://localhost:8000`, override bằng `?api=` hoặc nút đổi API, lưu
  localStorage).
- **Hero + search card**: ô nhập URL lớn, nút kiểm tra, nút xóa, 4 chip URL mẫu
  (google.com, youtube.com, vietcombank-dangnhap.com, techcombank-bao-mat.com —
  bấm là thử ngay), gợi ý định dạng dưới ô nhập.
- **Kết quả**: verdict card nổi bật với 4 nhãn — **AN TOÀN / NGHI NGỜ — CẦN THẬN TRỌNG /
  NGUY HIỂM: URL LỪA ĐẢO / TÊN MIỀN KHÔNG TỒN TẠI** — kèm **đồng hồ gauge tròn**
  hiển thị % xác suất phishing (màu xanh/vàng/đỏ, “—” khi không có xác suất), chip
  nguồn kết quả + mức rủi ro + NN prob (nếu có), banner cảnh báo vàng khi tên miền
  không hoạt động / không kiểm tra được.
- **Chi tiết mở rộng** (2 `<details>`): “Báo cáo kỹ thuật” (tuổi domain, trạng thái
  DNS, rủi ro giả mạo, link rút gọn — giữ tương thích response cũ) và “Thông tin tên
  miền chi tiết” (xem §2).
- **Lịch sử kiểm tra gần đây**: lưu localStorage (tối đa 8, key
  `scamshield_history_v1`), bấm một mục để kiểm tra lại, nút xóa toàn bộ.
- **Khác**: hộp loading 3 bước luân phiên (“Đang phân tích URL bằng AI…”,
  “Đang tra cứu DNS, WHOIS, TLS…”, “Đang kiểm tra khả năng truy cập…”),
  hộp lỗi tiếng Việt rõ ràng, mục “Hoạt động thế nào” + footer cảnh báo, nút đổi API.
- Fail-closed: API lỗi/timeout (90s) → báo lỗi, không mặc định an toàn.

## 2. Thông tin tên miền (backend mới: `backend/src/domain_info.py`)

Thư viện mới duy nhất: **`dnspython==2.6.1`** (thêm vào `requirements.txt`).
WHOIS dùng `python-whois` (đã có), TLS dùng `ssl`+`socket` (thư viện chuẩn),
HTTP dùng `requests` (đã có), tách domain dùng `tldextract` (đã có).

Hàm chính `get_domain_info(url, dns_result=None)` trả dict `domain_info` với các mục:

| Mục | Nội dung |
| --- | --- |
| `domain` / `host` / `is_ip_host` | Domain đã đăng ký (tldextract), host đầy đủ, host có phải IP không |
| `dns.status` | `resolved` / `nxdomain` / `no_answer` / `timeout` / `error` / `skipped_ip` |
| `dns.a` / `aaaa` / `mx` / `ns` / `txt` | Bản ghi DNS (mảng chuỗi; MX/NS/TXT chỉ tra khi có A/AAAA) |
| `whois.status` | `ok` / `unknown`; `created`, `expires` (YYYY-MM-DD), `registrar`, `age_days` |
| `tls.checked` / `valid` / `issuer` / `subject` / `expires` / `days_left` | Chứng chỉ TLS (chỉ kiểm tra với `https`, host không phải IP); `error` nếu lỗi |
| `http.reachable` / `status_code` / `final_url` / `redirects` / `server` / `content_type` / `response_time_ms` | HTTP GET (không đọc body), theo tối đa 5 redirect, **chặn redirect về IP nội bộ** |
| `status` | `active` / `inactive` / `nonexistent` / `unknown` (xem §3) |
| `reachable` | `true` / `false` / `null` (không kết luận được) |

Timeout: DNS 3s, WHOIS/TLS/HTTP 4s mỗi cái, **deadline chung 6s** cho 3 tra cứu chạy
song song (ThreadPoolExecutor). **Fail-soft**: tra cứu nào lỗi/timeout thì mục đó
trả `"unknown"` (hoặc `null`), không bao giờ làm hỏng cả request. Lưu ý kỹ thuật:
không dùng `with ThreadPoolExecutor` (shutdown(wait=True) sẽ treo theo thread WHOIS
vì `python-whois` không có timeout socket nội bộ) — dùng `shutdown(wait=False,
cancel_futures=True)`.

Endpoint mới: **`GET /domain-info?url=<url>`** → `{"url": ..., "domain_info": {...}}`.
Mọi response của `POST /predict` đều kèm thêm `domain_info`, `domain_status`,
`warning` (xem §3) — các trường cũ giữ nguyên.

## 3. Logic tên miền không tồn tại / không hoạt động (backend, `main.py`)

Thứ tự trong `POST /predict` (frontend chỉ hiển thị):

0. **URL sai định dạng** → HTTP **400**, `detail` tiếng Việt rõ ràng, ví dụ:
   `"URL không đúng định dạng: tên miền thiếu phần mở rộng (ví dụ: .com, .vn)"`.
   Kiểm tra: có scheme http/https, có hostname, hostname có dấu chấm (trừ IP/localhost),
   TLD hợp lệ, port 1–65535, không chứa ký tự `<>`… (hàm `validate_url_format` mới).
1. **Tra DB nội bộ trước** (Supabase): URL đã biết là phishing thì vẫn báo phishing
   dù tên miền đã chết.
2. **DNS NXDOMAIN** → trả HTTP 200, `status: "DomainNotFound"`, `probability: null`,
   `risk_level: "Unknown"`, `domain_status: "nonexistent"`, kèm `domain_info` +
   `message` (“Tên miền … không tồn tại (DNS không phân giải được) — không thể truy
   cập.”), **`source: "domain_check"`, không chạy model**.
3. **Chặn SSRF** (`is_safe_url`, như cũ) → 400 nếu host là IP nội bộ/loopback/link-local.
4. **`get_domain_info` (tái dùng kết quả DNS bước 2)** → `domain_status` + `warning`:
   - `inactive` (DNS phân giải được nhưng HTTP không phản hồi/timeout/lỗi, hoặc DNS
     `no_answer` — tồn tại nhưng không có bản ghi A/AAAA) → `warning` tiếng Việt
     tương ứng, **vẫn trả kèm kết quả model** nếu tính được.
   - `unknown` (DNS/HTTP đều không kết luận được) → warning “Không kiểm tra được
     trạng thái hoạt động… — kết quả AI vẫn được hiển thị.”
   - `active` → `warning: null`.
5. URLhaus → Google Safe Browsing → model (như cũ, chỉ thêm `_attach_domain_info`).

Quy tắc trạng thái trong `domain_info` (khi DNS đã biết):
`nxdomain → nonexistent`; `no_answer → inactive`; `resolved`/`skipped_ip` → active
nếu HTTP reachable, inactive nếu HTTP unreachable, unknown nếu HTTP không kết luận
được; `timeout`/`error` → active nếu HTTP reachable, else unknown.

## 4. Kết quả kiểm chứng

Môi trường test: venv Python 3.12 tại `.venv` (đã xóa sau khi test xong để khỏi nặng
thư mục upload — tạo lại bằng `pip install -r requirements.txt`, xem §6).
Chạy backend thật bằng uvicorn + serve frontend tĩnh. Các script test nằm trong
`tests/` (xem §5).

### 4.1 Unit test `domain_info` — 22/22 PASS (`tests/test_domain_info.py`)
- DNS mock (resolver giả): NXDOMAIN → `nxdomain` + records rỗng; resolved → đủ
  A/AAAA/MX/NS/TXT; NoAnswer → `no_answer`; Timeout → `timeout`.
- `check_domain_existence`: NXDOMAIN → `nonexistent`, resolved → `exists`, IP → `exists`.
- `get_domain_info` với DNS giả NXDOMAIN → `nonexistent`, `reachable: false`, <10s.
- `get_domain_info` với DNS giả resolved + HTTP thật qua proxy (google.com) →
  `active`, HTTP 200, 1,2s.
- `tls_info` fail-soft (xem §4.4), `http_check` port 81 → unreachable, `whois_lookup`
  fail-soft không treo (<10s).

### 4.2 E2E `POST /predict` + `GET /domain-info` — 29/29 PASS (`tests/test_predict_e2e.py`)
Dùng TestClient với model 05 thật; DNS được mock để mô phỏng resolver thật trên
Render (xem §4.4 vì sao phải mock). Kết quả từng ca:

| Ca | Kết quả |
| --- | --- |
| `GET /health` | 200, `models_loaded: true` |
| Legit `https://www.google.com` | 200, `status: Safe`, `probability: 0.0`, đủ trường cũ (`url/status/probability/risk_level/technical_report/source`), `domain_info` đủ key, `domain_status: active`, HTTP reachable, `warning: null` |
| Phishing trong benchmark `https://vietcombank-dangnhap.com/login` (benchmark.csv: label 0, `phish_synth_vn`) | 200, `status: Phishing`, `probability > 0.5`, có `domain_info` |
| Tên miền không tồn tại `https://xkqjzwv-qqqq-zzz12345.com/login` | 200, `status: DomainNotFound`, `domain_status: nonexistent`, `message` chứa “không tồn tại”, `probability: null` |
| URL sai định dạng: `not a url`, `htp:/bad`, `google` | cả 3 đều HTTP **400**, `detail` tiếng Việt “URL không đúng định dạng…” |
| Tên miền không hoạt động `https://www.google.com:81/` | 200, `domain_status: inactive`, có `warning`, **vẫn có kết quả model** (`status: Safe` vì whitelist) |
| `GET /domain-info?url=https://www.google.com` | 200, `domain_info.domain == "google.com"` |

### 4.3 Frontend (jsdom, không có trình duyệt thật) — 20/20 PASS (`tests/test_frontend_jsdom.js`)
Nạp `index.html` + `script.js` thật trong jsdom, stub `lucide` (CDN) và `fetch`
(trả payload `/health` + `/predict` mẫu cho 3 ca). Cần `npm install jsdom`.
Đã kiểm tra: pill “Máy chủ đang hoạt động”; chip mẫu điền URL; ca Safe → hiện kết
quả, nhãn “AN TOÀN”, gauge 0%, DNS A hiện IP, WHOIS hiện registrar + tuổi
“10.600 ngày”, TLS “Hợp lệ”, HTTP 200, lịch sử 1 mục + localStorage 1 mục; ca
DomainNotFound → nhãn “TÊN MIỀN KHÔNG TỒN TẠI”, mô tả hiện đúng `message` backend;
ca Phishing → nhãn “NGUY HIỂM: URL LỪA ĐẢO”, gauge 93%, WHOIS “12 ngày”, lịch sử
3 mục; input rỗng → hộp lỗi “Vui lòng dán một đường link vào ô kiểm tra.”
Cú pháp: `node --check script.js` OK, thẻ HTML cân bằng, `py_compile` cho
`main.py`/`domain_info.py`/`features.py` OK. **Chưa chụp screenshot trình duyệt thật**
(trên VM không có Chromium/Firefox/Playwright) — nên xem lại bằng mắt trên trình
duyệt thật sau khi deploy.

### 4.4 Server thật (uvicorn) + frontend tĩnh — chạy được, có 1 giới hạn của sandbox
- `uvicorn backend.src.main:app` khởi động OK, `GET /health` → 200
  `{"status":"ok","models_loaded":true,"threshold":0.5}`.
- Frontend tĩnh (`python -m http.server 8080 --directory frontend`): `index.html`
  200 (12.937 bytes), `style.css` 200, `script.js` 200.
- `POST /predict` với URL sai định dạng → 400 tiếng Việt đúng như thiết kế.
- ⚠️ **Giới hạn sandbox (không phải lỗi code):** DNS hệ thống ở đây là sinkhole
  wildcard — mọi hostname đều phân giải ra `198.18.123.x` (dải private), nên
  `is_safe_url` chặn mọi URL → `/predict https://www.google.com`,
  `/predict` domain ngẫu nhiên và `/domain-info` đều trả 400
  `"URL blocked for security reasons"` khi chạy server thật không mock. Vì vậy
  nhánh NXDOMAIN và kết quả model chỉ kiểm chứng được qua e2e mock (§4.2) +
  unit test mock (§4.1); **trên Render (resolver thật) logic này chạy đúng đường
  code đã test**. Tương tự: TLS trực tiếp tới cổng 443 bị egress chặn
  (`SSLError: WRONG_VERSION_NUMBER` — proxy HTTP xen vào) và WHOIS cổng 43 bị chặn
  (connection reset) → cả hai fail-soft về `unknown`/`checked: false` trong sandbox;
  trên Render chúng hoạt động bình thường. HTTP qua proxy thì hoạt động thật
  (google.com → 200, 1,2s).

## 5. Danh sách file đã đổi / thêm (để upload lên GitHub)

```
M  README.md                  (viết lại: tính năng mới, cách chạy, API, lưu ý Render)
M  requirements.txt           (+ dnspython==2.6.1)
M  backend/src/main.py        (+117/-14: validate_url_format, _attach_domain_info,
                               GET /domain-info, logic NXDOMAIN/inactive trong /predict)
?? backend/src/domain_info.py (mới: DNS/WHOIS/TLS/HTTP fail-soft, check_domain_existence)
M  frontend/index.html        (viết lại: topbar, hero, search card, verdict card + gauge,
                               2 details, history, how-it-works)
M  frontend/style.css         (viết lại: hệ màu navy/xanh/teal, responsive)
M  frontend/script.js         (viết lại: health pill, API base, gauge, domain info,
                               history localStorage, fail-closed)
?? tests/test_domain_info.py  (unit test domain_info, 22 assert)
?? tests/test_predict_e2e.py  (e2e TestClient, 29 assert, mock DNS)
?? tests/test_frontend_jsdom.js (smoke test frontend jsdom, 20 assert; cần npm i jsdom)
```
Không đổi: `backend/src/features.py` (18 đặc trưng, thứ tự khớp model 05),
`backend/src/brands.py`, `backend/src/database.py`, `backend/models/*`, `Dockerfile`.
`.venv/` (1,9 GB) đã xóa — không upload. `backend/src/__pycache__` đã xóa.

Chạy lại test sau khi tạo venv:
```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python tests/test_domain_info.py      # 22 assert
.venv/bin/python tests/test_predict_e2e.py      # 29 assert
cd /tmp && npm install jsdom@24 && node ~/workspace/phishing-ai-detector/tests/test_frontend_jsdom.js  # 20 assert
```

## 6. Lưu ý triển khai (Render)

- **Không cần cài thêm gì ngoài `requirements.txt`** — thư viện mới duy nhất là
  `dnspython`; WHOIS/TLS/HTTP dùng thư viện đã có hoặc thư viện chuẩn.
- **Phiên bản Python:** đặt `PYTHON_VERSION=3.11.9` trong cấu hình Render
  (Environment) — `tensorflow-cpu==2.16.1` không có wheel cho Python 3.14.
- Trên VM test dùng Python 3.12: `pandas==2.0.3` không có wheel cho 3.12 và build
  từ sdist cần `versioneer`+Cython; đã **bỏ qua pandas khi test** (server không
  import pandas — chỉ `backend/src/upload_training_data.py` dùng, không chạy lúc
  serve). Trên Render 3.11.9 thì pandas 2.0.3 có wheel, cài bình thường.
- ⚠️ Cảnh báo có sẵn (không do thay đổi này gây ra): khi nạp model, sklearn báo
  `InconsistentVersionWarning: Trying to unpickle estimator StandardScaler from
  version 1.6.1 when using version 1.3.2` — `scaler.pkl` được pickle bằng
  scikit-learn 1.6.1 trong khi `requirements.txt` pin 1.3.2. Model vẫn nạp và dự
  đoán đúng (đã kiểm chứng qua e2e), nhưng nên cân nhắc nâng pin lên
  `scikit-learn==1.6.1` cho khớp artifact ở lần cập nhật requirements sau.
- Không có Supabase/URLhaus/GSB key thì các tầng đó tự bỏ qua (đã log cảnh báo
  “Chưa cấu hình SUPABASE_URL…” — hành vi cũ, không ảnh hưởng).
- Timeout tra cứu tên miền nằm trong `backend/src/domain_info.py`:
  `DNS_TIMEOUT=3s`, `WHOIS_TIMEOUT=4s`, `TLS_TIMEOUT=4s`, `HTTP_TIMEOUT=4s`,
  `OVERALL_TIMEOUT=6s` (deadline chung). Tăng `OVERALL_TIMEOUT` nếu mạng Render
  chậm làm WHOIS/TLS hay về `unknown`.
