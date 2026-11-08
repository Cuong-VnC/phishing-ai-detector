# Cập nhật website ScamShield — Bỏ Báo cáo kỹ thuật + nút Đổi máy chủ API, mở rộng Thông tin tên miền

Ngày: 2026-11-08 · Repo: `Cuong-VnC/phishing-ai-detector` · **Chưa push, chưa deploy** (chỉ sửa code + test tại chỗ, chờ bước upload riêng).

## 1. Đã bỏ khỏi giao diện

| Mục | Đã xóa |
|---|---|
| **Báo cáo kỹ thuật** | Toàn bộ khối `<details id="techDetails">` trong `frontend/index.html` (gồm 3 dòng Tuổi tên miền / DNS / Giả mạo thương hiệu + URL rút gọn), khối điền dữ liệu `resAge`/`resDNS`/`resImpersonation`/`resShortened` trong `displayResult()` của `frontend/script.js`. CSS liên quan không còn dùng (không có rule riêng cho nó). |
| **Nút "Đổi máy chủ API"** | Nút `#apiSwitchBtn` ở footer trong `index.html`, toàn bộ handler `apiSwitchBtn` trong `script.js`, rule `.btn-small` trong `style.css` (chỉ dùng cho nút này). |

**Giữ nguyên, không đổi:**
- Trường `technical_report` vẫn có trong response backend (`backend/src/main.py`) — chỉ bỏ hiển thị ở frontend, API giữ tương thích.
- Logic URL API mặc định giữ nguyên: `resolveApiBase()` — `localhost`/`127.0.0.1` → `http://localhost:8000`, còn lại dùng `https://phishing-ai-api.onrender.com`; hỗ trợ `?api=` + localStorage như trước. Site thật chạy với backend Render nên vẫn trỏ đúng Render sau khi bỏ nút (đã kiểm chứng bằng test jsdom: localhost vẫn nhận đúng API mặc định).

Kiểm chứng: `grep "Báo cáo kỹ thuật|Đổi máy chủ API|apiSwitchBtn|techDetails|resAge|resDNS|resImpersonation|resShortened" frontend/` = **0 kết quả** (kể cả comment). `grep gradient frontend/` = **0 kết quả** (hệ màu đặc từ UI fix 2 vẫn giữ).

## 2. Trường thông tin tên miền mới (backend `backend/src/domain_info.py`)

Chỉ dùng thư viện đã có: `requests`, `dnspython`, `ssl`/`socket`, `python-whois`. **Không thêm thư viện mới, không dùng API cần key.** Mọi tra cứu mới timeout ngắn (1–4s) và fail-soft như cũ (lỗi → `None`/`[]`/`False`, không chặn kết luận).

### DNS (`resolve_dns`, thêm 6 nhóm)
| Trường | Nguồn / cách lấy | Ghi chú |
|---|---|---|
| `cname` | Bản ghi CNAME của host | `[]` nếu không có |
| `soa` | Bản ghi SOA của registered domain → `{primary_ns, serial, raw}` | Helper `_parse_soa`; lấy ở domain gốc (ví dụ `google.com` thay vì `www.google.com`) |
| `ptr` | Reverse DNS của IP A đầu tiên (hoặc AAAA nếu không có A), tối đa 2 | `dns.reversename.from_address` |
| `spf` | Trích từ TXT: bản ghi bắt đầu `v=spf1` | `None` nếu không có |
| `dmarc` | TXT `_dmarc.<registered domain>` → `{record, policy}` | Helper `_parse_dmarc` (lấy `p=`); `None` nếu không có |
| `dnssec` | `{enabled, ds, dnskey}` — có bản ghi DS / DNSKEY không | Tra ở registered domain; `enabled = ds or dnskey` |

Tra cứu mở rộng dùng `lifetime=1,0s` (chỉ để hiển thị).

### WHOIS (`whois_lookup`, thêm 3 trường)
- `updated` — ngày cập nhật (định dạng ISO `YYYY-MM-DD`).
- `name_servers` — tối đa 5, lowercase, dedupe.
- `domain_status` — list trạng thái WHOIS (tối đa 5; ví dụ `clientTransferProhibited`). **Lưu ý:** key `status` cũ (trạng thái tra cứu `ok`/`unknown`) giữ nguyên, không đổi tên.

### TLS (`tls_info`, thêm 5 trường)
- `sans` — Subject Alternative Names, tối đa 10.
- `sig_alg` — thuật toán ký của chứng chỉ (ví dụ `sha256WithRSAEncryption`); đọc bằng `cryptography` nếu có, fallback giải DER tối giản bằng stdlib (`_sig_alg_from_der` + bảng `_SIG_ALG_OIDS`).
- `tls_version` — phiên bản TLS đã thỏa thuận (`ssock.version()`, ví dụ `TLSv1.3`).
- `cipher` + `cipher_bits` — cipher đã thỏa thuận (`ssock.cipher()`, ví dụ `TLS_AES_256_GCM_SHA384`, 256-bit); lấy trong khối `with` khi socket còn mở.

### HTTP (`http_check`, thêm 5 trường)
- `content_type` — header Content-Type.
- `content_length` — parse int từ header (có thể `None` nếu server dùng chunked, ví dụ google.com).
- `redirect_count` — số lần redirect (đặt trong `finally` để đếm đủ cả đường return sớm).
- `resolved_ip` — IP đã phân giải: IP host nếu host là IP; else A[0]; else phân giải A của host ở `final_url` (lifetime 2s).
- `ip_info` — geo/ASN/ISP của IP đó qua `http://ip-api.com/json/<ip>` (requests, timeout 4s, fields `status/country/regionName/city/isp/org/as/query`; fail-soft → `None`). **Đã kiểm chứng thật từ sandbox: google.com → `{country: United States, region: New York, city: New York, isp: Google LLC, asn: AS15169 Google LLC}`.**

## 3. Quy tắc hiển thị "Không tìm thấy" (frontend)

Hằng `NF = "Không tìm thấy"` trong `script.js`; `fillDomainInfo()` viết lại với bảng `DI_IDS` (**40 id** trong `#domainDetails`) + helper `setText`/`setList`:
- Mọi mục thiếu dữ liệu (`null`/rỗng/`unknown`) đều hiện **"Không tìm thấy"**, không để trống, không để dấu `—`.
- Ngoại lệ có ý nghĩa thật: redirects rỗng → "Không có chuyển hướng"; DNSSEC không có → "Không" (có → "Có"); HTTP không phản hồi → "Không (lỗi)".
- `fmtDate`/`fmtList` cũng trả NF khi thiếu; chip Nguồn/Mức rủi ro fallback sang NF.
- Áp dụng cho **toàn bộ** mục hiện có (DNS A/AAAA/MX/NS/TXT, WHOIS, TLS, HTTP) + các mục mới, kể cả khi `domain_info` là `null` hoặc từng nhóm con bị thiếu (đã kiểm chứng bằng 2 payload test: sparse và null).

## 4. Kết quả test (chạy 2026-11-08, VM này)

| Bộ test | Kết quả |
|---|---|
| `tests/test_frontend_jsdom.js` | **44 PASS, 0 FAIL** (gồm: không còn section Báo cáo kỹ thuật, không còn nút Đổi máy chủ API, không còn chuỗi cấm trong JS, `resolveApiBase` vẫn nhận localhost → API mặc định; ca Safe hiện đủ trường mới: SPF `v=spf1 -all`, DMARC `p=reject`, DNSSEC `Có`, SOA `ns1.google.com (serial 123456)`, WHOIS ngày cập nhật/nameservers, TLS version `TLSv1.3`, cipher `TLS_AES_256_GCM_SHA384 (256-bit)`, sig alg, content-type, `0 lần` redirect, IP đã phân giải, ip_info ISP/ASN; ca **sparse: 37/40 mục = "Không tìm thấy", không ô trống**; ca **nullinfo: 40/40 = "Không tìm thấy"**) |
| `tests/test_domain_info.py` | **47 PASS, 0 FAIL** (SOA/PTR/SPF/DMARC/DNSSEC thật qua FakeResolver; unit test `_parse_soa`, `_parse_dmarc`, `_sig_alg_from_der` bằng cert tự tạo, `_ip_geo` với requests giả; WHOIS giả kiểm tra `updated`/`name_servers`/`domain_status`; google.com thật: HTTP 200, `redirect_count 0`, `resolved_ip = A record`, `ip_info` thật từ ip-api.com, tổng < 15s) |
| `tests/test_predict_e2e.py` (TestClient, **model 05 thật**) | **37 PASS, 0 FAIL** (`/health` models_loaded `True`; google.com → Safe + `domain_status active` + đủ trường mới có giá trị thật; phishing benchmark → Phishing, probability 0,9999; tên miền không tồn tại → `DomainNotFound` + message rõ ràng; URL sai định dạng → 400 tiếng Việt; `google:81` → `inactive` + warning + vẫn có kết quả model; `GET /domain-info` → 200) |

`node --check frontend/script.js` OK; HTML cân bằng (parser: unclosed `[]`, errors `[]`); 40 id `di*` trong JS đều có trong HTML.

## 5. Lưu ý môi trường test (không ảnh hưởng Render)

- Venv test đặt ở `~/workspace/venv-scam-test` (ngoài repo, xóa sau khi test xong); `TMPDIR=~/workspace/.pip-tmp` (do `/tmp` đầy).
- Venv dùng **phiên bản test** vì bản pin trong `requirements.txt` không có wheel cho Python 3.12 của VM: `tensorflow-cpu==2.17.0` (thay 2.16.1), `scikit-learn==1.6.1` (thay 1.3.2), **`xgboost==3.0.2` (thay 2.0.2)** — bắt buộc vì xgboost 2.1.3 + sklearn 1.6.1 lỗi tương thích đã biết (`AttributeError: 'super' object has no attribute '__sklearn_tags__'` khi `load_model`; xgboost 3.0.2 nạp file `xgb_model.json` cũ bình thường). **`requirements.txt không đổi`** — Render chạy Python 3.11.9 (đã pin bằng `.python-version`) với đúng bản đã pin, không gặp lỗi này.
- Giới hạn sandbox đã biết (fail-soft, không phải lỗi code): TLS trực tiếp (443) bị chặn → `tls_info.checked=false` với `SSLError: WRONG_VERSION_NUMBER`; WHOIS port 43 bị chặn → `whois.status=unknown`; DNS hệ thống thỉnh thoảng trả `no_answer` (chạy lại thì phân giải bình thường). Trên Render/Vercel thật các tra cứu này hoạt động bình thường.
- Trong test e2e, fake DNS chỉ patch `main.resolve_dns`; `get_domain_info` tự gọi resolver thật bên trong — ca legit vẫn PASS vì DNS thật phân giải được google.com trong lần chạy này.

## 6. File đã đổi (để bước sau upload lên GitHub)

| File | Thay đổi |
|---|---|
| `backend/src/domain_info.py` | Thêm CNAME/SOA/PTR/SPF/DMARC/DNSSEC (DNS), `updated`/`name_servers`/`domain_status` (WHOIS), `sans`/`sig_alg`/`tls_version`/`cipher`/`cipher_bits` (TLS), `content_type`/`content_length`/`redirect_count`/`resolved_ip`/`ip_info` (HTTP) + helper `_registered_domain`, `_parse_soa`, `_parse_dmarc`, `_sig_alg_from_der`, `_cert_sig_alg`, `_ip_geo` |
| `frontend/index.html` | Xóa `<details id="techDetails">` + nút `#apiSwitchBtn`; thêm 17 hàng mới trong `#domainDetails` (DNS: diCname, diSoa, diPtr, diSpf, diDmarc, diDnssec; WHOIS: diWhoisUpdated, diWhoisNs, diWhoisStatus; TLS: diTlsSans, diTlsSigAlg, diTlsVersion, diTlsCipher; HTTP: diHttpContentType, diHttpContentLength, diHttpRedirectCount, diHttpIp, diHttpIpInfo) |
| `frontend/script.js` | Xóa khối điền báo cáo kỹ thuật + handler `apiSwitchBtn`; `fillDomainInfo` viết lại (40 id, quy tắc NF); `resolveApiBase` giữ nguyên |
| `frontend/style.css` | Xóa rule `.btn-small` |
| `tests/test_frontend_jsdom.js` | Thêm check bỏ section/nút + payload mở rộng trường mới + 2 ca `SPARSE_PAYLOAD`/`NULLINFO_PAYLOAD` kiểm tra "Không tìm thấy" |
| `tests/test_domain_info.py` | `EMPTY` thêm key mới; FakeResolver chuẩn hóa host (xử lý `dns.name.Name` của reverse DNS); thêm check SOA/PTR/SPF/DMARC/DNSSEC + unit test parser/sig-alg/ip-geo + WHOIS giả + check trường mới ở ca google thật |
| `tests/test_predict_e2e.py` | Fake DNS đủ key mới (SOA/DMARC/SPF/PTR/DNSSEC cho google.com); thêm check các trường mới trong response `/predict` |

**Không đổi:** model (vẫn model 05), `requirements.txt`, cấu hình deploy. **Không push, không deploy trong bước này.**
