# UI-FIX-REPORT — Giao diện ScamShield: bớt chữ giải thích + palette mới không gradient

Ngày: 08/11/2026. Repo: `Cuong-VnC/phishing-ai-detector` (clone tại `~/workspace/phishing-ai-detector`).
Phạm vi: CHỈ frontend (`frontend/index.html`, `frontend/script.js`, `frontend/style.css`, `tests/test_frontend_jsdom.js`).
**Không động backend / requirements.txt / model / features.py. Không push, không deploy** — bước upload GitHub làm riêng bằng trình duyệt sau.

Phản hồi người dùng (dựa trên ảnh chụp site thật): (1) giao diện có quá nhiều chữ giải thích dùng công nghệ gì / làm như thế nào — trông giống web do AI tạo; (2) đổi hệ màu khác, không dùng màu gradient nữa.

## 1. Đã xóa những đoạn chữ nào

| Vị trí | Trước | Sau |
|---|---|---|
| Hero, dòng mô tả (`hero-sub`) | "Mô hình học máy (mạng nơ-ron + XGBoost) kết hợp kiểm tra tên miền thực tế: DNS, tuổi domain, chứng chỉ TLS và khả năng truy cập — để biết link có an toàn hay không." | "Dán link vào để kiểm tra trước khi bấm." (1 dòng, không nhắc tên công nghệ) |
| Mục "Hoạt động thế nào" (`how-card`) | Toàn bộ section: 3 bước giải thích (Phân tích bằng AI / Kiểm tra tên miền thật / Kết luận rõ ràng) + ghi chú dự án học tập | **Xóa cả section** (HTML + toàn bộ CSS `.how-card`, `.how-steps`, `.how-note`) |
| Footer | "ScamShield-AI — Dự án học tập phát hiện URL lừa đảo bằng học máy" | "ScamShield-AI — Kết quả chỉ mang tính tham khảo." (giữ lại ý cảnh báo, bỏ chữ "học máy") |
| Meta description | "...Kiểm tra link lừa đảo bằng học máy, kèm thông tin tên miền chi tiết (DNS, WHOIS, TLS, HTTP)." | "ScamShield-AI — Dán link vào để kiểm tra trước khi bấm." |
| `verdictDesc` mặc định (trước khi có kết quả) | "Kết quả dựa trên mô hình AI và thông tin tên miền." | "Chi tiết kết quả ở bên dưới." |
| Bước loading 1 (`script.js`) | "Đang phân tích URL bằng mô hình AI…" | "Đang phân tích link…" |
| Nhãn nguồn kết quả (`SOURCE_LABELS.ai_analysis`) | "Mô hình AI (NN + XGBoost)" | "Mô hình AI" (bỏ thuật ngữ NN/XGBoost) |

**Giữ nguyên:** ô nhập URL, nút kiểm tra, 4 chip URL mẫu, gợi ý nhập link đầy đủ, thẻ kết quả + gauge, 2 mục chi tiết kết quả (Báo cáo kỹ thuật + Thông tin tên miền — đây là KẾT QUẢ kiểm tra, không phải giải thích), lịch sử kiểm tra, hộp loading, hộp lỗi, nút đổi máy chủ API.

Kiểm tra bằng grep sau khi sửa: 0 kết quả cho `XGBoost`, `mạng nơ-ron`, `học máy`, `neural` trong `index.html` + `script.js` (phần hiển thị với người dùng).

## 2. Palette mới (màu đặc, không gradient)

Hệ cũ: nền xám-xanh `#f1f5f9`, chữ navy `#0f172a`, xanh dương `#2563eb` + teal `#0d9488`, gradient ở logo/nút/tiêu đề.
Hệ mới: **nền trắng ấm, header charcoal đặc, nút chính xanh lá đậm đặc, chữ charcoal ấm.**

| Vai trò | Mã màu | Ghi chú |
|---|---|---|
| Nền trang `--bg` | `#f7f5f0` | trắng ấm (off-white) |
| Mặt thẻ `--surface` | `#ffffff` | trắng |
| Mặt thẻ nhạt `--surface-soft` | `#f1eee7` | trắng ấm nhạt |
| Chữ chính `--ink` | `#26221e` | charcoal ấm (cũng là màu header) |
| Chữ phụ `--ink-2` | `#44403c` | |
| Chữ mờ `--muted` | `#78716c` | |
| Đường kẻ `--line` | `#e5e0d5` | |
| Nút chính `--primary` | `#166534` | xanh lá đậm, màu đặc |
| Nút chính hover `--primary-dark` | `#14532d` | xanh lá đậm hơn |
| Nền nhạt của primary `--primary-soft` | `#dcfce7` | |
| Header (topbar) | `#26221e` (`--ink`) | charcoal đặc, không gradient |
| Icon logo `.brand-icon` | nền `#ffffff`, icon `#14532d` | ô trắng + khiên xanh lá trên nền header charcoal |
| Chữ "-AI" trong logo `.brand-ai` | `#a7f3d0` | xanh lá nhạt |
| Tiêu đề phụ `.hero-accent` | `#166534` (`--primary`) | xanh lá đậm đặc (trước là chữ gradient) |
| Màu kết quả | an toàn `#16a34a`, nguy hiểm `#dc2626`, nghi ngờ `#d97706`, không tồn tại `#78716c` | giữ nguyên ý nghĩa, đều màu đặc |
| Bóng đổ | `rgba(28, 25, 23, …)` | đổi từ tông navy `rgba(15, 23, 42, …)` sang tông charcoal ấm |

**Đã xóa 3 gradient trong `style.css`:** `.brand-icon` (`linear-gradient(135deg, primary, teal)`), `.hero-accent` (gradient text + `background-clip: text`), `#scanBtn` (`linear-gradient(135deg, primary, #1e40af)`). Biến `--teal` đã xóa hẳn. Kiểm tra bằng grep sau khi sửa: **0 kết quả cho "gradient" trong toàn bộ `frontend/`** (kể cả comment trong code cũng đã tránh từ này).

**Gauge tròn: KHÔNG cần dựng lại.** Gauge vốn đã dùng vòng tròn SVG với `stroke` màu đặc (`gauge-track` / `gauge-fill`, `stroke-dasharray`/`stroke-dashoffset`), không dùng `conic-gradient`. Chỉ đổi màu track từ `#e2e8f0` sang `var(--line)` (`#e5e0d5`) cho khớp palette mới. Màu vòng gauge vẫn lấy theo kết quả (xanh/vàng/đỏ/xám đặc) qua `setGauge()` trong `script.js` — không đổi logic.

## 3. Kiểm chứng

- `node --check frontend/script.js`: **OK**.
- HTML cân bằng (`html.parser`): không thẻ lệch, không thẻ chưa đóng.
- `tests/test_frontend_jsdom.js`: **23 PASS, 0 FAIL** (20 check cũ + 3 check mới thêm cho yêu cầu này: CSS không còn gradient; hero-sub ngắn ≤ 60 ký tự và không nhắc tên công nghệ; không còn `.how-card`). Chạy bằng `NODE_PATH=/tmp/fe-test/node_modules node tests/test_frontend_jsdom.js` (jsdom cài ở `/tmp/fe-test`, không bền qua thay VM — cần cài lại nếu chạy lại sau).
  - Lưu ý: node không tự thoát sau khi in đủ kết quả (jsdom `pretendToBeVisual` giữ event loop) nên phải chạy kèm `timeout 25` — đó không phải lỗi test, kết quả đã in đầy đủ 23 PASS trước khi bị timeout.
- Không đổi id/class nào mà `script.js` và test dùng (chỉ đổi nội dung chữ + màu); responsive mobile + desktop giữ nguyên (media query 720px không sửa).

## 4. File đã đổi (để upload lên GitHub)

| File | Thay đổi |
|---|---|
| `frontend/index.html` | hero-sub 1 dòng, xóa `how-card`, footer + meta description + `verdictDesc` mặc định |
| `frontend/style.css` | palette mới toàn bộ, xóa 3 gradient + biến `--teal`, xóa CSS `how-card` |
| `frontend/script.js` | 2 chuỗi hiển thị: bước loading 1 + nhãn nguồn `ai_analysis` |
| `tests/test_frontend_jsdom.js` | thêm 3 check mới (gradient / hero-sub / how-card) |
| `UI-FIX-REPORT.md` | báo cáo này (mới) |

## 5. Ghi chú ngoài phạm vi (không sửa trong lần này)

- **Lỗi Render `tensorflow-cpu==2.16.1` KHÔNG phải do lần push cải tiến website gây ra.** Kiểm chứng bằng git: `git diff 7dcec85 origin/main -- requirements.txt` chỉ cho thấy **+1 dòng `dnspython==2.16.1`**; dòng `tensorflow-cpu==2.16.1` đã có sẵn từ trước trong file gốc (Render dùng Python 3.14.8 mặc định mới nên không có wheel cho TF 2.16.1). Hướng sửa: ghim Python 3.11.9 cho service Render — file `.python-version` (nội dung `3.11.9`) đã xuất hiện trong thư mục làm việc (do luồng khác tạo, không phải lần sửa này) và cần được upload cùng lần sau.
- Giao diện mới chưa được xem bằng trình duyệt thật (VM không có Chromium/Firefox/Playwright) — nên xem lại bằng mắt sau khi deploy.
