# Triển khai model v8 lên backend website ScamShield

Ngày: 08/11/2026. Model v8 CHÍNH THỨC: Output Commit Version #1 notebook Kaggle
"train model url v8" (artifacts đã kiểm chứng, xem `~/workspace/phishing-model/artifacts-v8/`).
Backend trước đó chạy model 05 (18 đặc trưng, không F2). Bản này thay toàn bộ
pipeline suy luận sang model 08 (41 đặc trưng + F2 + ngưỡng 0.45).

## 1. File đã đổi

| File | Thay đổi |
|---|---|
| `backend/src/features.py` | 185 → 845 dòng: port đầy đủ 41 đặc trưng + skeletonize + F2 từ notebook 08 |
| `backend/src/main.py` | 379 → 392 dòng: nạp thêm `tfidf_f2.pkl`/`svd_f2.pkl`, stack XGB 170 cột, check 41 features |
| `backend/models/meta.json` | Thay bằng meta.json v8 (model_version "08", threshold 0.45) |
| `backend/models/phishing_nn.keras` | Thay bằng NN v8 (193.217 tham số) |
| `backend/models/xgb_model.json` | Thay bằng XGB v8 (300 cây, input 170 cột) |
| `backend/models/scaler.pkl` | Thay bằng scaler v8 (41 đặc trưng) |
| `backend/models/tokenizer.json` | Thay bằng tokenizer v8 (vocab 650 ký tự, char-level, OOV) |
| `backend/models/tfidf_f2.pkl` | MỚI — TF-IDF F2 (vocab 10.000) |
| `backend/models/svd_f2.pkl` | MỚI — TruncatedSVD F2 (128 chiều) |
| `tests/test_predict_e2e.py` | 183 → 213 dòng: ngưỡng 0.45 + 2 ca phishing mới (xem §5) |
| `MODEL-V8-DEPLOY-REPORT.md` | Báo cáo này (mới) |

KHÔNG đổi: `requirements.txt`, `.python-version`, `backend/src/domain_info.py`,
`frontend/*`, `tests/test_domain_info.py`, `tests/test_frontend_jsdom.js`,
notebook v8, dataset. KHÔNG push lên GitHub (bước riêng).

## 2. Map 41 đặc trưng (đúng thứ tự `FEATURE_NAMES`, khớp meta.json v8)

18 đặc trưng đầu GIỐNG TÊN và THỨ TỰ của model 05 — nhưng model 05 tính trên
URL GỐC, còn v8 tính trên URL ĐÃ SKELETONIZE (lowercase + giải mã punycode ở
host + NFKC/NFKD bỏ dấu + map confusable → Latin). Giá trị vì vậy khác model 05.

| # | Nhóm | Đặc trưng |
|---|---|---|
| 0–17 | 18 cũ | `url_len, host_len, path_len, n_dots, n_hyphens, n_underscores, n_slashes, n_digits, digit_ratio, has_ip, has_at, n_subdomains, has_https, n_params, n_percent, n_equals, has_sus_kw, tld_len` |
| 18–24 | Brand / từ khóa (7) | `brand_in_host, brand_in_path, brand_in_subdomain_only, min_brand_distance_host, sus_kw_count, sus_kw_in_host, has_sus_tld` |
| 25–31 | Độ ngẫu nhiên (7) | `host_entropy, path_entropy, url_entropy, vowel_ratio_host, digit_ratio_host, digit_ratio_path, letter_digit_transitions` |
| 32–40 | Homoglyph (9) | `n_non_ascii, n_confusable_chars, has_mixed_scripts, skeleton_brand_match, has_punycode, n_cyrillic, n_greek, confusable_ratio, n_script_switches` |

Hằng số (khớp notebook 08 + meta.json): 33 brand, 21 từ khóa nhạy cảm,
15 TLD nhạy cảm, 22 trusted domain (giống hệt model 05), map confusable
**298 ký tự** (Unicode confusables.txt 18.0.0, chép nguyên văn từ notebook,
không gõ tay), `max_len` 200, ngưỡng **0.45**.

Quy tắc skeletonize (notebook 08): 9 đặc trưng homoglyph tính từ URL GỐC;
32 đặc trưng còn lại + input tokenizer + F2 tính từ URL ĐÃ SKELETONIZE;
whitelist luôn so khớp trên registrable domain GỐC.

## 3. Quy tắc hybrid NN + XGB (đúng `predict_url` notebook 08, cell 18)

1. Whitelist: `registrable_domain(url)` thuộc 22 trusted domain → Safe, prob 0.0.
2. `feats` = 41 đặc trưng → `scaler.transform` → `scaled` (41 chiều).
3. `seq` = char-sequence của URL ĐÃ SKELETONIZE (max_len 200, pad/truncate "post").
4. `nn_p = model_nn.predict([seq, scaled])`.
5. `f2 = svd_f2.transform(tfidf_f2.transform([f2_doc(skeletonize(url))]))`
   (128 chiều; F2 = token theo vị trí `sub:/dom:/path:/query:` + TF-IDF
   sublinear, vocab 10.000, min_df 5).
6. `stack = [nn_p, scaled(41), f2(128)]` = **170 cột** → `xgb.predict_proba`.
7. Phishing nếu `p >= 0.45` (ngưỡng từ meta.json).

## 4. Đối chiếu notebook 08 vs meta.json v8

Đã kiểm chứng bằng script: `FEATURE_NAMES` (41), `BRANDS` (33), `SUS_KW` (21),
`SUS_TLD` (15), `TRUSTED` (22) trong notebook **khớp hoàn toàn** meta.json.
`registrable_domain` (notebook cell 2) giống hệt bản backend cũ nên giữ nguyên.
Chỉ có 2 điểm cần ghi rõ (không phải lỗi, nhưng dễ hiểu lầm):

- **`n_features_xgb = 169` trong meta.json KHÔNG phải số cột XGB nhận.**
  169 = 41 + 128 (không tính cột `nn_p`). Input thực của XGB là **170 cột**
  (1 nn_p + 41 + 128) — đã xác minh: `xgb_model.json` có
  `n_features_in_ == 170`, và cell 14 notebook ghi rõ stack "= 170 cột".
  Backend dựng stack 170 cột theo đúng cell 14/18, không dùng số 169.
- **Ngưỡng lưu là `0.45000000000000007`** (float của lưới `np.arange(0.05, 0.95, 0.01)`
  lúc tune trên val) — bằng 0.45 trong sai số 1e-9; test so sánh với dung sai.

## 5. Kiểm chứng

### 5.1. Parity code backend vs notebook (quan trọng nhất)

Chạy code gốc notebook 08 (cell 6 + hàm F2 cell 9) và code backend mới trên
cùng **39 URL** đa dạng (legit, phishing, homoglyph Cyrillic/Hy Lạp,
punycode, typo brand, IP, subdomain, query, ký tự có dấu, token dài):
**0 mismatch** — `extract_features`, `skeletonize`, `f2_doc`,
`homoglyph_features` và toàn bộ hằng số (`FEATURE_NAMES`, `BRANDS`,
`SUS_KW`, `SUS_TLD`, `CONFUSABLE_MAP` 298) đều khớp chính xác.

### 5.2. Nạp artifacts (venv test: TF 2.17.0, sklearn 1.6.1, xgboost 3.0.2)

- NN inputs `[(None, 200), (None, 41)]`, 193.217 tham số; XGB `n_features_in_=170`;
  scaler `n_features_in_=41`; tokenizer vocab 650 (word_index 649 + pad);
  TF-IDF vocab 10.000; SVD 128 chiều. Nạp sạch, không lỗi version.
- 7 file chép vào `backend/models/` đã kiểm chứng md5 khớp nguồn.

### 5.3. Test suite (venv-scam-test)

| Suite | Kết quả |
|---|---|
| `tests/test_frontend_jsdom.js` | **44/44 PASS** (không đổi) |
| `tests/test_domain_info.py` | **47/47 PASS** (không đổi) |
| `tests/test_predict_e2e.py` | **44/44 PASS** (trước đây 37; +7 check mới) |

Check mới trong e2e: `/health` trả threshold 0.45; `drive-google-share.com`
→ Phishing prob **0.7573** (vòng 2 chỉ 0.4211, dưới ngưỡng cũ 0.48);
URL homoglyph punycode `xn--vietcombank-9ya.com` → Phishing prob **0.9988**;
`vietcombank-dangnhap.com` → Phishing prob 0.9997. Shape response API giữ
nguyên (đủ trường cũ `url/status/probability/risk_level/technical_report/source`
+ `domain_info/domain_status/warning`); `technical_report` vẫn có
`nn_probability`.

### 5.4. Smoke check thủ công (model thật, so với `predict_url` notebook)

11/11 URL khớp xác suất notebook tới 4 chữ số thập phân và đúng kỳ vọng:

| URL | Kết quả | prob | nn_prob |
|---|---|---|---|
| https://www.google.com | Safe (whitelist) | 0.0000 | 0.0000 |
| https://www.paypal.com | Safe (whitelist) | 0.0000 | 0.0000 |
| https://www.youtube.com/watch?v=abc | Safe (whitelist) | 0.0000 | 0.0000 |
| https://www.vietcombank.com.vn | Safe | 0.0190 | 0.0078 |
| https://vietcombank-dangnhap.com/login | Phishing | 0.9997 | 1.0000 |
| https://drive-google-share.com/ | Phishing | 0.7573 | 0.8126 |
| https://google-drive-share-docs.com/ | Phishing | 0.8492 | 0.8919 |
| https://www.vietcombаnk.com/login (а Cyrillic) | Phishing | 0.9859 | 1.0000 |
| https://xn--vietcombank-9ya.com/login (punycode) | Phishing | 0.9988 | 1.0000 |
| https://secure-login-vietcombank.vn-ul.top/ | Phishing | 0.9999 | 1.0000 |
| http://185.23.45.67/login.php | Phishing | 0.9999 | 1.0000 |

## 6. Lưu ý / rủi ro còn lại

1. **URL homoglyph Unicode thô bị chặn ở tầng HTTP trước khi tới model**
   (hành vi có từ trước, không đổi trong bản này): `validate_url_format`
   chỉ cho host ASCII (`[A-Za-z0-9._\-:\[\]]+`) nên URL chứa ký tự Cyrillic
   thô trả 400. Dạng punycode (`xn--...`) đi qua bình thường và model bắt
   đúng (0.9988). Nếu muốn nhận cả URL Unicode thô thì cần nới validation
   (ngoài phạm vi bản này).
2. **Version pickle trên Render:** artifacts được tạo trên Kaggle và nạp sạch
   trong venv test (sklearn 1.6.1); Render chạy Python 3.11.9 với bản pin
   (sklearn 1.3.2, TF 2.16.1, xgboost 2.0.2). `scaler.pkl`/`tfidf_f2.pkl`/
   `svd_f2.pkl` là pickle sklearn — khi nạp bằng sklearn 1.3.2 có thể hiện
   `InconsistentVersionWarning` nhưng thường vẫn nạp được (class ổn định).
   **Cần kiểm chứng trên Render sau khi deploy**: mở `/health` phải trả
   `models_loaded: true` và thử 1 URL phishing + 1 URL legit.
3. Levenshtein: backend dùng `python-Levenshtein` (đã có trong
   `requirements.txt`); nếu import thất bại sẽ tự rơi về bản thuần Python
   (chậm hơn nhưng đúng kết quả) — code này port từ notebook.
4. Tầng DB nội bộ / URLhaus / Google Safe Browsing không đổi; thứ tự ưu tiên
   trong `/predict` không đổi.
