"""Regression test cho lỗi Render 09/11/2026: "idf vector is not fitted".

Nguyên nhân: tfidf_f2.pkl lưu bằng sklearn 1.6.1 (Kaggle) nhưng Render
chạy sklearn 1.3.2. Khi unpickle bằng 1.3.2, TfidfTransformer giữ mảng
idf trong __dict__['idf_'] nhưng 1.3.2 đọc idf_ qua property lấy từ
_idf_diag (không có trong pickle) nên transform() lỗi NotFittedError.
Hàm repair_tfidf_idf() trong backend/src/tfidf_compat.py dựng lại
_idf_diag từ mảng idf đã lưu.

Test này nạp file pickle THẬT từ backend/models, gọi repair rồi kiểm
chứng transform cho ra đúng số đã đo trên cả hai phiên bản sklearn
(1.3.2 đã sửa và 1.6.1 gốc phải cho cùng kết quả). Không có repair,
test FAIL trên sklearn 1.3.2 (NotFittedError).

Chạy:  .venv/bin/python tests/test_tfidf_compat.py
"""
import pickle
import sys

sys.path.insert(0, "backend/src")

import numpy as np

from features import f2_doc, skeletonize
from tfidf_compat import repair_tfidf_idf

PASS = []
FAIL = []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else FAIL) + name + (f" | {extra}" if extra else ""))


with open("backend/models/tfidf_f2.pkl", "rb") as f:
    tfidf = pickle.load(f)
with open("backend/models/svd_f2.pkl", "rb") as f:
    svd = pickle.load(f)

# 1. Repair phải báo sẵn sàng (no-op trên sklearn 1.6.1, sửa thật trên 1.3.2)
ok = repair_tfidf_idf(tfidf)
check("repair_tfidf_idf tra True", ok is True, f"ok={ok}")

# 2. Transform URL có token khớp vocab: google.com -> nnz 2, sum 1.288905
doc = f2_doc(skeletonize("https://www.google.com/"))
X = tfidf.transform([doc])
check("tfidf transform khong loi", X.shape == (1, 10000), f"shape={X.shape}")
check("tfidf google.com nnz=2", X.nnz == 2, f"nnz={X.nnz}")
check("tfidf google.com sum=1.288905",
      abs(float(X.sum()) - 1.288905) < 1e-4, f"sum={float(X.sum()):.6f}")

# 3. SVD trên output TF-IDF: shape (1,128), sum 1.479865
Z = svd.transform(X)
check("svd shape (1,128)", Z.shape == (1, 128), f"shape={Z.shape}")
check("svd google.com sum=1.479865",
      abs(float(Z.sum()) - 1.479865) < 1e-4, f"sum={float(Z.sum()):.6f}")

# 4. URL không có token khớp vocab vẫn transform được (vector 0, không crash)
doc2 = f2_doc(skeletonize("https://usth.edu.vn"))
X2 = tfidf.transform([doc2])
Z2 = svd.transform(X2)
check("tfidf usth.edu.vn vector 0 khong crash",
      X2.nnz == 0 and float(Z2.sum()) == 0.0, f"nnz={X2.nnz}")

# 5. Gọi repair lần 2 phải an toàn (idempotent)
ok2 = repair_tfidf_idf(tfidf)
check("repair lan 2 van True", ok2 is True, f"ok2={ok2}")
X3 = tfidf.transform([doc])
check("transform sau repair lan 2 giong cu",
      X3.nnz == 2 and abs(float(X3.sum()) - 1.288905) < 1e-4,
      f"nnz={X3.nnz} sum={float(X3.sum()):.6f}")

print(f"\n== {len(PASS)} PASS, {len(FAIL)} FAIL ==")
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
