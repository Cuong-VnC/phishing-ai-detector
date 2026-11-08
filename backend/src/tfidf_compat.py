"""Tương thích pickle TF-IDF giữa các phiên bản scikit-learn.

Vấn đề (gặp thật trên Render 09/11/2026): file tfidf_f2.pkl được lưu bằng
scikit-learn 1.6.1 (Kaggle) nhưng backend Render chạy sklearn 1.3.2
(requirements.txt pin). Khi unpickle bằng 1.3.2, đối tượng
TfidfTransformer vẫn giữ mảng idf trong __dict__['idf_'] nhưng
sklearn 1.3.2 đọc idf_ qua property lấy từ self._idf_diag — thuộc tính
này không có trong pickle 1.6.1 — nên mọi lời gọi transform() đều lỗi
``NotFittedError: idf vector is not fitted`` (dù file pickle hoàn toàn
đúng và chạy tốt trên sklearn 1.6.1).

Khắc phục: dựng lại _idf_diag từ mảng idf đã lưu trong __dict__.
Hàm này an toàn khi chạy trên mọi phiên bản: nếu idf_ đã đọc được
bình thường thì không làm gì cả.
"""

import pickle  # noqa: F401  (giữ import rõ ràng cho test dùng chung module)


def repair_tfidf_idf(vec):
    """Sửa vectorizer TF-IDF đã nạp từ pickle để transform() chạy được.

    Trả về True nếu vectorizer đã sẵn sàng dùng (kể cả khi không cần sửa),
    False nếu không sửa được (khi đó transform() sẽ vẫn lỗi như cũ).
    """
    try:
        inner = getattr(vec, "_tfidf", None)
        if inner is None:
            return False
        try:
            _ = inner.idf_
            return True  # đã nạp đúng, không cần sửa
        except Exception:
            pass
        raw = inner.__dict__.get("idf_")
        if raw is None:
            return False
        from scipy.sparse import diags as _diags

        inner._idf_diag = _diags(raw)
        # Kiểm chứng sửa xong đọc được idf_
        _ = inner.idf_
        return True
    except Exception as e:
        print(f"⚠️ Không sửa được TF-IDF compat: {e}")
        return False
