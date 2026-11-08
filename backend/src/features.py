"""Dac trung URL cho pipeline ScamShield model v8 (notebook 08).

41 dac trung, dung thu tu FEATURE_NAMES (khop meta.json model 08):
- 18 dac trung cu (url_len..tld_len) — GIOng ten/thu tu model 05 NHUNG tinh
  tren URL DA SKELETONIZE (khong phai URL goc nhu model 05).
- Nhom 2 (brand/tu khoa): brand_in_host, brand_in_path,
  brand_in_subdomain_only, min_brand_distance_host, sus_kw_count,
  sus_kw_in_host, has_sus_tld.
- Nhom 3 (do ngau nhien): host_entropy, path_entropy, url_entropy,
  vowel_ratio_host, digit_ratio_host, digit_ratio_path,
  letter_digit_transitions.
- 9 homoglyph: n_non_ascii, n_confusable_chars, has_mixed_scripts,
  skeleton_brand_match, has_punycode, n_cyrillic, n_greek,
  confusable_ratio, n_script_switches — tinh tu URL GOC.

QUY TAC QUAN TRONG (theo notebook 08): 32 dac trung dau + input tokenizer
tinh tu URL DA SKELETONIZE (giai ma punycode + map confusable ve Latin);
9 dac trung homoglyph tinh tu URL GOC; whitelist luon so khop tren domain
GOC, khong bao gio so tren skeleton. F2 (TF-IDF + SVD 128 chieu) cung dung
URL DA SKELETONIZE.
"""
import tldextract
import re
import json
import math
import socket
import unicodedata
import whois
from datetime import datetime

try:
    import Levenshtein

    def _lev_dist(a, b):
        return Levenshtein.distance(a, b)
except Exception:
    # Du phong thuan Python neu thieu python-Levenshtein (co trong
    # requirements.txt; chi dung khi import that bai).
    def _lev_dist(a, b):
        if a == b:
            return 0
        la, lb = len(a), len(b)
        if la == 0:
            return lb
        if lb == 0:
            return la
        prev = list(range(lb + 1))
        for i, ca in enumerate(a, 1):
            cur = [i] + [0] * lb
            for j, cb in enumerate(b, 1):
                cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            prev = cur
        return prev[lb]


# --- DANH SÁCH THƯƠNG HIỆU ĐỐI CHỨNG (chi dung cho technical_report) ---
TOP_BRANDS = [
    "google", "facebook", "amazon", "apple", "microsoft", "netflix",
    "paypal", "binance", "metamask", "misa", "shopee", "lazada",
    "vietcombank", "techcombank", "zalo", "telegram", "twitter", "instagram"
]

# --- MODEL v8: hang so (khop notebook 08 + meta.json) ---
BRANDS = ["google", "facebook", "amazon", "apple", "microsoft", "netflix", "paypal",
          "binance", "metamask", "github", "linkedin", "twitter", "instagram", "telegram",
          "vietcombank", "techcombank", "vietinbank", "bidv", "agribank", "sacombank",
          "acb", "mb", "vpbank", "momo", "zalopay", "viettel", "vinaphone", "mobifone",
          "shopee", "lazada", "tiki", "vneid", "dichvucong"]
SUS_KW = ["login", "verify", "signin", "secure", "account", "update", "confirm", "free", "bonus",
          "nhan-thuong", "trung-thuong", "mien-phi", "khuyen-mai", "tang-qua", "nhan-qua",
          "rut-tien", "nap-tien", "nhanqua", "trungthuong", "uu-dai", "nhan-tien"]
SUS_TLD = {".top", ".xyz", ".club", ".online", ".site", ".fun", ".icu", ".buzz", ".live",
           ".vip", ".cc", ".ru", ".tk", ".ml", ".ga"}

# Ban do ky tu confusable -> Latin (theo UTS #39; 41 ky tu, CHI map chu cai, khong map so).
# Viet dang \uXXXX de doc duoc ma codepoint trong notebook (ky tu Cyrillic/Hy Lap
# nhin giong het chu Latin nen khong duoc viet truc tiep).
# Cyrillic: U+0430 a, U+0435 e, U+043E o, U+0440 p, U+0441 c, U+0445 x, U+0443 y,
# U+0456 i, U+0458 j, U+0455 s, U+04BB h, U+0501 d, U+043A k, U+043C m, U+043D h,
# U+0442 t, U+0432 b, U+0433 r, U+0434 d, U+043F n, U+0475 v, U+0461 w.
# Greek: U+03B1 a, U+03B5 e, U+03BF o, U+03C1 p, U+03BD v, U+03BA k, U+03C4 t,
# U+03C7 x, U+03B9 i, U+03BC u, U+03B7 n, U+03C5 u, U+03C9 w, U+03B2 b, U+03B4 o,
# U+03B3 r, U+03C2 s. Coptic: U+2C81 a. Latin IPA: U+0261 g.
# Luu y: khong map U+0437 (ze Cyrillic) vi no giong so 3, khong phai chu cai Latin.
CONFUSABLE_MAP = {
    # Nguon: Unicode confusables.txt 18.0.0 (unicode.org/Public/security/latest/confusables.txt,
    # ngay 2026-08-06) — loc: nguon la 1 ky tu non-ASCII, dich la 1 chu cai Latin [a-z],
    # chi giu entry ma NFKC/NFKD khong tu xu ly duoc; + map cu viet tay (lap khoang trong
    # k/m/t/n/... ma file chinh thuc chi co chuoi gian tiep, vd k -> kra U+0138). Tong 298 ky tu.
    # Fullwidth/toan hoc: NFKC trong _fold_text da gap ve ASCII nen khong can map.
    # -> "a": 10 bien the (COPTIC 1, CYRILLIC 1, GREEK 1, LATIN 2, OLD ITALIC 2, OTHER 3)
    "\u0251": "a",
    "\u03b1": "a",
    "\u0430": "a",
    "\u2c81": "a",
    "\uab64": "a",
    "\U0001d6c2": "a",
    "\U0001d6fc": "a",
    "\U0001d736": "a",
    "\U0001d770": "a",
    "\U0001d7aa": "a",
    # -> "b": 9 bien the (CANADIAN 2, CHEROKEE 1, CYRILLIC 2, GREEK 1, LATIN 1, OLD ITALIC 1, OTHER 1)
    "\u0184": "b",
    "\u03b2": "b",
    "\u042c": "b",
    "\u0432": "b",
    "\u07d5": "b",
    "\u13cf": "b",
    "\u1472": "b",
    "\u15af": "b",
    "\U0001031c": "b",
    # -> "c": 9 bien the (CHEROKEE 1, COPTIC 1, CYRILLIC 2, DESERET 1, GREEK 1, LATIN 1, OTHER 2)
    "\u03f2": "c",
    "\u0441": "c",
    "\u1004": "c",
    "\u105a": "c",
    "\u1c83": "c",
    "\u1d04": "c",
    "\u2ca5": "c",
    "\uabaf": "c",
    "\U0001043d": "c",
    # -> "d": 5 bien the (CANADIAN 1, CHEROKEE 1, CYRILLIC 2, LISU 1)
    "\u0434": "d",
    "\u0501": "d",
    "\u13e7": "d",
    "\u146f": "d",
    "\ua4d2": "d",
    # -> "e": 4 bien the (CYRILLIC 2, GREEK 1, LATIN 1)
    "\u03b5": "e",
    "\u0435": "e",
    "\u04bd": "e",
    "\uab32": "e",
    # -> "f": 7 bien the (ARMENIAN 1, LATIN 6)
    "\u017f": "f",
    "\u0192": "f",
    "\u0284": "f",
    "\u0584": "f",
    "\u1e9d": "f",
    "\ua799": "f",
    "\uab35": "f",
    # -> "g": 4 bien the (ARMENIAN 1, LATIN 3)
    "\u018d": "g",
    "\u0261": "g",
    "\u0581": "g",
    "\u1d83": "g",
    # -> "h": 6 bien the (ARMENIAN 1, CHEROKEE 1, CYRILLIC 3, GEORGIAN 1)
    "\u043d": "h",
    "\u04ba": "h",
    "\u04bb": "h",
    "\u0570": "h",
    "\u10b9": "h",
    "\u13c2": "h",
    # -> "i": 17 bien the (ARMENIAN 1, CHEROKEE 2, COPTIC 1, CYRILLIC 2, GREEK 1, LATIN 3, OLD ITALIC 2, OTHER 5)
    "\u0131": "i",
    "\u0269": "i",
    "\u026a": "i",
    "\u03b9": "i",
    "\u0456": "i",
    "\u0582": "i",
    "\u13a5": "i",
    "\u2c93": "i",
    "\ua647": "i",
    "\uab75": "i",
    "\U000118c3": "i",
    "\U0001d6a4": "i",
    "\U0001d6ca": "i",
    "\U0001d704": "i",
    "\U0001d73e": "i",
    "\U0001d778": "i",
    "\U0001d7b2": "i",
    # -> "j": 5 bien the (ARMENIAN 1, CYRILLIC 1, GREEK 1, LATIN 1, OTHER 1)
    "\u0237": "j",
    "\u03f3": "j",
    "\u0458": "j",
    "\u0575": "j",
    "\U0001d6a5": "j",
    # -> "k": 2 bien the (CYRILLIC 1, GREEK 1)
    "\u03ba": "k",
    "\u043a": "k",
    # -> "l": 50 bien the (COPTIC 1, CYRILLIC 3, GREEK 1, LATIN 6, LISU 1, LYCIAN 1, LYDIAN 1, OLD ITALIC 5, OTHER 28, RUNIC 2, VAI 1)
    "\u0196": "l",
    "\u01c0": "l",
    "\u0399": "l",
    "\u0406": "l",
    "\u04c0": "l",
    "\u04cf": "l",
    "\u05d5": "l",
    "\u05df": "l",
    "\u0627": "l",
    "\u07ca": "l",
    "\u16c1": "l",
    "\u16d0": "l",
    "\u2110": "l",
    "\u2111": "l",
    "\u2c92": "l",
    "\u2d4a": "l",
    "\u2d4f": "l",
    "\ua4f2": "l",
    "\ua56f": "l",
    "\ua781": "l",
    "\ua7ae": "l",
    "\ua7fe": "l",
    "\ufe8d": "l",
    "\ufe8e": "l",
    "\uff29": "l",
    "\U0001028a": "l",
    "\U00010309": "l",
    "\U0001050e": "l",
    "\U00010926": "l",
    "\U00010c3e": "l",
    "\U00010ca5": "l",
    "\U00016f28": "l",
    "\U0001d408": "l",
    "\U0001d43c": "l",
    "\U0001d470": "l",
    "\U0001d4d8": "l",
    "\U0001d540": "l",
    "\U0001d574": "l",
    "\U0001d5a8": "l",
    "\U0001d5dc": "l",
    "\U0001d610": "l",
    "\U0001d644": "l",
    "\U0001d678": "l",
    "\U0001d6b0": "l",
    "\U0001d6ea": "l",
    "\U0001d724": "l",
    "\U0001d75e": "l",
    "\U0001d798": "l",
    "\U0001ee00": "l",
    "\U0001ee80": "l",
    # -> "m": 1 bien the (CYRILLIC 1)
    "\u043c": "m",
    # -> "n": 4 bien the (ARMENIAN 2, CYRILLIC 1, GREEK 1)
    "\u03b7": "n",
    "\u043f": "n",
    "\u0578": "n",
    "\u057c": "n",
    # -> "o": 57 bien the (ARMENIAN 1, COPTIC 2, CYRILLIC 2, DESERET 1, GEORGIAN 1, GREEK 3, LATIN 3, LYDIAN 1, OLD ITALIC 4, OSAGE 1, OTHER 38)
    "\u03b4": "o",
    "\u03bf": "o",
    "\u03c3": "o",
    "\u03ed": "o",
    "\u043e": "o",
    "\u0585": "o",
    "\u05e1": "o",
    "\u0647": "o",
    "\u06be": "o",
    "\u06c1": "o",
    "\u06d5": "o",
    "\u07cb": "o",
    "\u0840": "o",
    "\u0d20": "o",
    "\u101d": "o",
    "\u10ff": "o",
    "\u110b": "o",
    "\u11bc": "o",
    "\u1a45": "o",
    "\u1c82": "o",
    "\u1d0f": "o",
    "\u1d11": "o",
    "\u2c9f": "o",
    "\u3147": "o",
    "\uab3d": "o",
    "\ufba6": "o",
    "\ufba7": "o",
    "\ufba8": "o",
    "\ufba9": "o",
    "\ufbaa": "o",
    "\ufbab": "o",
    "\ufbac": "o",
    "\ufbad": "o",
    "\ufee9": "o",
    "\ufeea": "o",
    "\ufeeb": "o",
    "\ufeec": "o",
    "\uffb7": "o",
    "\U0001042c": "o",
    "\U000104ea": "o",
    "\U0001092c": "o",
    "\U00010d07": "o",
    "\U00011124": "o",
    "\U000118c8": "o",
    "\U000118d7": "o",
    "\U0001d6d0": "o",
    "\U0001d6d4": "o",
    "\U0001d70a": "o",
    "\U0001d70e": "o",
    "\U0001d744": "o",
    "\U0001d748": "o",
    "\U0001d77e": "o",
    "\U0001d782": "o",
    "\U0001d7b8": "o",
    "\U0001d7bc": "o",
    "\U0001ee24": "o",
    "\U0001ee84": "o",
    # -> "p": 18 bien the (COPTIC 2, CYRILLIC 1, GREEK 3, LATIN 2, OLD ITALIC 4, OTHER 6)
    "\u00fe": "p",
    "\u01bf": "p",
    "\u03c1": "p",
    "\u03f1": "p",
    "\u03f8": "p",
    "\u0440": "p",
    "\u2ca3": "p",
    "\u2ccf": "p",
    "\U0001d6d2": "p",
    "\U0001d6e0": "p",
    "\U0001d70c": "p",
    "\U0001d71a": "p",
    "\U0001d746": "p",
    "\U0001d754": "p",
    "\U0001d780": "p",
    "\U0001d78e": "p",
    "\U0001d7ba": "p",
    "\U0001d7c8": "p",
    # -> "q": 3 bien the (ARMENIAN 2, CYRILLIC 1)
    "\u051b": "q",
    "\u0563": "q",
    "\u0566": "q",
    # -> "r": 7 bien the (BAMUM 1, CHEROKEE 1, COPTIC 1, CYRILLIC 1, GREEK 1, LATIN 2)
    "\u0433": "r",
    "\u1d26": "r",
    "\u2c85": "r",
    "\uab47": "r",
    "\uab48": "r",
    "\uab81": "r",
    "\U00016a19": "r",
    # -> "s": 8 bien the (CHEROKEE 1, CYRILLIC 1, DESERET 1, GREEK 1, LATIN 2, OTHER 2)
    "\u01bd": "s",
    "\u03c2": "s",
    "\u0455": "s",
    "\u0d1f": "s",
    "\ua731": "s",
    "\uabaa": "s",
    "\U00010448": "s",
    "\U000118c1": "s",
    # -> "t": 2 bien the (CYRILLIC 1, GREEK 1)
    "\u03c4": "t",
    "\u0442": "t",
    # -> "u": 15 bien the (ARMENIAN 1, GREEK 2, LATIN 5, OLD ITALIC 2, OSAGE 1, OTHER 4)
    "\u028b": "u",
    "\u03bc": "u",
    "\u03c5": "u",
    "\u057d": "u",
    "\u1d1c": "u",
    "\ua79f": "u",
    "\uab4e": "u",
    "\uab52": "u",
    "\U000104f6": "u",
    "\U000118d8": "u",
    "\U0001d6d6": "u",
    "\U0001d710": "u",
    "\U0001d74a": "u",
    "\U0001d784": "u",
    "\U0001d7be": "u",
    # -> "v": 12 bien the (CHEROKEE 1, CYRILLIC 1, GREEK 1, LATIN 1, OLD ITALIC 2, OTHER 6)
    "\u03bd": "v",
    "\u0475": "v",
    "\u05d8": "v",
    "\u1d20": "v",
    "\uaba9": "v",
    "\U00011706": "v",
    "\U000118c0": "v",
    "\U0001d6ce": "v",
    "\U0001d708": "v",
    "\U0001d742": "v",
    "\U0001d77c": "v",
    "\U0001d7b6": "v",
    # -> "w": 14 bien the (ARMENIAN 1, CHEROKEE 2, COPTIC 1, CYRILLIC 3, GREEK 1, LATIN 3, OTHER 3)
    "\u026f": "w",
    "\u03c9": "w",
    "\u0448": "w",
    "\u0461": "w",
    "\u051d": "w",
    "\u0561": "w",
    "\u1d21": "w",
    "\u2cbd": "w",
    "\ua7fa": "w",
    "\uab83": "w",
    "\uaba4": "w",
    "\U0001170a": "w",
    "\U0001170e": "w",
    "\U0001170f": "w",
    # -> "x": 6 bien the (CANADIAN 2, CYRILLIC 1, GREEK 1, OTHER 2)
    "\u03c7": "x",
    "\u0445": "x",
    "\u1541": "x",
    "\u157d": "x",
    "\u1763": "x",
    "\U00010cc2": "x",
    # -> "y": 18 bien the (COPTIC 1, CYRILLIC 2, GEORGIAN 1, GREEK 1, LATIN 5, OLD ITALIC 2, OTHER 6)
    "\u0263": "y",
    "\u028f": "y",
    "\u03b3": "y",
    "\u0443": "y",
    "\u04af": "y",
    "\u10e7": "y",
    "\u1d8c": "y",
    "\u1eff": "y",
    "\u213d": "y",
    "\u2ca9": "y",
    "\uab5a": "y",
    "\U000118c4": "y",
    "\U000118dc": "y",
    "\U0001d6c4": "y",
    "\U0001d6fe": "y",
    "\U0001d738": "y",
    "\U0001d772": "y",
    "\U0001d7ac": "y",
    # -> "z": 5 bien the (CHEROKEE 1, COPTIC 1, GEORGIAN 1, LATIN 2)
    "\u1d22": "z",
    "\u2c6c": "z",
    "\u2c8d": "z",
    "\u2d2d": "z",
    "\uab93": "z",
}

FEATURE_NAMES = ["url_len", "host_len", "path_len", "n_dots", "n_hyphens", "n_underscores",
                 "n_slashes", "n_digits", "digit_ratio", "has_ip", "has_at", "n_subdomains",
                 "has_https", "n_params", "n_percent", "n_equals", "has_sus_kw", "tld_len",
                 "brand_in_host", "brand_in_path", "brand_in_subdomain_only",
                 "min_brand_distance_host", "sus_kw_count", "sus_kw_in_host", "has_sus_tld",
                 "host_entropy", "path_entropy", "url_entropy", "vowel_ratio_host",
                 "digit_ratio_host", "digit_ratio_path", "letter_digit_transitions",
                 "n_non_ascii", "n_confusable_chars", "has_mixed_scripts",
                 "skeleton_brand_match", "has_punycode", "n_cyrillic", "n_greek",
                 "confusable_ratio", "n_script_switches"]
assert len(FEATURE_NAMES) == 41  # so luong dac trung phai khop danh sach ten


def _decode_punycode_label(label):
    # giai ma 1 nhan host dang punycode (xn--...); that bai thi giu nguyen
    if not label.startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except Exception:
        pass
    try:  # codec idna strict tu choi nhan khong round-trip (vd xn--vietcombank-9ya)
        return label[4:].encode("ascii").decode("punycode")
    except Exception:
        return label


def _fold_text(t):
    # NFKC (gap fullwidth) + NFKD bo dau (a-co-dau -> a) + map confusable -> Latin
    t = unicodedata.normalize("NFKC", t)
    t = "".join(c for c in unicodedata.normalize("NFKD", t) if unicodedata.category(c) != "Mn")
    return "".join(CONFUSABLE_MAP.get(c, c) for c in t)


def skeletonize(url):
    # Tra ve URL da skeletonize: lowercase + decode punycode o host + _fold_text.
    # Giu nguyen cau truc (scheme, userinfo, port) de cac dac trung nhu has_at con y nghia.
    s = str(url).lower()
    if "://" in s:
        scheme, rest = s.split("://", 1)
        prefix = scheme + "://"
    else:
        rest, prefix = s, ""
    m = re.split(r"([/?#])", rest, maxsplit=1)
    authority = m[0]
    tail = "".join(m[1:]) if len(m) > 1 else ""
    if "@" in authority:
        userinfo, hostport = authority.rsplit("@", 1)
        ui = userinfo + "@"
    else:
        hostport, ui = authority, ""
    if hostport.startswith("["):
        host, port = hostport, ""
        if "]" in hostport:
            host, port = hostport.split("]", 1)
            host = host + "]"
    else:
        if ":" in hostport:
            host, port = hostport.split(":", 1)
            port = ":" + port
        else:
            host, port = hostport, ""
    dec_host = ".".join(_decode_punycode_label(l) for l in host.split("."))
    return prefix + ui + _fold_text(dec_host) + port + _fold_text(tail)


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


def rd_label(url):
    # nhan domain cua registrable domain (vd: vietcombank.com.vn -> vietcombank)
    rd = registrable_domain(url)
    if not rd:
        return ""
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", rd):
        return rd
    parts = rd.split(".")
    two_level = {"co.uk", "com.au", "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "co.jp", "com.br"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_level:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else parts[0]


def get_entropy(text):
    """Tính toán độ hỗn loạn của chuỗi (Shannon Entropy)."""
    if not text:
        return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


def _host_tokens(host):
    return [t for t in re.split(r"[^a-z0-9]+", host.lower()) if t]


def _brand_in_tokens(tokens, brand):
    # brand dai >= 3: substring trong token (bat ca "vietcombanke"); brand ngan
    # nhu "mb": phai khop dung token (tranh "mb" trong "number", "remember")
    for t in tokens:
        if len(brand) >= 3 and brand in t:
            return True
        if len(brand) < 3 and t == brand:
            return True
    return False


def _brand_hits(tokens, rd_lbl):
    # tra ve (tap brand tim thay trong host, khoang cach Levenshtein nho nhat toi rd label)
    hits = set()
    min_d = 999
    for b in BRANDS:
        if abs(len(rd_lbl) - len(b)) < min_d:  # cat tia: khong the gan hon min hien tai
            d = _lev_dist(rd_lbl, b)
            if d < min_d:
                min_d = d
        if _brand_in_tokens(tokens, b):
            hits.add(b)
            continue
        for t in tokens:  # typo gan dung: token sai khac <= 1 ky tu so voi brand
            if abs(len(t) - len(b)) <= 1 and _lev_dist(t, b) <= 1:
                hits.add(b)
                break
    return hits, (min_d if min_d != 999 else 99)


def homoglyph_features(url):
    # 9 dac trung homoglyph, TINH TU URL GOC (khong skeletonize)
    u = str(url)
    host, path, query = safe_parse(u.lower())
    n_non_ascii = sum(1 for c in u if ord(c) > 127)
    dec_host = ".".join(_decode_punycode_label(l) for l in host.split("."))
    has_puny = 1 if any(l.startswith("xn--") for l in host.split(".")) else 0
    dec_text = dec_host + path + query
    n_conf = 0
    for c in dec_text:
        if c in CONFUSABLE_MAP:
            n_conf += 1
        elif ord(c) > 127:  # ky tu co dau (vd E-grave): NFKD ve chu Latin
            base = "".join(x for x in unicodedata.normalize("NFKD", c) if unicodedata.category(x) != "Mn")
            if len(base) == 1 and base.isascii() and base.isalpha():
                n_conf += 1
    has_mixed = 1 if (any(c.isascii() and c.isalpha() for c in dec_host)
                      and any(ord(c) > 127 for c in dec_host)) else 0
    # skeleton_brand_match: brand xuat hien trong authority skeletonize nhung
    # registrable domain goc KHONG phai brand do (vd xn--vietcombank-9ya.com)
    skel = skeletonize(u)
    sk_auth = skel.split("://", 1)[-1].split("/", 1)[0]
    sk_tokens = _host_tokens(sk_auth)
    rd_lbl = rd_label(u)
    sk_match = 0
    for b in BRANDS:
        if _brand_in_tokens(sk_tokens, b) and rd_lbl != b:
            sk_match = 1
            break
    # 4 dac trung homoglyph moi (vong 3): dem theo script trong host (da giai ma punycode),
    # ti le confusable, so lan doi script — bat ca ten mien mixed-script ma 5 dac trung cu bo sot.
    n_cyr = sum(1 for c in dec_host if 0x0400 <= ord(c) <= 0x04FF)
    n_grk = sum(1 for c in dec_host if 0x0370 <= ord(c) <= 0x03FF)
    conf_ratio = n_conf / max(len(dec_text), 1)

    def _script_cat(c):
        o = ord(c)
        if c.isascii() and c.isalpha():
            return "latin"
        if 0x0400 <= o <= 0x04FF:
            return "cyrillic"
        if 0x0370 <= o <= 0x03FF:
            return "greek"
        return "other"
    n_switch = 0
    _prev = None
    for c in dec_host:
        if not c.isalpha():
            continue
        _cat = _script_cat(c)
        if _prev is not None and _cat != _prev:
            n_switch += 1
        _prev = _cat
    return [n_non_ascii, n_conf, has_mixed, sk_match, has_puny,
            n_cyr, n_grk, conf_ratio, n_switch]


def extract_features(url):
    # 41 dac trung, dung thu tu FEATURE_NAMES. 9 homoglyph tinh tu URL GOC;
    # 32 con lai tinh tu URL DA SKELETONIZE.
    orig = str(url)
    skel = skeletonize(orig)
    host, path, query = safe_parse(skel)
    hg = homoglyph_features(orig)
    is_ip = 1 if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host) else 0
    feats = [
        len(skel), len(host), len(path),                      # do dai url/host/path
        skel.count("."), skel.count("-"), skel.count("_"),   # so dau cham/gach ngang/gach duoi
        skel.count("/"), sum(c.isdigit() for c in skel),     # so slash, so chu so
        sum(c.isdigit() for c in skel) / max(len(skel), 1),  # ti le chu so
        is_ip, 1 if "@" in skel else 0,                       # co IP, co ky tu @
        max(host.count(".") - 1, 0),                         # so subdomain
        1 if skel.startswith("https") else 0,                 # co https khong
        query.count("&") + (1 if query else 0),              # so tham so query
        skel.count("%"), skel.count("="),                    # so % va dau =
        1 if any(k in skel for k in SUS_KW) else 0,           # co tu khoa nhay cam khong
        len(host.split(".")[-1]) if "." in host else 0,      # do dai TLD
    ]
    tokens = _host_tokens(host)
    path_tokens = _host_tokens(path)
    rd_lbl = rd_label(skel)
    hits, min_d = _brand_hits(tokens, rd_lbl)
    hits_path = set(b for b in BRANDS if _brand_in_tokens(path_tokens, b))
    tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
    feats += [
        1 if hits else 0,                                    # brand_in_host
        1 if hits_path else 0,                               # brand_in_path
        1 if (hits and not any(b in registrable_domain(skel) for b in hits)) else 0,  # brand chi o subdomain
        min_d,                                               # min_brand_distance_host
        sum(skel.count(k) for k in SUS_KW),                  # sus_kw_count
        1 if any(k in host for k in SUS_KW) else 0,          # sus_kw_in_host
        1 if tld in SUS_TLD else 0,                          # has_sus_tld
    ]

    def _vowel_ratio(s):
        return (sum(c in "aeiou" for c in s) / len(s)) if s else 0

    def _digit_ratio(s):
        return (sum(c.isdigit() for c in s) / len(s)) if s else 0
    trans = 0
    prev_is_digit = None
    for c in skel:
        if c.isdigit():
            cur = True
        elif c.isalpha():
            cur = False
        else:
            continue
        if prev_is_digit is not None and cur != prev_is_digit:
            trans += 1
        prev_is_digit = cur
    feats += [
        get_entropy(host), get_entropy(path), get_entropy(skel),  # host/path/url entropy
        _vowel_ratio(host), _digit_ratio(host), _digit_ratio(path),
        trans,                                                # letter_digit_transitions
    ]
    feats += hg  # 9 dac trung homoglyph (tu URL goc)
    return feats


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


# --- F2: token theo vi tri + TF-IDF (word-level) + SVD 128 chieu (notebook 08, cell 9) ---
# Tokenize URL thanh token chu-so, lowercase, BO DAU tieng Viet; gan tien to
# vi tri: sub:<token> (subdomain), dom:<token> (registered domain),
# path:<token> (path), query:<token> (query). Goi tren URL DA SKELETONIZE.
def _strip_accents(s):
    # NFKC (gap fullwidth) + NFKD tach dau + bo ky tu Mark; rieng chu d
    # (U+0111) NFKD khong tach duoc nen map tay sang d.
    s = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", s))
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")
    return s.replace("đ", "d").replace("Đ", "d")


def _split_tokens(text):
    # tach token chu-so, GIU dau gach noi ben trong (vd "xac-minh" la 1 token);
    # bo token dai hon 32 ky tu (thuong la hash/chuoi ngau nhien, khong phai tu).
    out = []
    for t in re.split(r"[^a-z0-9-]+", text):
        t = t.strip("-")
        if t and len(t) <= 32:
            out.append(t)
    return out


def f2_tokens(url):
    s = _strip_accents(str(url).lower())
    host, path, query = safe_parse(s)
    labels = [l for l in host.split(".") if l]
    rd = registrable_domain(s)
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        sub_labels, dom_label = [], ""  # host IP: khong co token host; van lay token path/query
    elif rd and host.endswith(rd):
        n_rd = len(rd.split("."))
        sub_labels = labels[:-n_rd] if n_rd < len(labels) else []
        dom_label = rd_label(s)
    else:
        sub_labels, dom_label = labels, ""
    toks = []
    for lab in sub_labels:
        for t in _split_tokens(lab):
            toks.append("sub:" + t)
    for t in _split_tokens(dom_label):
        toks.append("dom:" + t)
    for t in _split_tokens(path):
        toks.append("path:" + t)
    for t in _split_tokens(query):
        toks.append("query:" + t)
    return toks


def f2_doc(url):
    # tra ve chuoi token cach nhau bang khoang trang, de TF-IDF tach bang token_pattern.
    return " ".join(f2_tokens(url))


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
        # Nếu lấy được WHOIS, thường là domain rác/mới đăng ký chưa cập nhật
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
        dist = _lev_dist(ext.domain, brand)
        if dist < min_dist:
            min_dist = dist
            matched_brand = brand

    if 0 < min_dist <= 2:
        insights['impersonation_risk'] = f"High (Similar to {matched_brand.capitalize()})"

    return insights
