"""E2E test cho POST /predict + GET /domain-info + GET /health.

Chạy:  .venv/bin/python tests/test_predict_e2e.py
Ghi chú về sandbox:
- DNS hệ thống ở đây là sinkhole wildcard (mọi host đều phân giải ra
  198.18.123.x, bị is_private chặn) nên test MOCK 2 điểm để mô phỏng Render:
  (1) socket.gethostbyname -> trả IP công khai giả theo host;
  (2) main.resolve_dns -> NXDOMAIN cho domain test không tồn tại,
  "resolved" cho các host còn lại.
- Model thật (08) được nạp và chạy thật; HTTP/TLS qua proxy egress thật.
- WHOIS cổng 43 bị chặn -> kỳ vọng whois "unknown" trong domain_info.
- Ngưỡng quyết định của model 08 là 0.45 (meta.json); các ca phishing
  mới: drive-google-share.com (vòng 2 sai, vòng 3 đã sửa) và URL homoglyph
  dạng punycode xn--vietcombank-9ya.com (Cyrillic 'а' trong vietcombank).
"""
import json
import socket
import sys

sys.path.insert(0, "backend/src")

import main as app_main
from fastapi.testclient import TestClient

# --- Mock DNS hệ thống: mô phỏng resolver thật trên Render ---
_REAL_GETHOSTBYNAME = socket.gethostbyname
_FAKE_IPS = {
    "www.google.com": "142.250.80.4",
    "google.com": "142.250.80.4",
    "vietcombank-dangnhap.com": "45.60.11.10",
    "drive-google-share.com": "104.21.33.15",
    "xn--vietcombank-9ya.com": "103.86.120.20",
    "xkqjzwv-qqqq-zzz12345.com": None,  # -> gaierror (không dùng tới vì DNS check chặn trước)
}


def _fake_gethostbyname(host):
    if host in _FAKE_IPS:
        if _FAKE_IPS[host] is None:
            raise socket.gaierror("Name or service not known")
        return _FAKE_IPS[host]
    return _REAL_GETHOSTBYNAME(host)


socket.gethostbyname = _fake_gethostbyname

# --- Mock resolve_dns trong main (dnspython hệ thống là sinkhole) ---
_REAL_RESOLVE_DNS = app_main.resolve_dns


def _fake_resolve_dns(host, resolver=None):
    base = {"cname": [], "soa": None, "ptr": [], "spf": None, "dmarc": None,
            "dnssec": {"enabled": False, "ds": False, "dnskey": False}}
    if host == "xkqjzwv-qqqq-zzz12345.com":
        return "nxdomain", {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], **base}
    if host in ("www.google.com", "google.com", "vietcombank-dangnhap.com",
                "drive-google-share.com", "xn--vietcombank-9ya.com"):
        extra = dict(base)
        if host in ("www.google.com", "google.com"):
            extra.update({
                "soa": {"primary_ns": "ns1.google.com", "serial": "123456",
                        "raw": "ns1.google.com. dns-admin.google.com. 123456 900 900 1800 60"},
                "ptr": ["fra24s12-in-f4.1e100.net"], "spf": "v=spf1 -all",
                "dmarc": {"record": "v=DMARC1; p=reject", "policy": "reject"},
                "dnssec": {"enabled": True, "ds": True, "dnskey": True},
            })
        return "resolved", {"a": [_FAKE_IPS[host]], "aaaa": [], "mx": [], "ns": [], "txt": [], **extra}
    return _REAL_RESOLVE_DNS(host, resolver=resolver)


app_main.resolve_dns = _fake_resolve_dns

client = TestClient(app_main.app, raise_server_exceptions=False)
PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f" | {extra}" if extra else ""))


def show(name, resp):
    try:
        body = resp.json()
    except Exception:
        body = resp.text[:200]
    print(f"--- {name}: HTTP {resp.status_code}")
    print(json.dumps(body, ensure_ascii=False, indent=2)[:1800])


# 0. Health
r = client.get("/health")
check("GET /health 200 + models_loaded", r.status_code == 200 and r.json().get("models_loaded") is True,
      str(r.json()))
check("GET /health threshold 0.45 (model v8)",
      isinstance(r.json().get("threshold"), (int, float))
      and abs(r.json()["threshold"] - 0.45) < 1e-9,  # meta.json luu float(best_t)=0.45000000000000007
      str(r.json().get("threshold")))

# 1. URL legit (whitelist)
r = client.post("/predict", json={"url": "https://www.google.com"})
show("legit google.com", r)
b = r.json() if r.status_code == 200 else {}
check("legit: HTTP 200", r.status_code == 200, str(r.status_code))
check("legit: status Safe", b.get("status") == "Safe", str(b.get("status")))
check("legit: du truong cu (url/status/probability/risk_level/technical_report/source)",
      all(k in b for k in ("url", "status", "probability", "risk_level", "technical_report", "source")))
check("legit: co domain_info day du key",
      isinstance(b.get("domain_info"), dict) and set(b["domain_info"]) >=
      {"domain", "host", "dns", "whois", "tls", "http", "status", "reachable"},
      str(list((b.get("domain_info") or {}).keys())))
check("legit: domain_status active", b.get("domain_status") == "active", str(b.get("domain_status")))
check("legit: http reachable trong domain_info",
      (b.get("domain_info") or {}).get("http", {}).get("reachable") is True)
check("legit: warning null", b.get("warning") is None)
check("legit: dns co truong moi (cname/soa/ptr/spf/dmarc/dnssec)",
      set((b.get("domain_info") or {}).get("dns", {})) >= {"cname", "soa", "ptr", "spf", "dmarc", "dnssec"},
      str(list((b.get("domain_info") or {}).get("dns", {}).keys())))
check("legit: dns SOA/DMARC/SPF co gia tri that",
      ((b.get("domain_info") or {}).get("dns", {}).get("soa") or {}).get("primary_ns") == "ns1.google.com"
      and ((b.get("domain_info") or {}).get("dns", {}).get("dmarc") or {}).get("policy") == "reject"
      and (b.get("domain_info") or {}).get("dns", {}).get("spf") == "v=spf1 -all")
check("legit: whois co truong moi (updated/name_servers/domain_status)",
      set((b.get("domain_info") or {}).get("whois", {})) >= {"updated", "name_servers", "domain_status"})
check("legit: tls co truong moi (sans/sig_alg/tls_version/cipher/cipher_bits)",
      set((b.get("domain_info") or {}).get("tls", {})) >= {"sans", "sig_alg", "tls_version", "cipher", "cipher_bits"})
check("legit: http co truong moi (content_type/content_length/redirect_count/resolved_ip/ip_info)",
      set((b.get("domain_info") or {}).get("http", {})) >= {"content_type", "content_length", "redirect_count", "resolved_ip", "ip_info"})
check("legit: http resolved_ip = A record",
      (b.get("domain_info") or {}).get("http", {}).get("resolved_ip") == "142.250.80.4",
      str((b.get("domain_info") or {}).get("http", {}).get("resolved_ip")))
check("legit: http redirect_count 0",
      (b.get("domain_info") or {}).get("http", {}).get("redirect_count") == 0,
      str((b.get("domain_info") or {}).get("http", {}).get("redirect_count")))
check("legit: http ip_info dict hoac None (fail-soft)",
      (b.get("domain_info") or {}).get("http", {}).get("ip_info") is None
      or isinstance((b.get("domain_info") or {}).get("http", {}).get("ip_info"), dict))

# 2. URL phishing trong benchmark
r = client.post("/predict", json={"url": "https://vietcombank-dangnhap.com/login"})
show("phishing benchmark", r)
b = r.json() if r.status_code == 200 else {}
check("phishing: HTTP 200", r.status_code == 200, str(r.status_code))
check("phishing: status Phishing", b.get("status") == "Phishing", str(b.get("status")))
check("phishing: probability > 0.5", isinstance(b.get("probability"), (int, float)) and b["probability"] > 0.5,
      str(b.get("probability")))
check("phishing: co domain_info", isinstance(b.get("domain_info"), dict))

# 2b. URL phishing giả mạo Google Drive (vòng 2 sai: prob 0.4211 < ngưỡng 0.48;
#     vòng 3 đã sửa -> phải là Phishing với ngưỡng 0.45)
r = client.post("/predict", json={"url": "https://drive-google-share.com/"})
show("phishing drive-google-share", r)
b = r.json() if r.status_code == 200 else {}
check("drive-share: HTTP 200", r.status_code == 200, str(r.status_code))
check("drive-share: status Phishing", b.get("status") == "Phishing", str(b.get("status")))
check("drive-share: probability >= 0.45", isinstance(b.get("probability"), (int, float))
      and b["probability"] >= 0.45, str(b.get("probability")))

# 2c. URL homoglyph dạng punycode: xn--vietcombank-9ya.com
#     ('vietcombаnk' với 'а' Cyrillic U+0430) -> skeleton_brand_match = 1
r = client.post("/predict", json={"url": "https://xn--vietcombank-9ya.com/login"})
show("phishing homoglyph punycode", r)
b = r.json() if r.status_code == 200 else {}
check("homoglyph: HTTP 200", r.status_code == 200, str(r.status_code))
check("homoglyph: status Phishing", b.get("status") == "Phishing", str(b.get("status")))
check("homoglyph: probability >= 0.45", isinstance(b.get("probability"), (int, float))
      and b["probability"] >= 0.45, str(b.get("probability")))

# 3. Ten mien KHONG ton tai
r = client.post("/predict", json={"url": "https://xkqjzwv-qqqq-zzz12345.com/login"})
show("nonexistent domain", r)
b = r.json() if r.status_code == 200 else {}
check("nonexistent: HTTP 200 (khong phai 400/500)", r.status_code == 200, str(r.status_code))
check("nonexistent: status DomainNotFound", b.get("status") == "DomainNotFound", str(b.get("status")))
check("nonexistent: domain_status nonexistent", b.get("domain_status") == "nonexistent",
      str(b.get("domain_status")))
check("nonexistent: co message ro rang", bool(b.get("message")) and "không tồn tại" in b.get("message", ""),
      str(b.get("message")))
check("nonexistent: probability null", b.get("probability") is None)

# 4. URL sai dinh dang
for bad in ["not a url", "htp:/bad", "google"]:
    r = client.post("/predict", json={"url": bad})
    show(f"malformed {bad!r}", r)
    b = r.json() if r.status_code in (200, 400) else {}
    check(f"malformed {bad!r}: HTTP 400", r.status_code == 400, str(r.status_code))
    check(f"malformed {bad!r}: detail tieng Viet ro rang",
          "không đúng định dạng" in str(b.get("detail", "")), str(b.get("detail")))

# 5. Ten mien khong hoat dong (DNS co, HTTP port 81 khong phan hoi)
r = client.post("/predict", json={"url": "https://www.google.com:81/"})
show("inactive google:81", r)
b = r.json() if r.status_code == 200 else {}
check("inactive: HTTP 200", r.status_code == 200, str(r.status_code))
check("inactive: domain_status inactive", b.get("domain_status") == "inactive",
      str(b.get("domain_status")))
check("inactive: co warning", bool(b.get("warning")), str(b.get("warning")))
check("inactive: van co ket qua model (status Safe vi whitelist)",
      b.get("status") == "Safe", str(b.get("status")))

# 6. GET /domain-info
r = client.get("/domain-info", params={"url": "https://www.google.com"})
show("GET /domain-info", r)
b = r.json() if r.status_code == 200 else {}
check("domain-info: HTTP 200", r.status_code == 200, str(r.status_code))
check("domain-info: co domain_info day du",
      isinstance(b.get("domain_info"), dict) and b["domain_info"].get("domain") == "google.com",
      str((b.get("domain_info") or {}).get("domain")))

print(f"\n== {len(PASS)} PASS, {len(FAIL)} FAIL ==")
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
