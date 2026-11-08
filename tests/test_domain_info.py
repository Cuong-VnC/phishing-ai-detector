"""Unit test cho backend/src/domain_info.py.

Chạy:  .venv/bin/python tests/test_domain_info.py
- Các ca DNS dùng resolver GIẢ (mock) để kiểm chứng đúng logic NXDOMAIN /
  resolved / no_answer / timeout — vì DNS hệ thống trong sandbox này là
  sinkhole wildcard (mọi host đều phân giải được) nên không test NXDOMAIN
  bằng DNS thật được ở đây; trên Render (resolver thật) logic này dùng
  cùng code path với mock.
- Các ca TLS/HTTP dùng mạng thật qua proxy egress (google.com).
- WHOIS: cổng 43 bị chặn trong sandbox -> kỳ vọng fail-soft "unknown",
  không raise, không treo (deadline chung 6s).
"""
import sys
import time

sys.path.insert(0, "backend/src")

import dns.exception
import dns.resolver

import domain_info as di

PASS = []
FAIL = []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f" | {extra}" if extra else ""))


class _Rdata:
    def __init__(self, text):
        self._t = text

    def to_text(self):
        return self._t


class FakeResolver:
    """resolver giả: behavior dict {(host, rtype): 'A:1.2.3.4' | 'NXDOMAIN' | 'NoAnswer' | 'Timeout'}"""

    def __init__(self, behavior):
        self.behavior = behavior
        self.timeout = 3
        self.lifetime = 3

    def resolve(self, host, rtype):
        # Chuẩn hóa host về str không dấu chấm cuối (dnspython thật trả
        # dns.name.Name cho reversename, str(Name) có dấu chấm cuối).
        action = self.behavior.get((str(host).rstrip("."), rtype), "NoAnswer")
        if action == "NXDOMAIN":
            raise dns.resolver.NXDOMAIN()
        if action == "NoAnswer":
            raise dns.resolver.NoAnswer()
        if action == "Timeout":
            raise dns.exception.Timeout()
        return [_Rdata(x) for x in action.split(",")]


EMPTY = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], "cname": [],
         "soa": None, "ptr": [], "spf": None, "dmarc": None,
         "dnssec": {"enabled": False, "ds": False, "dnskey": False}}

# 1. NXDOMAIN -> nonexistent
r = FakeResolver({("no-such-domain-xyz123.com", "A"): "NXDOMAIN"})
status, rec = di.resolve_dns("no-such-domain-xyz123.com", resolver=r)
check("DNS NXDOMAIN -> status nxdomain", status == "nxdomain", status)
check("DNS NXDOMAIN -> records rong", rec == EMPTY)

# 2. Resolved -> records day du
r = FakeResolver({
    ("www.google.com", "A"): "142.250.80.4",
    ("www.google.com", "AAAA"): "2a00:1450:4001:81c::2004",
    ("www.google.com", "MX"): "10 smtp.google.com.",
    ("www.google.com", "NS"): "ns1.google.com.",
    ("www.google.com", "TXT"): "v=spf1 -all",
    ("google.com", "SOA"): "ns1.google.com. dns-admin.google.com. 123456 900 900 1800 60",
    ("4.80.250.142.in-addr.arpa", "PTR"): "fra24s12-in-f4.1e100.net.",
    ("_dmarc.google.com", "TXT"): "v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com",
    ("google.com", "DS"): "12345 8 2 49E2B5A1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7",
})
status, rec = di.resolve_dns("www.google.com", resolver=r)
check("DNS resolved -> status resolved", status == "resolved", status)
check("DNS resolved -> A record", rec["a"] == ["142.250.80.4"], str(rec["a"]))
check("DNS resolved -> MX/NS/TXT", rec["mx"] and rec["ns"] and rec["txt"], str(rec))
check("DNS resolved -> SOA nameserver chinh + serial",
      (rec["soa"] or {}).get("primary_ns") == "ns1.google.com" and (rec["soa"] or {}).get("serial") == "123456",
      str(rec.get("soa")))
check("DNS resolved -> PTR reverse DNS", rec["ptr"] == ["fra24s12-in-f4.1e100.net"], str(rec.get("ptr")))
check("DNS resolved -> SPF trich tu TXT", rec.get("spf") == "v=spf1 -all", str(rec.get("spf")))
check("DNS resolved -> DMARC policy reject", (rec.get("dmarc") or {}).get("policy") == "reject",
      str(rec.get("dmarc")))
check("DNS resolved -> DNSSEC enabled (co DS)", (rec.get("dnssec") or {}).get("enabled") is True,
      str(rec.get("dnssec")))
check("DNS resolved -> CNAME rong khi khong co", rec.get("cname") == [], str(rec.get("cname")))

# 2b. Parser phu: SOA / DMARC / thuat toan ky tu DER
check("_parse_soa dung", di._parse_soa("ns1.example.com. hostmaster.example.com. 2026110801 7200 3600 1209600 300") == {
    "primary_ns": "ns1.example.com", "serial": "2026110801",
    "raw": "ns1.example.com. hostmaster.example.com. 2026110801 7200 3600 1209600 300"})
check("_parse_soa rong -> None", di._parse_soa("") is None)
check("_parse_dmarc p=quarantine", (di._parse_dmarc("v=DMARC1; p=quarantine; rua=mailto:x@y") or {}).get("policy") == "quarantine")
check("_parse_dmarc khong co p -> policy None", (di._parse_dmarc("v=DMARC1; rua=mailto:x@y") or {}).get("policy") is None)
check("_parse_dmarc rong -> None", di._parse_dmarc("") is None)
try:
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID as _NameOID
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    _key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _subject = _issuer = _x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, "test.example")])
    import datetime as _dt
    _cert = (_x509.CertificateBuilder().subject_name(_subject).issuer_name(_issuer)
             .public_key(_key.public_key()).serial_number(_x509.random_serial_number())
             .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
             .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
             .sign(_key, _hashes.SHA256()))
    _der = _cert.public_bytes(__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER)
    check("_sig_alg_from_der doc OID sha256+RSA",
          di._sig_alg_from_der(_der) == "sha256WithRSAEncryption", str(di._sig_alg_from_der(_der)))
    check("_cert_sig_alg dung cryptography neu co",
          di._cert_sig_alg(_der) == "sha256WithRSAEncryption", str(di._cert_sig_alg(_der)))
    check("_sig_alg_from_der DER rac -> None", di._sig_alg_from_der(b"\x30\x03\x02\x01\x05") is None)
except ImportError:
    print("SKIP: cryptography khong co, bo qua test chu ky DER")

# 2c. _ip_geo voi requests gia
class _FakeResp:
    def __init__(self, payload):
        self._p = payload
    def json(self):
        return self._p


_real_get = di.requests.get
try:
    di.requests.get = lambda url, **kw: _FakeResp({"status": "success", "country": "United States",
        "regionName": "California", "city": "Mountain View", "isp": "Google LLC",
        "org": "Google LLC", "as": "AS15169 Google LLC", "query": "142.250.80.4"})
    geo = di._ip_geo("142.250.80.4")
    check("_ip_geo tra dung truong", geo == {"country": "United States", "region": "California",
          "city": "Mountain View", "isp": "Google LLC", "org": "Google LLC", "asn": "AS15169 Google LLC"},
          str(geo))
    di.requests.get = lambda url, **kw: _FakeResp({"status": "fail", "message": "reserved range"})
    check("_ip_geo fail -> None", di._ip_geo("127.0.0.1") is None)
    def _boom(url, **kw):
        raise ConnectionError("no network")
    di.requests.get = _boom
    check("_ip_geo loi mang -> None", di._ip_geo("8.8.8.8") is None)
finally:
    di.requests.get = _real_get

# 3. NoAnswer cho A/AAAA -> no_answer
r = FakeResolver({})
status, rec = di.resolve_dns("example.com", resolver=r)
check("DNS NoAnswer -> status no_answer", status == "no_answer", status)

# 4. Timeout -> timeout
r = FakeResolver({("example.com", "A"): "Timeout"})
status, rec = di.resolve_dns("example.com", resolver=r)
check("DNS Timeout -> status timeout", status == "timeout", status)

# 5. check_domain_existence
r = FakeResolver({("no-such-domain-xyz123.com", "A"): "NXDOMAIN"})
check("existence NXDOMAIN -> nonexistent",
      di.check_domain_existence("no-such-domain-xyz123.com", resolver=r) == "nonexistent")
r = FakeResolver({("www.google.com", "A"): "142.250.80.4"})
check("existence resolved -> exists",
      di.check_domain_existence("www.google.com", resolver=r) == "exists")
check("existence IP host -> exists",
      di.check_domain_existence("8.8.8.8") == "exists")

# 6. get_domain_info voi DNS gia NXDOMAIN -> nonexistent, khong chay HTTP/TLS/WHOIS lau
t0 = time.time()
info = di.get_domain_info("https://no-such-domain-xyz123.com/",
                          dns_result=("nxdomain", dict(EMPTY)))
dt = time.time() - t0
check("domain_info NXDOMAIN -> status nonexistent", info["status"] == "nonexistent", info["status"])
check("domain_info NXDOMAIN -> reachable False", info["reachable"] is False)
check("domain_info NXDOMAIN -> nhanh (<10s)", dt < 10, f"{dt:.1f}s")

# 7. get_domain_info voi DNS gia resolved + HTTP that qua proxy (google.com)
t0 = time.time()
info = di.get_domain_info(
    "https://www.google.com/",
    dns_result=("resolved", {"a": ["142.250.80.4"], "aaaa": [], "mx": [], "ns": [], "txt": []}))
dt = time.time() - t0
check("domain_info google -> status active", info["status"] == "active", info["status"])
check("domain_info google -> http reachable", info["http"].get("reachable") is True,
      str(info["http"].get("status_code")))
check("domain_info google -> http 200", info["http"].get("status_code") == 200,
      str(info["http"].get("status_code")))
check("domain_info google -> http co content_length (int hoac None)",
      info["http"].get("content_length") is None or isinstance(info["http"].get("content_length"), int),
      str(info["http"].get("content_length")))
check("domain_info google -> http redirect_count 0", info["http"].get("redirect_count") == 0,
      str(info["http"].get("redirect_count")))
check("domain_info google -> http resolved_ip = A record",
      info["http"].get("resolved_ip") == "142.250.80.4", str(info["http"].get("resolved_ip")))
check("domain_info google -> http ip_info dict hoac None (fail-soft)",
      info["http"].get("ip_info") is None or isinstance(info["http"].get("ip_info"), dict),
      str(info["http"].get("ip_info")))
check("domain_info google -> tong thoi gian < 15s", dt < 15, f"{dt:.1f}s")

# 7b. WHOIS voi whois gia (kiem tra truong moi updated / name_servers / domain_status)
class _FakeWhois:
    creation_date = "1997-09-15"
    expiration_date = "2028-09-14"
    updated_date = "2024-09-09"
    registrar = "MarkMonitor Inc."
    name_servers = ["NS1.GOOGLE.COM", "ns2.google.com", "ns1.google.com"]
    status = ["clientTransferProhibited", "clientUpdateProhibited"]


_real_whois = di.whois.whois
try:
    di.whois.whois = lambda domain: _FakeWhois()
    w2 = di.whois_lookup("google.com")
    check("whois gia -> updated", w2.get("updated") == "2024-09-09", str(w2.get("updated")))
    check("whois gia -> name_servers lowercase, dedupe",
          w2.get("name_servers") == ["ns1.google.com", "ns2.google.com"], str(w2.get("name_servers")))
    check("whois gia -> domain_status list",
          w2.get("domain_status") == ["clientTransferProhibited", "clientUpdateProhibited"],
          str(w2.get("domain_status")))
    check("whois gia -> age_days tinh dung", isinstance(w2.get("age_days"), int) and w2["age_days"] > 10000,
          str(w2.get("age_days")))
finally:
    di.whois.whois = _real_whois

# 8. TLS that (google.com) — trong sandbox ket noi truc tiep 443 co the bi chan:
#    chi kiem tra fail-soft (khong raise, tra ve dict day du key).
t0 = time.time()
tls = di.tls_info("www.google.com")
dt = time.time() - t0
check("tls_info khong raise, du key", set(tls) >= {"checked", "valid", "issuer", "expires", "days_left",
      "sans", "sig_alg", "tls_version", "cipher", "cipher_bits"},
      f"checked={tls['checked']} valid={tls['valid']} err={tls.get('error')}")
check("tls_info nhanh (<8s)", dt < 8, f"{dt:.1f}s")

# 9. HTTP toi host khong phan hoi (port 81 google) -> inactive path
http = di.http_check("https://www.google.com:81/")
check("http_check port 81 -> unreachable", http.get("reachable") is False, str(http.get("error")))

# 10. WHOIS fail-soft (cong 43 bi chan trong sandbox): khong raise, nhanh
t0 = time.time()
w = di.whois_lookup("google.com")
dt = time.time() - t0
check("whois_lookup khong raise, co key day du",
      set(w) >= {"status", "created", "expires", "updated", "registrar", "age_days",
                 "name_servers", "domain_status"}, str(w.get("status")))
check("whois_lookup khong treo (<10s)", dt < 10, f"{dt:.1f}s")

print(f"\n== {len(PASS)} PASS, {len(FAIL)} FAIL ==")
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
