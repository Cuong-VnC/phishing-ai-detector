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
        action = self.behavior.get((host, rtype), "NoAnswer")
        if action == "NXDOMAIN":
            raise dns.resolver.NXDOMAIN()
        if action == "NoAnswer":
            raise dns.resolver.NoAnswer()
        if action == "Timeout":
            raise dns.exception.Timeout()
        return [_Rdata(x) for x in action.split(",")]


EMPTY = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": []}

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
})
status, rec = di.resolve_dns("www.google.com", resolver=r)
check("DNS resolved -> status resolved", status == "resolved", status)
check("DNS resolved -> A record", rec["a"] == ["142.250.80.4"], str(rec["a"]))
check("DNS resolved -> MX/NS/TXT", rec["mx"] and rec["ns"] and rec["txt"], str(rec))

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
check("domain_info google -> tong thoi gian < 15s", dt < 15, f"{dt:.1f}s")

# 8. TLS that (google.com) — trong sandbox ket noi truc tiep 443 co the bi chan:
#    chi kiem tra fail-soft (khong raise, tra ve dict day du key).
t0 = time.time()
tls = di.tls_info("www.google.com")
dt = time.time() - t0
check("tls_info khong raise, du key", set(tls) >= {"checked", "valid", "issuer", "expires", "days_left"},
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
      set(w) >= {"status", "created", "expires", "registrar", "age_days"}, str(w.get("status")))
check("whois_lookup khong treo (<10s)", dt < 10, f"{dt:.1f}s")

print(f"\n== {len(PASS)} PASS, {len(FAIL)} FAIL ==")
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
