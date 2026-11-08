"""Tra cứu thông tin tên miền cho ScamShield (DNS / WHOIS / TLS / HTTP).

Mọi hàm đều fail-soft: timeout ngắn (3-5 giây), tra cứu nào lỗi thì trả
"unknown" cho mục đó, KHÔNG bao giờ raise lên tầng gọi. Module này không
chạm vào model hay thứ tự đặc trưng — chỉ bổ sung thông tin hiển thị và
logic "tên miền không tồn tại / không hoạt động" cho /predict.
"""
import ipaddress
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import dns.exception
import dns.resolver
import requests
import tldextract
import whois

DNS_TIMEOUT = 3.0
WHOIS_TIMEOUT = 4.0
TLS_TIMEOUT = 4.0
HTTP_TIMEOUT = 4.0
MAX_REDIRECTS = 5
OVERALL_TIMEOUT = 6.0

# IP nội bộ / đặc biệt: chặn SSRF khi theo redirect (chỉ chặn các dải nội bộ
# thật sự; không chặn 198.18.0.0/15 (benchmark/CGNAT) vì đó không phải mạng nội bộ).
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_UA = {"User-Agent": "Mozilla/5.0 (ScamShield-AI domain check)"}


def _is_public_ip(ip_str: str) -> bool:
    """True nếu IP không nằm trong các dải nội bộ/đặc biệt ở trên."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return False
    return not any(ip in net for net in _BLOCKED_NETWORKS)


def _is_public_host(host: str) -> bool:
    """Hostname có phân giải ra IP công khai không (dùng cho redirect)."""
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return False
    return _is_public_ip(ip)


def _fmt_date(value):
    """Chuẩn hóa ngày WHOIS (datetime / chuỗi / list) về 'YYYY-MM-DD' hoặc None."""
    if value is None:
        return None
    if isinstance(value, list):
        value = next((v for v in value if v), None)
        if value is None:
            return None
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, str):
        m = re.search(r"(\d{4}-\d{2}-\d{2})", value)
        return m.group(1) if m else None
    return None


def _parse_date(value):
    """Như _fmt_date nhưng trả datetime (aware UTC) để tính tuổi domain."""
    if value is None:
        return None
    if isinstance(value, list):
        value = next((v for v in value if v), None)
        if value is None:
            return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        m = re.search(r"(\d{4}-\d{2}-\d{2})", value)
        if m:
            return datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc)
    return None


def _query(resolver, host, rtype):
    """Truy vấn 1 loại bản ghi, trả list chuỗi (rỗng nếu lỗi/không có)."""
    try:
        ans = resolver.resolve(host, rtype)
        out = []
        for r in ans:
            txt = r.to_text().strip().strip('"')
            if txt:
                out.append(txt)
        return out
    except Exception:
        return []


def resolve_dns(host, resolver=None):
    """Phân giải DNS qua dnspython (resolver hệ thống).

    Trả về (status, records):
      status: resolved | nxdomain | no_answer | timeout | error | skipped_ip
      records: {"a": [...], "aaaa": [...], "mx": [...], "ns": [...], "txt": [...]}
    `resolver` có thể truyền vào (dùng cho unit test); mặc định dùng resolver hệ thống.
    """
    records = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": []}
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host) or ":" in host:
        return "skipped_ip", records
    if resolver is None:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
    try:
        a = _query(resolver, host, "A")
        aaaa = _query(resolver, host, "AAAA")
        if not a and not aaaa:
            # Phân biệt "domain không tồn tại" với "domain có nhưng không có bản ghi A/AAAA":
            # truy vấn lại để xem resolver báo NXDOMAIN hay NoAnswer.
            try:
                resolver.resolve(host, "A")
            except dns.resolver.NXDOMAIN:
                return "nxdomain", records
            except dns.resolver.NoAnswer:
                return "no_answer", records
            except (dns.resolver.Timeout, dns.exception.Timeout):
                return "timeout", records
            except Exception:
                return "no_answer", records
            return "no_answer", records
        records["a"] = a
        records["aaaa"] = aaaa
        records["mx"] = _query(resolver, host, "MX")[:5]
        records["ns"] = _query(resolver, host, "NS")[:5]
        records["txt"] = [t[:200] for t in _query(resolver, host, "TXT")[:3]]
        return "resolved", records
    except dns.resolver.NXDOMAIN:
        return "nxdomain", records
    except (dns.resolver.Timeout, dns.exception.Timeout):
        return "timeout", records
    except Exception:
        return "error", records


def whois_lookup(domain):
    """WHOIS: ngày tạo / hết hạn / registrar / tuổi domain (ngày)."""
    out = {"status": "unknown", "created": None, "expires": None,
           "registrar": None, "age_days": None}
    if not domain or "." not in domain:
        return out
    try:
        w = whois.whois(domain)
        created = _parse_date(getattr(w, "creation_date", None))
        expires = _parse_date(getattr(w, "expiration_date", None))
        registrar = getattr(w, "registrar", None)
        if isinstance(registrar, list):
            registrar = next((r for r in registrar if r), None)
        out["created"] = _fmt_date(getattr(w, "creation_date", None))
        out["expires"] = _fmt_date(getattr(w, "expiration_date", None))
        out["registrar"] = str(registrar)[:120] if registrar else None
        if created:
            out["age_days"] = max(0, (datetime.now(timezone.utc) - created).days)
            out["status"] = "ok"
        elif out["registrar"] or out["expires"]:
            out["status"] = "ok"
    except Exception:
        pass
    return out


def tls_info(host, port=443):
    """Chứng chỉ TLS: hợp lệ không, issuer, ngày hết hạn, số ngày còn lại."""
    out = {"checked": False, "valid": None, "issuer": None, "subject": None,
           "expires": None, "days_left": None, "error": None}
    if not host or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        out["error"] = "IP host, skip TLS check"
        return out
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        out["checked"] = True

        def _name(field):
            parts = dict((k, v) for item in cert.get(field, []) for k, v in item)
            return parts.get("organizationName") or parts.get("commonName")

        out["issuer"] = _name("issuer")
        out["subject"] = _name("subject")
        exp = cert.get("notAfter")
        if exp:
            dt = datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            out["expires"] = dt.date().isoformat()
            out["days_left"] = (dt - datetime.now(timezone.utc)).days
            out["valid"] = out["days_left"] >= 0
        else:
            out["valid"] = True
    except ssl.SSLCertVerificationError as e:
        out["checked"] = True
        out["valid"] = False
        out["error"] = f"certificate verify failed: {e.verify_message or e}"
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"[:200]
    return out


def http_check(url):
    """HTTP(S): status, redirect chain (tự theo tối đa 5, chặn redirect về IP nội bộ),
    server header, thời gian phản hồi. Không đọc body."""
    out = {"reachable": None, "status_code": None, "final_url": None,
           "redirects": [], "server": None, "content_type": None,
           "response_time_ms": None, "error": None}
    current = url
    t0 = time.time()
    try:
        for _ in range(MAX_REDIRECTS + 1):
            try:
                resp = requests.get(current, headers=_UA, timeout=HTTP_TIMEOUT,
                                    allow_redirects=False, stream=True)
            except requests.exceptions.Timeout:
                out["error"] = "timeout"
                out["reachable"] = False
                return out
            except requests.exceptions.SSLError as e:
                out["error"] = f"TLS error: {e}"[:200]
                out["reachable"] = False
                return out
            except requests.exceptions.RequestException as e:
                out["error"] = f"{type(e).__name__}: {e}"[:200]
                out["reachable"] = False
                return out
            try:
                resp.close()
            except Exception:
                pass
            out["status_code"] = resp.status_code
            out["final_url"] = resp.url
            out["server"] = (resp.headers.get("server") or "")[:120] or None
            out["content_type"] = (resp.headers.get("content-type") or "").split(";")[0][:80] or None
            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location")
                if not loc:
                    break
                nxt = urljoin(current, loc)
                parsed = urlparse(nxt)
                if parsed.scheme not in ("http", "https") or not parsed.hostname:
                    out["error"] = "redirect to non-http URL"
                    out["reachable"] = False
                    return out
                if not _is_public_host(parsed.hostname):
                    out["error"] = "redirect to private/internal host (blocked)"
                    out["reachable"] = False
                    return out
                out["redirects"].append(nxt)
                current = nxt
                continue
            break
        else:
            out["error"] = "too many redirects"
            out["reachable"] = False
            return out
        out["reachable"] = out["status_code"] is not None and out["status_code"] < 500
        out["response_time_ms"] = int((time.time() - t0) * 1000)
    except Exception as e:  # fail-soft tuyệt đối
        out["error"] = f"{type(e).__name__}: {e}"[:200]
        out["reachable"] = False
    return out


def get_domain_info(url, dns_result=None, resolver=None):
    """Tổng hợp DNS + WHOIS + TLS + HTTP cho 1 URL (chạy song song, deadline chung).

    Trả về dict có các key: domain, host, is_ip_host, dns, whois, tls, http,
    status ("active" | "inactive" | "nonexistent" | "unknown"), reachable.
    `dns_result` (tuple từ resolve_dns) có thể truyền vào để khỏi tra lại.
    """
    parsed = urlparse(str(url))
    host = (parsed.hostname or "").lower()
    ext = tldextract.extract(str(url))
    domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host
    is_ip = bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host)) or ":" in host

    if dns_result is not None:
        dns_status, dns_records = dns_result
    else:
        dns_status, dns_records = resolve_dns(host, resolver=resolver)

    tasks = {}
    deadline = time.time() + OVERALL_TIMEOUT
    # Không dùng `with` (shutdown(wait=True) sẽ chờ cả thread WHOIS đang treo
    # vì python-whois không có timeout socket nội bộ) — shutdown(wait=False)
    # để request trả về đúng deadline dù thread nền còn treo.
    pool = ThreadPoolExecutor(max_workers=3)
    try:
        if not is_ip:
            tasks["whois"] = pool.submit(whois_lookup, domain)
        if parsed.scheme == "https" and not is_ip:
            tasks["tls"] = pool.submit(tls_info, host)
        tasks["http"] = pool.submit(http_check, str(url))

        def _collect(name, default):
            fut = tasks.get(name)
            if fut is None:
                return default
            try:
                # Deadline CHUNG cho cả 3 tra cứu (không cộng dồn từng cái).
                return fut.result(timeout=max(0.1, deadline - time.time()))
            except Exception:
                return default

        whois_out = _collect("whois", {"status": "unknown", "created": None,
                                       "expires": None, "registrar": None, "age_days": None})
        tls_out = _collect("tls", {"checked": False, "valid": None, "issuer": None,
                                   "subject": None, "expires": None, "days_left": None,
                                   "error": "timeout"})
        http_out = _collect("http", {"reachable": None, "status_code": None, "final_url": None,
                                     "redirects": [], "server": None, "content_type": None,
                                     "response_time_ms": None, "error": "timeout"})
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    # Kết luận tổng hợp về tên miền
    if dns_status == "nxdomain":
        status, reachable = "nonexistent", False
    elif dns_status == "no_answer":
        status, reachable = "inactive", False
    elif dns_status == "resolved" or dns_status == "skipped_ip":
        if http_out.get("reachable") is True:
            status, reachable = "active", True
        elif http_out.get("reachable") is False:
            status, reachable = "inactive", False
        else:
            status, reachable = "unknown", None
    else:  # timeout / error: DNS không kết luận được
        if http_out.get("reachable") is True:
            status, reachable = "active", True
        elif http_out.get("reachable") is False:
            status, reachable = "unknown", None
        else:
            status, reachable = "unknown", None

    return {
        "domain": domain,
        "host": host,
        "is_ip_host": is_ip,
        "dns": {"status": dns_status, **dns_records},
        "whois": whois_out,
        "tls": tls_out,
        "http": http_out,
        "status": status,
        "reachable": reachable,
    }


def check_domain_existence(host, resolver=None):
    """Kiểm tra nhanh tên miền có tồn tại không (chỉ DNS A/AAAA).

    Trả về "nonexistent" | "exists" | "unknown". Dùng cho quyết định dừng
    sớm trong /predict: NXDOMAIN -> không chạy model.
    """
    if not host or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host) or ":" in host:
        return "exists"  # host IP: không áp dụng logic DNS
    status, _ = resolve_dns(host, resolver=resolver)
    if status == "nxdomain":
        return "nonexistent"
    if status in ("resolved", "no_answer"):
        return "exists"
    return "unknown"
