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
import dns.reversename
import requests
import tldextract
import whois

DNS_TIMEOUT = 3.0
WHOIS_TIMEOUT = 4.0
TLS_TIMEOUT = 4.0
HTTP_TIMEOUT = 4.0
IP_API_TIMEOUT = 4.0
IP_API_URL = ("http://ip-api.com/json/{ip}"
              "?fields=status,country,regionName,city,isp,org,as,query")
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


def _registered_domain(host):
    """Tên miền đăng ký (vd www.google.com -> google.com), dùng cho SOA/DMARC/DNSSEC."""
    ext = tldextract.extract(host or "")
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else (host or "")


def _parse_soa(text):
    """SOA rdata: 'mname rname serial refresh retry expire minimum' -> dict."""
    parts = (text or "").split()
    if not parts:
        return None
    return {"primary_ns": parts[0].rstrip("."),
            "serial": parts[2] if len(parts) > 2 else None,
            "raw": text}


def _parse_dmarc(text):
    """Bản ghi DMARC (v=DMARC1; p=...) -> {'record': ..., 'policy': ...}."""
    if not text:
        return None
    m = re.search(r"\bp\s*=\s*(none|quarantine|reject)\b", text, re.IGNORECASE)
    return {"record": text[:300], "policy": m.group(1).lower() if m else None}


_SIG_ALG_OIDS = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}


def _read_tlv(buf, pos):
    """Đọc 1 thẻ DER tại pos -> (tag, vị trí bắt đầu nội dung, độ dài nội dung)."""
    tag = buf[pos]
    pos += 1
    if tag & 0x1F == 0x1F:  # tag nhiều byte (không gặp ở đây, vẫn xử lý cho đủ)
        while buf[pos] & 0x80:
            pos += 1
        pos += 1
    ln = buf[pos]
    pos += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    return tag, pos, ln


def _sig_alg_from_der(der):
    """Thuật toán ký từ chứng chỉ DER (không cần thư viện ngoài).

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    -> bỏ qua tbsCertificate, đọc OID đầu tiên trong signatureAlgorithm.
    """
    try:
        _, p, _ = _read_tlv(der, 0)          # SEQUENCE ngoài
        _, p2, l2 = _read_tlv(der, p)        # tbsCertificate
        p = p2 + l2                          # bỏ qua tbsCertificate
        _, p3, _ = _read_tlv(der, p)         # signatureAlgorithm SEQUENCE
        _, p4, l4 = _read_tlv(der, p3)       # OID
        raw = der[p4:p4 + l4]
        if not raw:
            return None
        parts = [raw[0] // 40, raw[0] % 40]
        val = 0
        for b in raw[1:]:
            val = (val << 7) | (b & 0x7F)
            if not (b & 0x80):
                parts.append(val)
                val = 0
        oid = ".".join(str(x) for x in parts)
        return _SIG_ALG_OIDS.get(oid, f"OID {oid}")
    except Exception:
        return None


def _cert_sig_alg(der):
    """Thuật toán ký của chứng chỉ DER: thử `cryptography` trước, không có thì
    dùng bộ giải DER tối giản ở trên (stdlib thuần). Luôn fail-soft."""
    if not der:
        return None
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        return cert.signature_algorithm_oid._name
    except ImportError:
        return _sig_alg_from_der(der)
    except Exception:
        return None


def _ip_geo(ip):
    """Geo/ASN/ISP của 1 IP qua ip-api.com (miễn phí, không cần key).
    Trả dict {'country','region','city','isp','org','asn'} hoặc None (fail-soft)."""
    if not ip:
        return None
    try:
        r = requests.get(IP_API_URL.format(ip=ip), headers=_UA, timeout=IP_API_TIMEOUT)
        data = r.json()
        if data.get("status") == "success":
            return {"country": data.get("country"), "region": data.get("regionName"),
                    "city": data.get("city"), "isp": data.get("isp"),
                    "org": data.get("org"), "asn": data.get("as")}
    except Exception:
        pass
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
      records: {"a", "aaaa", "mx", "ns", "txt", "cname", "soa", "ptr", "spf",
                "dmarc", "dnssec"} — "soa" là dict {primary_ns, serial, raw} hoặc
      None; "dmarc" là dict {record, policy} hoặc None; "dnssec" là dict
      {enabled, ds, dnskey}; "spf" là chuỗi bản ghi SPF hoặc None.
    `resolver` có thể truyền vào (dùng cho unit test); mặc định dùng resolver hệ thống.
    Các tra cứu mở rộng (CNAME/SOA/PTR/SPF/DMARC/DNSSEC) dùng lifetime 1s vì
    chỉ phục vụ hiển thị, không chặn kết luận về tên miền.
    """
    records = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], "cname": [],
               "soa": None, "ptr": [], "spf": None, "dmarc": None,
               "dnssec": {"enabled": False, "ds": False, "dnskey": False}}
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
        # --- Tra cứu mở rộng (chỉ hiển thị; lifetime 1s, lỗi -> giá trị rỗng) ---
        reg = _registered_domain(host)
        old_lifetime = getattr(resolver, "lifetime", None)
        try:
            resolver.lifetime = 1.0
            records["cname"] = _query(resolver, host, "CNAME")[:3]
            soa_raw = _query(resolver, reg, "SOA")
            records["soa"] = _parse_soa(soa_raw[0]) if soa_raw else None
            first_ip = a[0] if a else (aaaa[0] if aaaa else None)
            if first_ip:
                try:
                    rev = dns.reversename.from_address(first_ip)
                    records["ptr"] = [p.rstrip(".") for p in _query(resolver, rev, "PTR")[:2]]
                except Exception:
                    records["ptr"] = []
            txt_full = _query(resolver, host, "TXT")[:5]
            records["spf"] = next(
                (t for t in txt_full if t.strip().lower().startswith("v=spf1")), None)
            dmarc_raw = _query(resolver, "_dmarc." + reg, "TXT")
            records["dmarc"] = _parse_dmarc(dmarc_raw[0]) if dmarc_raw else None
            ds = _query(resolver, reg, "DS")
            dnskey = _query(resolver, reg, "DNSKEY")
            records["dnssec"] = {"enabled": bool(ds or dnskey),
                                 "ds": bool(ds), "dnskey": bool(dnskey)}
        finally:
            if old_lifetime is not None:
                resolver.lifetime = old_lifetime
        return "resolved", records
    except dns.resolver.NXDOMAIN:
        return "nxdomain", records
    except (dns.resolver.Timeout, dns.exception.Timeout):
        return "timeout", records
    except Exception:
        return "error", records


def whois_lookup(domain):
    """WHOIS: ngày tạo / cập nhật / hết hạn / registrar / tuổi domain (ngày) /
    nameservers / trạng thái WHOIS."""
    out = {"status": "unknown", "created": None, "expires": None, "updated": None,
           "registrar": None, "age_days": None, "name_servers": None,
           "domain_status": None}
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
        out["updated"] = _fmt_date(getattr(w, "updated_date", None))
        out["registrar"] = str(registrar)[:120] if registrar else None
        ns = getattr(w, "name_servers", None)
        if isinstance(ns, str):
            ns = [ns]
        if ns:
            seen = []
            for x in ns:
                s = str(x).strip().lower().rstrip(".")
                if s and s not in seen:
                    seen.append(s)
            out["name_servers"] = seen[:5] or None
        st = getattr(w, "status", None)
        if isinstance(st, str):
            st = [st]
        if st:
            out["domain_status"] = [str(x).strip()[:80] for x in st if x][:5] or None
        if created:
            out["age_days"] = max(0, (datetime.now(timezone.utc) - created).days)
            out["status"] = "ok"
        elif out["registrar"] or out["expires"]:
            out["status"] = "ok"
    except Exception:
        pass
    return out


def tls_info(host, port=443):
    """Chứng chỉ TLS: hợp lệ không, issuer, ngày hết hạn, số ngày còn lại,
    SANs, thuật toán ký, TLS version và cipher đã thỏa thuận."""
    out = {"checked": False, "valid": None, "issuer": None, "subject": None,
           "expires": None, "days_left": None, "error": None, "sans": None,
           "sig_alg": None, "tls_version": None, "cipher": None,
           "cipher_bits": None}
    if not host or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        out["error"] = "IP host, skip TLS check"
        return out
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True)
                out["tls_version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    out["cipher"] = cipher[0]
                    out["cipher_bits"] = cipher[2] if len(cipher) > 2 else None
        out["checked"] = True

        def _name(field):
            parts = dict((k, v) for item in cert.get(field, []) for k, v in item)
            return parts.get("organizationName") or parts.get("commonName")

        out["issuer"] = _name("issuer")
        out["subject"] = _name("subject")
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        out["sans"] = sans[:10] if sans else None
        out["sig_alg"] = _cert_sig_alg(der)
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
           "content_length": None, "redirect_count": 0,
           "resolved_ip": None, "ip_info": None,
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
            _cl = resp.headers.get("content-length")
            try:
                out["content_length"] = int(_cl) if _cl is not None else None
            except (TypeError, ValueError):
                out["content_length"] = None
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
    finally:
        # Luôn đếm đủ số lần chuyển hướng, kể cả các đường return sớm ở trên.
        out["redirect_count"] = len(out["redirects"])
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
                                       "expires": None, "updated": None,
                                       "registrar": None, "age_days": None,
                                       "name_servers": None, "domain_status": None})
        tls_out = _collect("tls", {"checked": False, "valid": None, "issuer": None,
                                   "subject": None, "expires": None, "days_left": None,
                                   "error": "timeout", "sans": None, "sig_alg": None,
                                   "tls_version": None, "cipher": None,
                                   "cipher_bits": None})
        http_out = _collect("http", {"reachable": None, "status_code": None, "final_url": None,
                                     "redirects": [], "server": None, "content_type": None,
                                     "content_length": None, "redirect_count": 0,
                                     "resolved_ip": None, "ip_info": None,
                                     "response_time_ms": None, "error": "timeout"})
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    # IP đã phân giải + geo/ASN/ISP (ip-api.com, fail-soft, timeout 4s).
    resolved_ip = None
    if is_ip:
        resolved_ip = host
    elif dns_records.get("a"):
        resolved_ip = dns_records["a"][0]
    else:
        final_host = (urlparse(http_out.get("final_url") or str(url)).hostname or "")
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", final_host or ""):
            resolved_ip = final_host
        elif final_host and ":" not in final_host:
            try:
                rslv = resolver or dns.resolver.Resolver()
                rslv.timeout = 2.0
                rslv.lifetime = 2.0
                _a = _query(rslv, final_host, "A")
                if _a:
                    resolved_ip = _a[0]
            except Exception:
                pass
    http_out["resolved_ip"] = resolved_ip
    http_out["redirect_count"] = len(http_out.get("redirects") or [])
    http_out["ip_info"] = _ip_geo(resolved_ip) if resolved_ip else None

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
