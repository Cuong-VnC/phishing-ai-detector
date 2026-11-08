/* Smoke test frontend ScamShield trong jsdom (khong can trinh duyet that).
   - Nap index.html that + script.js that.
   - Stub lucide (CDN) va fetch (tra ve payload /health + /predict gia).
   - Kiem tra: khoi tao khong loi, health pill, analyzeURL hien ket qua
     Safe / DomainNotFound / Phishing, lich su luu localStorage, sample chip.
*/
const fs = require("fs");
const { JSDOM } = require("jsdom");

const REPO = "/home/hatch/workspace/phishing-ai-detector/frontend";
const html = fs.readFileSync(REPO + "/index.html", "utf8");
const js = fs.readFileSync(REPO + "/script.js", "utf8");
const css = fs.readFileSync(REPO + "/style.css", "utf8");

const SAFE_PAYLOAD = {
  url: "https://www.google.com", status: "Safe", probability: 0.0,
  risk_level: "Low", source: "whitelist",
  technical_report: { domain_age: "N/A", dns_status: "Unknown", impersonation_risk: "Low", is_shortened: false },
  domain_info: {
    domain: "google.com", host: "www.google.com", is_ip_host: false,
    dns: { status: "resolved", a: ["142.250.80.4"], aaaa: [], mx: [], ns: [], txt: ["v=spf1 -all"],
           cname: [], soa: { primary_ns: "ns1.google.com", serial: "123456", raw: "ns1.google.com. dns-admin.google.com. 123456 900 900 1800 60" },
           ptr: ["fra24s12-in-f4.1e100.net"], spf: "v=spf1 -all",
           dmarc: { record: "v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com", policy: "reject" },
           dnssec: { enabled: true, ds: true, dnskey: true } },
    whois: { status: "ok", created: "1997-09-15", expires: "2028-09-14", updated: "2024-09-09",
             registrar: "MarkMonitor Inc.", age_days: 10600,
             name_servers: ["ns1.google.com", "ns2.google.com"], domain_status: ["clientTransferProhibited"] },
    tls: { checked: true, valid: true, issuer: "Google Trust Services", subject: "Google Trust Services", expires: "2026-11-01", days_left: 90,
           sans: ["*.google.com", "google.com"], sig_alg: "sha256WithRSAEncryption", tls_version: "TLSv1.3",
           cipher: "TLS_AES_256_GCM_SHA384", cipher_bits: 256 },
    http: { reachable: true, status_code: 200, final_url: "https://www.google.com/", redirects: [], server: "gws", response_time_ms: 180,
            content_type: "text/html", content_length: 12345, redirect_count: 0,
            resolved_ip: "142.250.80.4",
            ip_info: { country: "United States", region: "California", city: "Mountain View", isp: "Google LLC", org: "Google LLC", asn: "AS15169 Google LLC" } },
    status: "active", reachable: true
  },
  domain_status: "active", warning: null
};
const NF_PAYLOAD = {
  url: "https://xkqjzwv-qqqq-zzz12345.com/login", status: "DomainNotFound", probability: null,
  risk_level: "Unknown", source: "domain_check",
  technical_report: { domain_age: "N/A", dns_status: "No DNS record", impersonation_risk: "Unknown", is_shortened: false },
  domain_info: {
    domain: "xkqjzwv-qqqq-zzz12345.com", host: "xkqjzwv-qqqq-zzz12345.com", is_ip_host: false,
    dns: { status: "nxdomain", a: [], aaaa: [], mx: [], ns: [], txt: [] },
    whois: { status: "unknown", created: null, expires: null, registrar: null, age_days: null },
    tls: { checked: false, valid: null, issuer: null, subject: null, expires: null, days_left: null },
    http: { reachable: false, status_code: null, final_url: null, redirects: [], server: null, response_time_ms: null, error: "dns" },
    status: "nonexistent", reachable: false
  },
  domain_status: "nonexistent", warning: null,
  message: "Tên miền xkqjzwv-qqqq-zzz12345.com không tồn tại (DNS không phân giải được) — không thể truy cập."
};
const SPARSE_PAYLOAD = {
  url: "https://www.example.com", status: "Safe", probability: 0.1,
  risk_level: "Low", source: "ai_analysis",
  technical_report: { domain_age: "N/A", dns_status: "Unknown", impersonation_risk: "Low", is_shortened: false },
  domain_info: {
    domain: "example.com", host: "www.example.com", is_ip_host: false,
    dns: { status: "resolved", a: [], aaaa: [], mx: [], ns: [], txt: [], cname: [], soa: null, ptr: [], spf: null, dmarc: null, dnssec: null },
    whois: { status: "unknown", created: null, expires: null, updated: null, registrar: null, age_days: null, name_servers: null, domain_status: null },
    tls: { checked: false, valid: null, issuer: null, subject: null, expires: null, days_left: null, sans: null, sig_alg: null, tls_version: null, cipher: null, cipher_bits: null, error: null },
    http: { reachable: null, status_code: null, final_url: null, redirects: [], server: null, content_type: null, content_length: null, redirect_count: null, resolved_ip: null, ip_info: null, response_time_ms: null, error: null },
    status: "unknown", reachable: null
  },
  domain_status: "unknown", warning: null
};
const NULLINFO_PAYLOAD = {
  url: "https://www.example.com", status: "Safe", probability: 0.05,
  risk_level: "Low", source: "ai_analysis",
  technical_report: { domain_age: "N/A", dns_status: "Unknown", impersonation_risk: "Low", is_shortened: false },
  domain_info: null, domain_status: "unknown", warning: null
};
const PHISH_PAYLOAD = {
  url: "https://vietcombank-dangnhap.com/login", status: "Phishing", probability: 0.93,
  risk_level: "High", source: "ai_analysis",
  technical_report: { domain_age: 12, dns_status: "Resolved", impersonation_risk: "High", is_shortened: false, nn_probability: 0.91 },
  domain_info: {
    domain: "vietcombank-dangnhap.com", host: "vietcombank-dangnhap.com", is_ip_host: false,
    dns: { status: "resolved", a: ["45.60.11.10"], aaaa: [], mx: [], ns: [], txt: [] },
    whois: { status: "ok", created: "2026-10-27", expires: "2027-10-27", registrar: "NameCheap", age_days: 12 },
    tls: { checked: false, valid: null, issuer: null, subject: null, expires: null, days_left: null, error: "timeout" },
    http: { reachable: true, status_code: 200, final_url: "https://vietcombank-dangnhap.com/login", redirects: [], server: "nginx", response_time_ms: 320 },
    status: "active", reachable: true
  },
  domain_status: "active", warning: null
};

let mode = "safe";
const dom = new JSDOM(html, { url: "http://localhost:8080/", runScripts: "outside-only", pretendToBeVisual: true });
const { window } = dom;
window.HTMLElement.prototype.scrollIntoView = function () {}; // jsdom chua co ham nay (trinh duyet that co)
window.lucide = { createIcons: () => {} };
window.fetch = async (url, opts) => {
  const u = String(url);
  if (u.endsWith("/health")) {
    return { ok: true, json: async () => ({ status: "ok", models_loaded: true, threshold: 0.5 }) };
  }
  if (u.endsWith("/predict")) {
    const payload = mode === "safe" ? SAFE_PAYLOAD : mode === "nf" ? NF_PAYLOAD
      : mode === "sparse" ? SPARSE_PAYLOAD : mode === "nullinfo" ? NULLINFO_PAYLOAD : PHISH_PAYLOAD;
    return { ok: true, json: async () => payload };
  }
  throw new Error("unexpected fetch " + u);
};
window.eval(js);
window.document.dispatchEvent(new window.Event("DOMContentLoaded", { bubbles: true }));

const $ = (id) => window.document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PASS = [], FAIL = [];
function check(name, cond, extra = "") {
  (cond ? PASS : FAIL).push(name);
  console.log((cond ? "PASS " : "FAIL ") + name + (extra ? " | " + extra : ""));
}

(async () => {
  await sleep(80);
  // 1. Khoi tao: health pill
  check("health pill hien API dang hoat dong", /hoạt động/i.test($("apiStatusText").textContent), $("apiStatusText").textContent.trim());
  // 0. Giao dien moi: khong gradient, khong giai thich cong nghe
  check("CSS khong con gradient", !/gradient/i.test(css));
  const heroSub = window.document.querySelector(".hero-sub");
  check("hero-sub ngan 1 dong, khong nhac ten cong nghe",
    heroSub && heroSub.textContent.trim().length <= 60 && !/xgboost|mạng nơ-ron|học máy|mô hình ai|neural/i.test(heroSub.textContent),
    heroSub ? heroSub.textContent.trim() : "thieu .hero-sub");
  check("khong con muc 'hoat dong the nao'", !window.document.querySelector(".how-card"));
  // 0b. Da bo muc Bao cao ky thuat + nut Doi may chu API
  check("khong con section Bao cao ky thuat",
    !window.document.getElementById("techDetails") && !/Báo cáo kỹ thuật/.test(window.document.body.textContent));
  check("khong con nut Doi may chu API",
    !window.document.getElementById("apiSwitchBtn") && !/Đổi máy chủ API/.test(window.document.body.textContent));
  check("js khong con chuoi Bao cao ky thuat / Doi may chu API",
    !/Báo cáo kỹ thuật|Đổi máy chủ API|apiSwitchBtn|resAge|resDNS/.test(js));
  check("resolveApiBase van nhan localhost -> API mac dinh",
    /localhost/.test(js) && /127\.0\.0\.1/.test(js) && /phishing-ai-api\.onrender\.com/.test(js));
  // 2. Sample chip dien URL
  window.document.querySelector(".chip").click();
  check("chip mau dien URL vao input", $("urlInput").value.length > 0, $("urlInput").value);
  // 3. Ca Safe
  mode = "safe";
  $("urlInput").value = "https://www.google.com";
  $("scanBtn").click();
  await sleep(80);
  check("Safe: result hien", !$("resultArea").classList.contains("hidden"));
  check("Safe: nhan 'An toàn'", /an toàn/i.test($("verdictTitle").textContent), $("verdictTitle").textContent);
  check("Safe: gauge co so %", /%/.test($("gaugeValue").textContent), $("gaugeValue").textContent);
  check("Safe: DNS A hien IP", /142\.250/.test($("diA").textContent), $("diA").textContent);
  check("Safe: WHOIS hien registrar", /MarkMonitor/.test($("diRegistrar").textContent));
  check("Safe: WHOIS hien tuoi domain", /10\.600/.test($("diWhoisAge").textContent), $("diWhoisAge").textContent);
  check("Safe: TLS hien Hop le", /Hợp lệ/.test($("diTlsValid").textContent), $("diTlsValid").textContent);
  check("Safe: HTTP hien 200", /200/.test($("diHttpStatus").textContent), $("diHttpStatus").textContent);
  check("Safe: SPF hien", /v=spf1/.test($("diSpf").textContent), $("diSpf").textContent);
  check("Safe: DMARC hien p=reject", /p=reject/.test($("diDmarc").textContent), $("diDmarc").textContent);
  check("Safe: DNSSEC hien Co", /Có/.test($("diDnssec").textContent), $("diDnssec").textContent);
  check("Safe: SOA hien nameserver chinh", /ns1\.google\.com/.test($("diSoa").textContent), $("diSoa").textContent);
  check("Safe: WHOIS ngay cap nhat hien", /2024/.test($("diWhoisUpdated").textContent), $("diWhoisUpdated").textContent);
  check("Safe: WHOIS nameservers hien", /ns1\.google\.com/.test($("diWhoisNs").textContent), $("diWhoisNs").textContent);
  check("Safe: TLS version hien", /TLSv1\.3/.test($("diTlsVersion").textContent), $("diTlsVersion").textContent);
  check("Safe: cipher hien", /TLS_AES_256_GCM_SHA384/.test($("diTlsCipher").textContent), $("diTlsCipher").textContent);
  check("Safe: thuat toan ky hien", /sha256WithRSAEncryption/.test($("diTlsSigAlg").textContent), $("diTlsSigAlg").textContent);
  check("Safe: content-type hien", /text\/html/.test($("diHttpContentType").textContent), $("diHttpContentType").textContent);
  check("Safe: so lan chuyen huong 0 lan", /0 lần/.test($("diHttpRedirectCount").textContent), $("diHttpRedirectCount").textContent);
  check("Safe: IP da phan giai hien", /142\.250/.test($("diHttpIp").textContent), $("diHttpIp").textContent);
  check("Safe: ip_info hien ISP/ASN", /Google LLC/.test($("diHttpIpInfo").textContent) && /AS15169/.test($("diHttpIpInfo").textContent), $("diHttpIpInfo").textContent);
  check("Safe: lich su co 1 muc", window.document.querySelectorAll("#historyList li").length === 1);
  check("Safe: localStorage luu 1 muc", JSON.parse(window.localStorage.getItem("scamshield_history_v1") || "[]").length === 1);
  // 4. Ca DomainNotFound
  mode = "nf";
  $("urlInput").value = "https://xkqjzwv-qqqq-zzz12345.com/login";
  $("scanBtn").click();
  await sleep(80);
  check("NF: nhan 'Không tồn tại'", /không tồn tại/i.test($("verdictTitle").textContent), $("verdictTitle").textContent);
  check("NF: mo ta hien message tu backend", /không tồn tại/i.test($("verdictDesc").textContent), $("verdictDesc").textContent);
  check("NF: lich su co 2 muc", window.document.querySelectorAll("#historyList li").length === 2);
  // 5. Ca Phishing
  mode = "phish";
  $("urlInput").value = "https://vietcombank-dangnhap.com/login";
  $("scanBtn").click();
  await sleep(80);
  check("Phish: nhan 'Nguy hiểm'", /nguy hiểm/i.test($("verdictTitle").textContent), $("verdictTitle").textContent);
  check("Phish: gauge ~93%", /93%/.test($("gaugeValue").textContent), $("gaugeValue").textContent);
  check("Phish: WHOIS hien tuoi 12 ngay", /12/.test($("diWhoisAge").textContent), $("diWhoisAge").textContent);
  check("Phish: lich su co 3 muc", window.document.querySelectorAll("#historyList li").length === 3);
  // 6. Ca domain_info thieu nhieu truong -> tat ca hien "Không tìm thấy", khong o trong
  mode = "sparse";
  $("urlInput").value = "https://www.example.com";
  $("scanBtn").click();
  await sleep(80);
  const sparseVals = [...window.document.querySelectorAll("#domainDetails .kv-value")].map((el) => el.textContent.trim());
  check("Sparse: khong o nao trong hay chi co dau gach",
    sparseVals.length > 0 && sparseVals.every((t) => t !== "" && t !== "—"),
    sparseVals.filter((t) => t === "" || t === "—").join("|"));
  check("Sparse: hau het muc hien 'Không tìm thấy'",
    sparseVals.filter((t) => t === "Không tìm thấy").length >= 10,
    `NF=${sparseVals.filter((t) => t === "Không tìm thấy").length}/${sparseVals.length}`);
  check("Sparse: ten mien van hien", /example\.com/.test($("diDomain").textContent), $("diDomain").textContent);
  // 7. Ca domain_info null -> tat ca "Không tìm thấy"
  mode = "nullinfo";
  $("urlInput").value = "https://www.example.com";
  $("scanBtn").click();
  await sleep(80);
  const nullVals = [...window.document.querySelectorAll("#domainDetails .kv-value")].map((el) => el.textContent.trim());
  check("NullInfo: tat ca muc hien 'Không tìm thấy'",
    nullVals.length > 0 && nullVals.every((t) => t === "Không tìm thấy"),
    `NF=${nullVals.filter((t) => t === "Không tìm thấy").length}/${nullVals.length}`);
  // 8. Input rong -> bao loi, khong goi API
  $("urlInput").value = "   ";
  $("scanBtn").click();
  await sleep(50);
  check("Input rong: hien loi nhap lieu", $("errorBox").hidden === false && /dán một đường link/i.test($("errorText").textContent), $("errorText").textContent);
  console.log(`\n== ${PASS.length} PASS, ${FAIL.length} FAIL ==`);
  if (FAIL.length) { console.log("FAILED:", FAIL); process.exit(1); }
})();
