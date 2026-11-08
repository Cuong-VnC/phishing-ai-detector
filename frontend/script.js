/**
 * ScamShield-AI — Frontend logic (giao diện mới).
 * API: POST /predict, GET /health, GET /domain-info.
 * Nguyên tắc fail-closed: không bao giờ mặc định hiển thị AN TOÀN khi
 * response lỗi hoặc thiếu dữ liệu.
 */

const DEFAULT_API = "https://phishing-ai-api.onrender.com";
const LOCAL_API = "http://localhost:8000";
const HISTORY_KEY = "scamshield_history_v1";
const API_KEY = "scamshield_api_base";
const MAX_HISTORY = 8;
const GAUGE_CIRC = 326.7; // 2 * PI * 52

function resolveApiBase() {
    const params = new URLSearchParams(window.location.search);
    const fromQuery = params.get("api");
    if (fromQuery) {
        try { localStorage.setItem(API_KEY, fromQuery.replace(/\/$/, "")); } catch (e) { /* ignore */ }
    }
    try {
        const saved = localStorage.getItem(API_KEY);
        if (saved) return saved.replace(/\/$/, "");
    } catch (e) { /* ignore */ }
    const host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1") return LOCAL_API;
    return DEFAULT_API;
}

const API_BASE = resolveApiBase();

const SOURCE_LABELS = {
    whitelist: "Danh sách tin cậy",
    ai_analysis: "Mô hình AI (NN + XGBoost)",
    database_blacklist: "Cơ sở dữ liệu đen",
    database_whitelist: "Cơ sở dữ liệu trắng",
    urlhaus_database: "URLhaus",
    google_safe_browsing: "Google Safe Browsing",
    domain_check: "Kiểm tra tên miền",
};

const $ = (id) => document.getElementById(id);

function refreshIcons() {
    if (typeof lucide !== "undefined") lucide.createIcons();
}

function fmtDate(iso) {
    if (!iso) return "Không rõ";
    const d = new Date(iso + (iso.length === 10 ? "T00:00:00" : ""));
    return isNaN(d) ? iso : d.toLocaleDateString("vi-VN");
}

function fmtList(arr) {
    if (!arr || !arr.length) return "—";
    return arr.join(", ");
}

/* ---------------- Trạng thái máy chủ ---------------- */
async function checkApiHealth() {
    const dot = $("apiDot"), text = $("apiStatusText");
    try {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 8000);
        const res = await fetch(`${API_BASE}/health`, { signal: ctrl.signal });
        clearTimeout(t);
        if (!res.ok) throw new Error("health not ok");
        const data = await res.json();
        dot.className = "api-dot " + (data.models_loaded ? "ok" : "bad");
        text.textContent = data.models_loaded ? "Máy chủ đang hoạt động" : "Máy chủ lỗi model";
    } catch (e) {
        dot.className = "api-dot bad";
        text.textContent = "Không kết nối được máy chủ";
    }
}

/* ---------------- Lịch sử (localStorage) ---------------- */
function loadHistory() {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); }
    catch (e) { return []; }
}

function saveHistory(entry) {
    try {
        let list = loadHistory().filter((x) => x.url !== entry.url);
        list.unshift(entry);
        localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, MAX_HISTORY)));
    } catch (e) { /* ignore */ }
}

function verdictClassOf(data) {
    const status = String((data && data.status) || "");
    if (status === "DomainNotFound") return "dead";
    if (status.includes("Phishing")) return "danger";
    if (status === "Safe") {
        const p = Number(data.probability);
        if (Number.isFinite(p) && p >= 0.4) return "suspicious";
        return "safe";
    }
    return "suspicious";
}

function verdictLabelOf(data) {
    const cls = verdictClassOf(data);
    return { safe: "An toàn", danger: "Nguy hiểm", suspicious: "Nghi ngờ", dead: "Không tồn tại" }[cls];
}

function renderHistory() {
    const list = loadHistory();
    const ul = $("historyList");
    ul.innerHTML = "";
    $("historyEmpty").style.display = list.length ? "none" : "block";
    list.forEach((item) => {
        const li = document.createElement("li");
        const dot = document.createElement("span");
        dot.className = "history-dot " + item.cls;
        const url = document.createElement("span");
        url.className = "history-url";
        url.textContent = item.url;
        url.title = item.url;
        const verdict = document.createElement("span");
        verdict.className = "history-verdict";
        verdict.textContent = item.label;
        const time = document.createElement("span");
        time.className = "history-time";
        time.textContent = new Date(item.time).toLocaleString("vi-VN", {
            day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit",
        });
        li.append(dot, url, verdict, time);
        li.addEventListener("click", () => {
            $("urlInput").value = item.url;
            analyzeURL();
        });
        ul.appendChild(li);
    });
}

/* ---------------- Hiển thị kết quả ---------------- */
function showError(title, text) {
    $("errorBox").hidden = false;
    $("errorTitle").textContent = title;
    $("errorText").textContent = text;
    $("resultArea").hidden = true;
    $("loadingBox").hidden = true;
    refreshIcons();
    $("errorBox").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function hideError() { $("errorBox").hidden = true; }

function setGauge(prob, color) {
    const fill = $("gaugeFill");
    const value = $("gaugeValue");
    if (prob === null || prob === undefined || !Number.isFinite(prob)) {
        fill.style.strokeDashoffset = GAUGE_CIRC;
        fill.style.stroke = "var(--grey)";
        value.textContent = "—";
        return;
    }
    const pct = Math.max(0, Math.min(100, prob * 100));
    fill.style.strokeDashoffset = GAUGE_CIRC * (1 - pct / 100);
    fill.style.stroke = color;
    value.textContent = pct.toFixed(0) + "%";
}

function fillDomainInfo(info) {
    if (!info) {
        ["diDomain", "diHost", "diStatus", "diA", "diAAAA", "diMX", "diNS", "diTXT",
         "diWhoisCreated", "diWhoisExpires", "diRegistrar", "diWhoisAge",
         "diTlsValid", "diTlsIssuer", "diTlsExpires", "diTlsDays",
         "diHttpOk", "diHttpStatus", "diHttpServer", "diHttpTime", "diHttpFinal", "diHttpRedirects"
        ].forEach((id) => { $(id).textContent = "—"; });
        return;
    }
    const dns = info.dns || {};
    const whois = info.whois || {};
    const tls = info.tls || {};
    const http = info.http || {};
    $("diDomain").textContent = info.domain || "—";
    $("diHost").textContent = info.host || "—";
    const statusMap = {
        active: "Đang hoạt động", inactive: "Không hoạt động",
        nonexistent: "Không tồn tại", unknown: "Không xác định",
    };
    $("diStatus").textContent = statusMap[info.status] || (info.status || "—");
    $("diA").textContent = fmtList(dns.a);
    $("diAAAA").textContent = fmtList(dns.aaaa);
    $("diMX").textContent = fmtList(dns.mx);
    $("diNS").textContent = fmtList(dns.ns);
    $("diTXT").textContent = fmtList(dns.txt);
    $("diWhoisCreated").textContent = fmtDate(whois.created);
    $("diWhoisExpires").textContent = fmtDate(whois.expires);
    $("diRegistrar").textContent = whois.registrar || "Không rõ";
    $("diWhoisAge").textContent = (whois.age_days !== null && whois.age_days !== undefined)
        ? whois.age_days.toLocaleString("vi-VN") + " ngày" : "Không rõ";
    $("diTlsValid").textContent = !tls.checked ? "Không kiểm tra"
        : (tls.valid === true ? "Hợp lệ" : (tls.valid === false ? "Không hợp lệ" : "Không rõ"));
    $("diTlsIssuer").textContent = tls.issuer || "—";
    $("diTlsExpires").textContent = fmtDate(tls.expires);
    $("diTlsDays").textContent = (tls.days_left !== null && tls.days_left !== undefined)
        ? (tls.days_left >= 0 ? `Còn ${tls.days_left} ngày` : `Hết hạn ${-tls.days_left} ngày trước`)
        : "—";
    $("diHttpOk").textContent = http.reachable === true ? "Có"
        : (http.reachable === false ? `Không (${http.error || "lỗi kết nối"})` : "Không rõ");
    $("diHttpStatus").textContent = http.status_code !== null && http.status_code !== undefined
        ? String(http.status_code) : "—";
    $("diHttpServer").textContent = http.server || "—";
    $("diHttpTime").textContent = (http.response_time_ms !== null && http.response_time_ms !== undefined)
        ? http.response_time_ms.toLocaleString("vi-VN") + " ms" : "—";
    $("diHttpFinal").textContent = http.final_url || "—";
    $("diHttpRedirects").textContent = http.redirects && http.redirects.length
        ? http.redirects.join(" → ") : "Không có chuyển hướng";
}

function displayResult(data) {
    const area = $("resultArea");
    const status = String((data && data.status) || "");
    const probNum = Number(data && data.probability);
    const hasProb = Number.isFinite(probNum);
    const riskLevel = data && data.risk_level;
    const cls = verdictClassOf(data);
    const card = $("verdictCard");
    const title = $("verdictTitle");
    const desc = $("verdictDesc");
    const icon = $("verdictIcon");

    // --- FAIL-CLOSED: response lỗi / thiếu dữ liệu thì không bao giờ hiện AN TOÀN ---
    if (status === "Error" || (!hasProb && !riskLevel && !status)) {
        showError("Không thể phân tích", (data && data.detail) || "Dữ liệu trả về không hợp lệ.");
        return;
    }

    hideError();
    area.hidden = false;
    card.className = "verdict-card " + cls;

    const iconName = { safe: "shield-check", danger: "shield-alert", suspicious: "shield-alert", dead: "globe" }[cls];
    icon.innerHTML = `<i data-lucide="${iconName}"></i>`;

    const prob = hasProb ? probNum : null;
    if (status === "DomainNotFound") {
        title.textContent = "TÊN MIỀN KHÔNG TỒN TẠI";
        desc.textContent = (data && data.message) || "Tên miền này không phân giải được trên Internet — có thể đã bị xóa hoặc chưa từng được đăng ký.";
        setGauge(null, "var(--grey)");
    } else if (cls === "danger") {
        title.textContent = "NGUY HIỂM: URL LỪA ĐẢO";
        desc.textContent = "Đừng nhập mật khẩu, mã OTP hay chuyển tiền trên trang này. Hãy đóng tab và báo cáo nếu cần.";
        setGauge(prob, "var(--danger)");
    } else if (cls === "safe") {
        title.textContent = "AN TOÀN";
        desc.textContent = "Chưa thấy dấu hiệu lừa đảo. Tuy vậy, hãy luôn kiểm tra kỹ tên miền trước khi đăng nhập.";
        setGauge(prob, "var(--success)");
    } else {
        title.textContent = "NGHI NGỜ — CẦN THẬN TRỌNG";
        desc.textContent = "URL có một số dấu hiệu đáng ngờ. Không nên nhập thông tin nhạy cảm cho đến khi chắc chắn.";
        setGauge(prob, "var(--warning)");
    }

    $("verdictUrl").textContent = data.url || "";
    $("sourceChip").textContent = "Nguồn: " + (SOURCE_LABELS[data.source] || data.source || "—");
    $("riskChip").textContent = "Mức rủi ro: " + (riskLevel || "—");
    const tr = data.technical_report || {};
    if (tr.nn_probability !== undefined && tr.nn_probability !== null) {
        $("nnChip").hidden = false;
        $("nnChip").textContent = "NN: " + (Number(tr.nn_probability) * 100).toFixed(1) + "%";
    } else {
        $("nnChip").hidden = true;
    }

    // Cảnh báo tên miền không hoạt động / không kiểm tra được
    const warn = $("warningBanner");
    if (data.warning) {
        warn.hidden = false;
        $("warningText").textContent = data.warning;
    } else {
        warn.hidden = true;
    }

    // Báo cáo kỹ thuật (giữ tương thích response cũ)
    $("resAge").textContent = (tr.domain_age !== undefined && tr.domain_age !== "N/A" && tr.domain_age !== null)
        ? tr.domain_age + " ngày" : "Không rõ";
    $("resDNS").textContent = tr.dns_status || "—";
    $("resImpersonation").textContent = tr.impersonation_risk || "Thấp";
    $("resShortened").textContent = tr.is_shortened ? "Có" : "Không";

    fillDomainInfo(data.domain_info || null);

    // Lưu lịch sử (chỉ khi có kết luận rõ ràng)
    saveHistory({
        url: data.url || $("urlInput").value.trim(),
        cls, label: verdictLabelOf(data), time: Date.now(),
    });
    renderHistory();

    refreshIcons();
    area.scrollIntoView({ behavior: "smooth", block: "start" });
}

/* ---------------- Gọi API ---------------- */
let loadingTimer = null;

async function analyzeURL() {
    const input = $("urlInput");
    const url = input.value.trim();
    if (!url) {
        showError("Chưa nhập URL", "Vui lòng dán một đường link vào ô kiểm tra.");
        input.focus();
        return;
    }

    const scanBtn = $("scanBtn");
    const originalBtn = scanBtn.innerHTML;
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span>Đang kiểm tra…</span>';
    hideError();
    $("resultArea").hidden = true;
    const loading = $("loadingBox");
    loading.hidden = false;
    const steps = [
        "Đang phân tích URL bằng mô hình AI…",
        "Đang tra cứu DNS, WHOIS, chứng chỉ TLS…",
        "Đang kiểm tra khả năng truy cập của tên miền…",
    ];
    let stepIdx = 0;
    $("loadingStep").textContent = steps[0];
    loadingTimer = setInterval(() => {
        stepIdx = (stepIdx + 1) % steps.length;
        $("loadingStep").textContent = steps[stepIdx];
    }, 2500);

    // Render free cold start có thể mất 30-60s, nhưng không để treo vô hạn.
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 90000);

    try {
        const response = await fetch(`${API_BASE}/predict`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
            signal: controller.signal,
        });
        clearTimeout(timeoutId);
        clearInterval(loadingTimer);
        loading.hidden = true;

        let data = null;
        try { data = await response.json(); } catch (e) { /* ignore */ }
        if (!response.ok) {
            const detail = (data && data.detail) || `Máy chủ trả về lỗi HTTP ${response.status}`;
            showError("Không thể kiểm tra", detail);
            return;
        }
        displayResult(data);
    } catch (error) {
        clearTimeout(timeoutId);
        clearInterval(loadingTimer);
        loading.hidden = true;
        console.error("Lỗi:", error);
        if (error.name === "AbortError") {
            showError("Máy chủ phản hồi chậm", "Quá 90 giây chưa có kết quả (máy chủ miễn phí có thể đang khởi động lại). Vui lòng thử lại sau ít phút.");
        } else {
            showError("Không kết nối được máy chủ", `${error.message}. Kiểm tra lại mạng hoặc thử lại sau.`);
        }
    } finally {
        scanBtn.disabled = false;
        scanBtn.innerHTML = originalBtn;
        refreshIcons();
    }
}

function resetCheck() {
    $("urlInput").value = "";
    $("resultArea").hidden = true;
    hideError();
    $("urlInput").focus();
}

/* ---------------- Khởi tạo ---------------- */
document.addEventListener("DOMContentLoaded", () => {
    refreshIcons();
    checkApiHealth();
    renderHistory();

    $("scanBtn").addEventListener("click", analyzeURL);
    $("resetBtn").addEventListener("click", resetCheck);
    $("urlInput").addEventListener("keypress", (e) => {
        if (e.key === "Enter") analyzeURL();
    });
    $("urlInput").addEventListener("input", () => {
        $("clearInputBtn").style.display = $("urlInput").value ? "flex" : "none";
    });
    $("clearInputBtn").addEventListener("click", () => {
        $("urlInput").value = "";
        $("clearInputBtn").style.display = "none";
        $("urlInput").focus();
    });
    document.querySelectorAll(".chip").forEach((chip) => {
        chip.addEventListener("click", () => {
            $("urlInput").value = chip.dataset.url;
            $("clearInputBtn").style.display = "flex";
            analyzeURL();
        });
    });
    $("clearHistoryBtn").addEventListener("click", () => {
        try { localStorage.removeItem(HISTORY_KEY); } catch (e) { /* ignore */ }
        renderHistory();
    });
    $("apiSwitchBtn").addEventListener("click", () => {
        const current = API_BASE;
        const next = window.prompt("Địa chỉ máy chủ API (để trống = mặc định):", current === DEFAULT_API ? "" : current);
        if (next === null) return;
        try {
            if (next.trim()) localStorage.setItem(API_KEY, next.trim().replace(/\/$/, ""));
            else localStorage.removeItem(API_KEY);
        } catch (e) { /* ignore */ }
        window.location.reload();
    });
});
