/**
 * SCAMSHIELD-AI - FRONTEND LOGIC
 */

const API_CONFIG = {
    BASE_URL: "https://phishing-ai-api.onrender.com",
    ENDPOINTS: {
        PREDICT: "/predict"
    }
};

document.addEventListener('DOMContentLoaded', () => {
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    const urlInput = document.getElementById('urlInput');
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            analyzeURL();
        }
    });
});

async function analyzeURL() {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();

    if (!url) {
        alert("Vui lòng nhập một URL hợp lệ!");
        return;
    }

    // Loading đơn giản: khóa nút + đổi nhãn, không popup, không delay giả.
    const scanBtn = document.getElementById('scanBtn');
    const originalBtnHTML = scanBtn.innerHTML;
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span>Đang kiểm tra...</span>';
    document.getElementById('result-area').style.display = 'none';

    // Timeout: Render free cold start có thể mất 30-60s, nhưng không để treo vô hạn.
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 90000);

    try {
        const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.PREDICT}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url }),
            signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || "Lỗi máy chủ");
        }

        const data = await response.json();
        displayResult(data);

    } catch (error) {
        clearTimeout(timeoutId);
        console.error("Lỗi:", error);
        if (error.name === 'AbortError') {
            alert("❌ Máy chủ phản hồi chậm (quá 90 giây), vui lòng thử lại.");
        } else {
            alert(`❌ Không thể kết nối tới ScamShield-AI: ${error.message}`);
        }
    } finally {
        scanBtn.disabled = false;
        scanBtn.innerHTML = originalBtnHTML;
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    }
}

// Reset inline: xóa kết quả và ô nhập, không reload cả trang.
function resetCheck() {
    document.getElementById('urlInput').value = '';
    document.getElementById('result-area').style.display = 'none';
    document.getElementById('urlInput').focus();
}

function displayResult(data) {
    const area = document.getElementById('result-area');
    area.style.display = 'block';

    const status = String((data && data.status) || "");
    const probNum = Number(data && data.probability);
    const hasProb = Number.isFinite(probNum);
    const riskLevel = data && data.risk_level;
    const hasRisk = (riskLevel === "High" || riskLevel === "Medium" || riskLevel === "Low");

    const verdictText = document.getElementById('verdictText');
    const verdictIcon = document.getElementById('verdictIcon');
    const probText = document.getElementById('probabilityText');
    const fill = document.getElementById('probFill');

    // --- FAIL-CLOSED: không bao giờ mặc định là AN TOÀN ---
    // BE trả status "Error", hoặc thiếu cả probability lẫn risk_level lẫn status
    // (vd row DB shape lạ, lỗi backend) thì phải hiện lỗi, không hiện an toàn.
    if (status === "Error" || (!hasProb && !hasRisk && !status)) {
        verdictText.innerText = "❌ KHÔNG THỂ PHÂN TÍCH";
        verdictText.style.color = "var(--danger)";
        if (verdictIcon) verdictIcon.style.color = "var(--danger)";
        probText.innerText = "—";
        fill.style.width = "0%";
        fill.style.backgroundColor = "var(--danger)";
        const detail = (data && data.detail) ? data.detail : "Dữ liệu trả về không hợp lệ";
        document.getElementById('probabilityDesc').innerText = detail;
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
        area.scrollIntoView({ behavior: 'smooth' });
        return;
    }

    // --- Verdict theo status của model, KHÔNG theo risk_level ---
    // risk_level chỉ quyết định màu thanh rủi ro. Trước đây verdict theo band
    // 0.7/0.4 nên vùng 0.5-0.7 (model nói Phishing) chỉ hiện "NGHI VẤN".
    const isPhishing = status.includes("Phishing");
    const prob = hasProb ? probNum * 100 : 0;

    // 1. Cập nhật thanh rủi ro
    probText.innerText = hasProb ? prob.toFixed(1) + "%" : "—";
    fill.style.width = hasProb ? prob + "%" : "0%";

    // Đổi màu theo mức độ rủi ro (fallback theo verdict nếu thiếu risk_level)
    const colorLevel = hasRisk ? riskLevel : (isPhishing ? "High" : "Low");
    if (colorLevel === "High") {
        fill.style.backgroundColor = "var(--danger)";
    } else if (colorLevel === "Medium") {
        fill.style.backgroundColor = "var(--warning)";
    } else {
        fill.style.backgroundColor = "var(--success)";
    }

    // 2. Cập nhật tiêu đề thông báo theo status
    if (isPhishing) {
        verdictText.innerText = "🚨 CẢNH BÁO: URL ĐỘC HẠI";
        verdictText.style.color = "var(--danger)";
        if (verdictIcon) verdictIcon.style.color = "var(--danger)";
    } else if (status === "Safe") {
        verdictText.innerText = "✅ AN TOÀN: LIÊN KẾT HỢP LỆ";
        verdictText.style.color = "var(--success)";
        if (verdictIcon) verdictIcon.style.color = "var(--success)";
    } else {
        // Status lạ nhưng dữ liệu còn đủ: cảnh báo vàng, không kết luận an toàn.
        verdictText.innerText = "⚠️ CHÚ Ý: LIÊN KẾT NGHI VẤN";
        verdictText.style.color = "var(--warning)";
        if (verdictIcon) verdictIcon.style.color = "var(--warning)";
    }

    // 3. Cập nhật báo cáo kỹ thuật
    if (data.technical_report) {
        document.getElementById('resAge').innerText =
            (data.technical_report.domain_age !== "N/A" ? data.technical_report.domain_age + " ngày" : "Không rõ");
        document.getElementById('resDNS').innerText = data.technical_report.dns_status || "N/A";
        document.getElementById('resImpersonation').innerText = data.technical_report.impersonation_risk || "Thấp";
        document.getElementById('resShortened').innerText = data.technical_report.is_shortened ? "Có" : "Không";
    }

    // 4. Hiển thị nguồn dữ liệu (Source Tag)
    console.log("Phân tích từ nguồn:", data.source);

    // Re-render các icon Lucide cho giao diện mới
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    area.scrollIntoView({ behavior: 'smooth' });
}
