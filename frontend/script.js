/**
 * PHISHING GUARDIAN AI - FRONTEND LOGIC
 */

const API_CONFIG = {
    BASE_URL: "https://phishing-guardian-api.onrender.com",
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

    // 1. Hiển thị Popup quét (Hiệu ứng radar/vân tay)
    const popup = document.getElementById('scanPopup');
    if (popup) popup.style.display = 'flex';

    // 2. Reset giao diện cũ
    document.getElementById('initial-view').style.display = 'none';
    document.getElementById('result-area').style.display = 'none';
    document.getElementById('loading').style.display = 'none';

    try {
        const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.PREDICT}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || "Lỗi máy chủ");
        }

        const data = await response.json();
        
        // Ẩn popup và hiển thị kết quả sau 1.2s để tạo hiệu ứng chuyên nghiệp
        setTimeout(() => {
            if (popup) popup.style.display = 'none';
            displayResult(data);
        }, 1200);

    } catch (error) {
        if (popup) popup.style.display = 'none';
        console.error("Lỗi:", error);
        alert(`❌ Không thể kết nối tới SOC AI Core: ${error.message}`);
    }
}

function displayResult(data) {
    const area = document.getElementById('result-area');
    area.style.display = 'block';
    
    // --- SỬA LỖI LOGIC TẠI ĐÂY ---
    // Kiểm tra rủi ro dựa trên risk_level hoặc status chứa từ khóa Phishing/Malicious/Suspicious
    const riskLevel = data.risk_level; // "High", "Medium", "Low"
    const isDangerous = (riskLevel === "High" || riskLevel === "Medium");
    const prob = (data.probability * 100).toFixed(1);
    
    // 1. Cập nhật thanh rủi ro
    const probText = document.getElementById('probabilityText');
    const fill = document.getElementById('probFill');
    
    probText.innerText = prob + "%";
    fill.style.width = prob + "%";
    
    // Đổi màu theo mức độ rủi ro
    if (riskLevel === "High") {
        fill.style.backgroundColor = "var(--danger)";
    } else if (riskLevel === "Medium") {
        fill.style.backgroundColor = "var(--warning)";
    } else {
        fill.style.backgroundColor = "var(--success)";
    }
    
    // 2. Cập nhật tiêu đề thông báo
    const verdictText = document.getElementById('verdictText');
    const verdictIcon = document.getElementById('verdictIcon');
    
    if (riskLevel === "High") {
        verdictText.innerText = "🚨 CẢNH BÁO: URL ĐỘC HẠI";
        verdictText.style.color = "var(--danger)";
        if (verdictIcon) verdictIcon.style.color = "var(--danger)";
    } else if (riskLevel === "Medium") {
        verdictText.innerText = "⚠️ CHÚ Ý: LIÊN KẾT NGHI VẤN";
        verdictText.style.color = "var(--warning)";
        if (verdictIcon) verdictIcon.style.color = "var(--warning)";
    } else {
        verdictText.innerText = "✅ AN TOÀN: LIÊN KẾT HỢP LỆ";
        verdictText.style.color = "var(--success)";
        if (verdictIcon) verdictIcon.style.color = "var(--success)";
    }
    
    // 3. Cập nhật báo cáo kỹ thuật
    if (data.technical_report) {
        document.getElementById('resAge').innerText = 
            (data.technical_report.domain_age !== "N/A" ? data.technical_report.domain_age + " ngày" : "Không rõ");
        document.getElementById('resDNS').innerText = data.technical_report.dns_status || "N/A";
        document.getElementById('resImpersonation').innerText = data.technical_report.impersonation_risk || "Thấp";
        document.getElementById('resShortened').innerText = data.technical_report.is_shortened ? "CÓ" : "KHÔNG";
    }

    // 4. Hiển thị nguồn dữ liệu (Source Tag)
    console.log("Phân tích từ nguồn:", data.source);

    // Re-render các icon Lucide cho giao diện mới
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
    
    area.scrollIntoView({ behavior: 'smooth' });
}
