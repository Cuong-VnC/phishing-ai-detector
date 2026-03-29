/**
 * PHISHING GUARDIAN AI - FRONTEND LOGIC
 * Chịu trách nhiệm gọi API, xử lý dữ liệu và cập nhật giao diện người dùng.
 */

// 1. CẤU HÌNH HỆ THỐNG
// Thay đổi URL này khi bạn deploy Backend lên các dịch vụ như Render/Railway
const API_CONFIG = {
    BASE_URL: "https://phishing-guardian-api.onrender.com",
    ENDPOINTS: {
        PREDICT: "/predict"
    }
};

// 2. KHỞI TẠO KHI TRANG WEB LOAD XONG
document.addEventListener('DOMContentLoaded', () => {
    // Khởi tạo các icon Lucide ban đầu
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    // Hỗ trợ nhấn phím Enter để quét
    const urlInput = document.getElementById('urlInput');
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            analyzeURL();
        }
    });
});

/**
 * Hàm chính thực hiện gọi API phân tích URL
 */
async function analyzeURL() {
    const urlInput = document.getElementById('urlInput');
    const loadingArea = document.getElementById('loading');
    const resultArea = document.getElementById('result-area');
    const sourceTag = document.getElementById('sourceTag');
    
    const urlValue = urlInput.value.trim();

    // Kiểm tra đầu vào hợp lệ cơ bản
    if (!urlValue) {
        alert("Vui lòng nhập một URL hợp lệ để bắt đầu phân tích!");
        return;
    }

    // BƯỚC 1: TRẠNG THÁI CHỜ (UI RESET)
    loadingArea.style.display = 'block';
    resultArea.style.display = 'none';
    sourceTag.style.display = 'none';
    
    // Cuộn xuống để người dùng thấy radar đang quét
    loadingArea.scrollIntoView({ behavior: 'smooth' });

    try {
        // BƯỚC 2: GỌI API BACKEND
        const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.PREDICT}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ url: urlValue })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || "Lỗi máy chủ Backend");
        }

        const data = await response.json();

        // BƯỚC 3: HIỂN THỊ KẾT QUẢ
        setTimeout(() => {
            displayResult(data);
            loadingArea.style.display = 'none';
        }, 800); // Tạo độ trễ nhỏ để hiệu ứng radar trông thật hơn

    } catch (error) {
        console.error("Analysis Error:", error);
        loadingArea.style.display = 'none';
        alert(`❌ Không thể kết nối tới hệ thống AI: ${error.message}\n\nHãy đảm bảo bạn đã khởi động Backend (main.py) trên cổng 8000.`);
    }
}

/**
 * Cập nhật dữ liệu trả về từ API lên các thành phần giao diện
 * @param {Object} data - Dữ liệu JSON từ API
 */
function displayResult(data) {
    const resultArea = document.getElementById('result-area');
    const verdictBox = document.getElementById('mainVerdict');
    const verdictText = document.getElementById('verdictText');
    const probText = document.getElementById('probabilityText');
    const sourceTag = document.getElementById('sourceTag');

    // 1. Hiện khu vực kết quả
    resultArea.style.display = 'block';

    // 2. Phân loại màu sắc và nội dung theo Status
    const isPhishing = data.status === "Phishing";
    
    verdictBox.className = "main-verdict " + (isPhishing ? "verdict-phishing" : "verdict-safe");
    verdictText.innerText = isPhishing ? "🚨 CẢNH BÁO: URL ĐỘC HẠI" : "✅ URL CÓ VẺ AN TOÀN";
    
    // 3. Hiệu ứng thanh xác suất (Probability Bar)
    const probPercentage = (data.probability * 100).toFixed(2);
    probText.innerText = `Mức độ rủi ro: ${probPercentage}%`;
    
    // Tạo thanh tiến trình (nếu bạn có thêm HTML này trong CSS)
    const probBar = document.querySelector('.probability-fill');
    if (probBar) {
        probBar.style.width = probPercentage + "%";
        probBar.style.backgroundColor = isPhishing ? "var(--danger)" : "var(--success)";
    }

    // 4. Kiểm tra nguồn dữ liệu (AI hay Cache)
    if (data.source === "database_cache") {
        sourceTag.style.display = 'inline-block';
        sourceTag.title = "Kết quả này được lấy ngay lập tức từ cơ sở dữ liệu tri thức.";
    }

    // 5. Cập nhật Technical Report (Thông tin mạng)
    if (data.technical_report) {
        updateTechnicalField('resAge', data.technical_report.domain_age, "ngày");
        updateTechnicalField('resDNS', data.technical_report.dns_status);
        updateTechnicalField('resImpersonation', data.technical_report.impersonation_risk);
        updateTechnicalField('resShortened', data.technical_report.is_shortened ? "Có (Rủi ro)" : "Không");
    }

    // 6. Vẽ lại các icon Lucide mới (cho các tag động)
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    // Cuộn xuống kết quả
    resultArea.scrollIntoView({ behavior: 'smooth' });
}

/**
 * Hàm bổ trợ để cập nhật giá trị vào các Card thông tin
 */
function updateTechnicalField(id, value, suffix = "") {
    const element = document.getElementById(id);
    if (element) {
        if (value === null || value === undefined || value === "Unknown" || value === "N/A") {
            element.innerText = "Không rõ";
            element.style.color = "var(--text-dim)";
        } else {
            element.innerText = `${value} ${suffix}`;
            element.style.color = "var(--text-main)";
        }
    }
}
