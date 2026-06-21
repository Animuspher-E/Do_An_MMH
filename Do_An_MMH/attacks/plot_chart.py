import matplotlib.pyplot as plt
import json
import os

def main():
    json_path = "attacks/benchmark_results.json"
    
    if not os.path.exists(json_path):
        print(f"[-] LỖI: Không tìm thấy file {json_path}")
        return
        
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    r_data = data["replay_attack"]
    m_data = data["client_malware"]
    v_data = data["revocation_ocsp"]
    
    req1_latencies = r_data["req1_latencies_ms"]
    req2_latencies = r_data["req2_latencies_ms"]
    malware_latencies = m_data["latencies_ms"]
    ocsp_latencies = v_data["latencies_ms"]
    
    avg_req1 = r_data["avg_req1_ms"]
    avg_req2 = r_data["avg_req2_ms"]
    avg_malware = m_data["avg_latency_ms"]
    avg_ocsp = v_data["avg_latency_ms"]
    
    # Thiết lập giao diện matplotlib
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    
    # ----------------------------------------------------
    # BIỂU ĐỒ 1: SO SÁNH THỜI GIAN PHẢN HỒI TRUNG BÌNH (AVG LATENCY)
    # ----------------------------------------------------
    fig1, ax1 = plt.subplots(figsize=(9, 6))
    
    categories = [
        "Ký từ xa\n(Remote HSM)",
        "Replay bị chặn\n(DPoP JTI)",
        "Xác minh Chữ ký\n(OCSP + Chain)"
    ]
    latencies = [avg_req1, avg_req2, avg_ocsp]
    colors = ["#2980b9", "#e74c3c", "#2ecc71"]
    
    bars = ax1.bar(categories, latencies, color=colors, width=0.45, edgecolor='none', alpha=0.9)
    ax1.set_title("So sánh Thời gian Phản hồi (Latency) - Hệ thống Chữ ký số\n(Trung bình đo kiểm 50 lần liên tục)", fontsize=13, fontweight='bold', pad=15)
    ax1.set_ylabel("Thời gian phản hồi trung bình (ms)", fontsize=11, labelpad=10)
    ax1.set_ylim(0, max(latencies) * 1.15)
    
    for bar in bars:
        height = bar.get_height()
        ax1.annotate(f"{height:.2f} ms",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),  # Đẩy lên 3pt
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=10, fontweight='bold')
                    
    ax1.text(1.3, avg_ocsp * 0.7, f"* Ghi chú: Kịch bản Client Malware chạy cục bộ\ntrên máy khách để băm và tráo hash\nchỉ tốn trung bình {avg_malware:.4f} ms\n(không tốn độ trễ kết nối API mạng).", 
             bbox=dict(facecolor='#f8f9fa', alpha=0.9, boxstyle='round,pad=0.5', edgecolor='#e2e8f0'), fontsize=9.5)
             
    ax1.grid(True, axis='y', linestyle='--', alpha=0.7)
    ax1.grid(False, axis='x')
    plt.tight_layout()
    fig1.savefig("attacks/benchmark_latency_avg.png", dpi=300)
    plt.close(fig1)
    print("[✔] Đã tạo biểu đồ 1: attacks/benchmark_latency_avg.png")
    
    # ----------------------------------------------------
    # BIỂU ĐỒ 2: BIẾN THIÊN ĐỘ TRỄ QUA 50 LẦN THỬ (LATENCY TRENDS)
    # ----------------------------------------------------
    fig2, (ax2_top, ax2_bot) = plt.subplots(2, 1, figsize=(10, 7.5), sharex=True)
    
    x = range(1, len(req1_latencies) + 1)
    
    # Subplot trên: Remote HSM & Replay Blocked (khoảng 30-50ms)
    ax2_top.plot(x, req1_latencies, color="#2980b9", label="Ký từ xa (Lần 1)", marker='o', markersize=3, linewidth=1.2)
    ax2_top.plot(x, req2_latencies, color="#e74c3c", label="Replay bị chặn (Lần 2)", marker='x', markersize=3, linestyle='--', linewidth=1.2)
    ax2_top.set_title("Biến thiên Độ trễ theo Từng lần thử (Latency Trends over 50 Iterations)", fontsize=12, fontweight='bold', pad=12)
    ax2_top.set_ylabel("Độ trễ API (ms)", fontsize=10)
    ax2_top.legend(loc="upper right", frameon=True)
    ax2_top.grid(True, linestyle='--', alpha=0.5)
    
    # Subplot dưới: OCSP & PDF Verification (khoảng 700-900ms)
    ax2_bot.plot(x, ocsp_latencies, color="#2ecc71", label="Xác minh OCSP & PDF", marker='^', markersize=3, linewidth=1.2)
    ax2_bot.set_xlabel("Lần đo kiểm (Iteration)", fontsize=11)
    ax2_bot.set_ylabel("Độ trễ Xác minh (ms)", fontsize=10)
    ax2_bot.legend(loc="upper right", frameon=True)
    ax2_bot.grid(True, linestyle='--', alpha=0.5)
    
    plt.tight_layout()
    fig2.savefig("attacks/benchmark_latency_trends.png", dpi=300)
    plt.close(fig2)
    print("[✔] Đã tạo biểu đồ 2: attacks/benchmark_latency_trends.png")
    
    # ----------------------------------------------------
    # BIỂU ĐỒ 3: SỰ PHÂN PHỐI ĐỘ TRỄ (LATENCY BOXPLOTS)
    # ----------------------------------------------------
    fig3, (ax3_left, ax3_right) = plt.subplots(1, 2, figsize=(10, 6))
    
    # Box plot trái: Replay & HSM Sign
    box_data1 = [req1_latencies, req2_latencies]
    bp1 = ax3_left.boxplot(box_data1, patch_artist=True, tick_labels=["Remote HSM", "Replay Blocked"])
    
    colors1 = ["#2980b9", "#e74c3c"]
    for patch, color in zip(bp1['boxes'], colors1):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
        
    ax3_left.set_title("Độ phân tán: Ký từ xa vs Replay", fontsize=11, fontweight='bold')
    ax3_left.set_ylabel("Độ trễ (ms)", fontsize=10)
    ax3_left.grid(True, linestyle='--', alpha=0.5)
    
    # Box plot phải: OCSP & PDF verification
    bp2 = ax3_right.boxplot([ocsp_latencies], patch_artist=True, tick_labels=["OCSP & PDF Verify"])
    bp2['boxes'][0].set_facecolor("#2ecc71")
    bp2['boxes'][0].set_alpha(0.7)
    
    ax3_right.set_title("Độ phân tán: Xác minh OCSP", fontsize=11, fontweight='bold')
    ax3_right.set_ylabel("Độ trễ (ms)", fontsize=10)
    ax3_right.grid(True, linestyle='--', alpha=0.5)
    
    fig3.suptitle("Biểu đồ Hộp Phân phối và Khoảng sai số (Latency Boxplots)", fontsize=13, fontweight='bold', y=0.98)
    plt.tight_layout()
    fig3.savefig("attacks/benchmark_latency_distribution.png", dpi=300)
    plt.close(fig3)
    print("[✔] Đã tạo biểu đồ 3: attacks/benchmark_latency_distribution.png")

if __name__ == "__main__":
    main()
