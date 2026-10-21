# AES_RSA_BAITAP: HỆ THỐNG MÃ HÓA MẬT MÃ AES & RSA (.NET C#)

**Học phần:** An toàn và bảo mật thông tin  
**Sinh viên thực hiện:** Nguyễn Thị Ngọc Linh  
**Lớp:** K59KTP.K01 (K59KMT.K01)  
**Nền tảng:** .NET 10.0 (C# Windows Forms Application - Soft Pastel Aesthetic & CLI Automation)

---

## 📌 Tổng quan đồ án (Repository Overview)

Repository này chứa trọn bộ chương trình thực nghiệm và báo cáo khoa học của 2 bài tập lớn môn **An toàn và bảo mật thông tin**, bao gồm đầy đủ mã hóa đối xứng (Symmetric Cryptography - AES) và mã hóa bất đối xứng (Asymmetric Cryptography - RSA) kết hợp Chữ ký số và hàm băm SHA-256.

```
📁 AES_RSA_BAITAP/
├── 📄 AES_RSA_BAITAP.txt       # Đề bài và yêu cầu chi tiết môn học
├── 📄 README.md                # Tài liệu tổng quan (file hiện tại)
├── 📁 BaiTap1_AES/             # BÀI 1: MÃ HÓA ĐỐI XỨNG AES-256
│   ├── 📁 BaiTap1_AES/         # Mã nguồn dự án C# Windows Forms (.NET 10.0)
│   ├── 📄 BaiTap1_AES.slnx     # Visual Studio Solution
│   ├── 📄 README.md            # Báo cáo chi tiết Bài 1 (Đo đạc file 1GB, bảng số liệu)
│   ├── 📄 aes_key.txt          # Khóa AES-256 (32 bytes) & IV (16 bytes) mẫu
│   └── 📁 images/              # Ảnh chụp màn hình minh chứng thực nghiệm Bài 1
│
└── 📁 BaiTap2_RSA/             # BÀI 2: MÃ HÓA BẤT ĐỐI XỨNG RSA & CHỮ KÝ SỐ
    ├── 📁 BaiTap2_RSA/         # Mã nguồn dự án C# Windows Forms & CLI (.NET 10.0)
    │   ├── Program.cs          # Điểm khởi chạy app & Runner tự động CLI
    │   ├── MainForm.cs         # Giao diện chính 6 Tabs Soft Pastel Aesthetic
    │   ├── RsaHelper.cs        # Xử lý ASN.1 DER TLV, RSA, Benchmark, PSS
    │   └── CustomControls.cs   # Custom rounded button, card, badge
    ├── 📄 BaiTap2_RSA.sln      # Solution chuẩn cho Visual Studio
    ├── 📄 BaiTap2_RSA.slnx     # Solution định dạng mới
    ├── 📄 README.md            # Báo cáo chi tiết Bài 2 (ASN.1 TLV, Benchmark, PSS)
    ├── 📄 rsa_public_key.pem   # Khóa công khai RSA 2048-bit mẫu (PKCS#1)
    ├── 📄 rsa_private_key.pem  # Khóa bí mật RSA 2048-bit mẫu (PKCS#1)
    ├── 📄 sample_aes_key.txt   # Khóa AES 256-bit (32 bytes) mẫu dùng để mã hóa
    └── 📄 rsa_encrypted_aes_key.base64 # Bản mã RSA của khóa AES (Base64)
```

---

## 🚀 Tóm tắt nội dung 2 bài tập

### 💖 1. [Bài Tập 1: Mã Hóa Đối Xứng AES-256 (CBC • PKCS7)](./BaiTap1_AES/README.md)
* **Kích thước khóa:** AES 256-bit (`32 bytes`), Vector khởi tạo IV (`16 bytes`).
* **Tính năng:**
  1. Sinh khóa AES và IV ngẫu nhiên an toàn mật mã (`RandomNumberGenerator`).
  2. Xuất khóa ra file [`aes_key.txt`](./BaiTap1_AES/aes_key.txt).
  3. Import khóa từ file vào chương trình.
  4. Mã hóa đoạn văn bản xuất kết quả Base64/Hex ra màn hình và giải mã đối chiếu.
  5. **Thực nghiệm File lớn (1 GB - 1.073.741.824 bytes):**
     * Thời gian mã hóa: **1,739 giây** (Tốc độ: **588,85 MB/s**).
     * Thời gian giải mã: **1,195 giây** (Tốc độ: **856,75 MB/s**).
     * Đối chiếu từng byte (`Byte-by-Byte`): **GIỐNG NHAU 100%**.
     * Giải thích chi tiết hiện tượng file tăng 16 bytes theo cơ chế đệm **PKCS7**.
* Chi tiết xem tại: 👉 [**README Bài 1**](./BaiTap1_AES/README.md)

---

### 💜 2. [Bài Tập 2: Mã Hóa Bất Đối Xứng RSA & Chữ Ký Số](./BaiTap2_RSA/README.md)
* **Độ dài khóa:** Hỗ trợ 1024, 2048 (khuyên dùng), 4096-bit.
* **Tính năng:**
  1. **Sinh cặp khóa RSA:** Tự động tạo cặp khóa chuẩn mật mã.
  2. **Xuất file PEM:** Chuẩn PKCS#1 (`BEGIN RSA PUBLIC/PRIVATE KEY`) và PKCS#8.
  3. **Phân tích ASN.1 DER:** Bóc tách ý nghĩa từng byte/trường (`Version`, `Modulus n`, `Exponent e`, `Private Exponent d`, `Prime 1 p`, `Prime 2 q`, `dp`, `dq`, `iqmp`).
  4. **Import PEM:** Trích xuất $(n, e)$ cho Public Key và $(n, e, d, p, q, \dots)$ cho Private Key.
  5. **Mã hóa dữ liệu $\le 190$ bytes:** Mô hình bọc khóa đối xứng AES-256 (32 bytes) bằng RSA-2048 OAEP-SHA256.
  6. **Giải mã & Đối chiếu:** Đọc file Base64, giải mã bằng Private Key $\rightarrow$ Khớp **100%**.
  7. **Benchmark tốc độ:** So sánh Public Key ($e = 65537$ nhỏ) vs Private Key ($d$ lớn):
     * Public Key: **~49.778 ops/s** (Lũy thừa nhị phân chỉ mất 17 phép tính).
     * Private Key: **~1.654 ops/s** (Phải tính hàng ngàn phép nhân số lớn dù có CRT).
     * $\Rightarrow$ **Public Key nhanh hơn gấp ~30 lần!**
  8. **Băm SHA-256 & Hiệu ứng Tuyết lở (Avalanche Effect):** Đổi 1 ký tự $\rightarrow$ Đảo lật **128/256 bits (50,00%)** ở đầu ra.
  9. **Chữ ký số & Đề xuất cơ chế chữ ký ngẫu nhiên:**
     * Đề xuất chuẩn **RSASSA-PSS (RFC 8017)** với **Random Salt (Muối ngẫu nhiên)**.
     * Cùng 1 dữ liệu, cùng 1 người ký $\rightarrow$ Mỗi lần ký tạo ra 1 chữ ký số khác nhau 100%, nhưng cùng 1 Public Key vẫn xác thực hợp lệ tuyệt đối.
* Chi tiết xem tại: 👉 [**README Bài 2**](./BaiTap2_RSA/README.md)

---

## 🛠️ Hướng dẫn khởi chạy

Cả hai dự án đều được viết bằng **.NET 10.0 C#** và có thể mở trực tiếp trong Visual Studio 2022 / Rider / VS Code:

### Chạy Bài 1 (AES):
```powershell
dotnet run --project BaiTap1_AES\BaiTap1_AES\BaiTap1_AES.csproj
```

### Chạy Bài 2 (RSA & Chữ ký số):
* **Giao diện đồ họa (GUI):**
  ```powershell
  dotnet run --project BaiTap2_RSA\BaiTap2_RSA\BaiTap2_RSA.csproj
  ```
* **Chế độ kiểm thử tự động (CLI):**
  ```powershell
  dotnet run --project BaiTap2_RSA\BaiTap2_RSA\BaiTap2_RSA.csproj -- --cli
  ```
