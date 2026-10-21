# BÀI TẬP 2: MÃ HÓA BẤT ĐỐI XỨNG RSA & CHỮ KÝ SỐ (.NET C#)

**Họ và tên:** Nguyễn Thị Ngọc Linh  
**Lớp:** K59KTP.K01 (K59KMT.K01)  
**Môn học:** An toàn và bảo mật thông tin  
**Nền tảng:** .NET 10.0 (C# Windows Forms Application & CLI Runner)

---

## 1. Kiến trúc chương trình và Giải pháp kỹ thuật

Chương trình được xây dựng trên nền tảng **.NET 10.0 (C#)** theo kiến trúc hướng đối tượng hiện đại, kết hợp giao diện đồ họa **Windows Forms (Soft Pastel Aesthetic)** trang nhã và chế độ **CLI Runner** tự động hóa kiểm thử. Ứng dụng đáp ứng toàn diện và chuyên sâu 9 yêu cầu nghiệp vụ về mật mã bất đối xứng:

* **Thư viện mật mã:** Sử dụng các API chuẩn an toàn của hệ điều hành: `System.Security.Cryptography.RSA`, `System.Formats.Asn1` (phân tích DER TLV), và `System.Security.Cryptography.SHA256`.
* **Độ dài khóa RSA:** Hỗ trợ linh hoạt các kích thước tiêu chuẩn: **1024-bit**, **2048-bit** (khuyến nghị NIST), và **4096-bit** (bảo mật cấp cao).
* **Định dạng khóa:** Xuất và nạp chuẩn **PEM (Privacy-Enhanced Mail)** theo đặc tả **PKCS#1** (`-----BEGIN RSA PUBLIC/PRIVATE KEY-----`), **PKCS#8** và **X.509 SubjectPublicKeyInfo**.
* **Đệm mã hóa (Padding):** Hỗ trợ **OAEP-SHA256** (Optimal Asymmetric Encryption Padding - chuẩn an toàn chống tấn công đệm Bleichenbacher) và **PKCS#1 v1.5**.
* **Mô hình mã hóa lai (Hybrid Encryption):** Sử dụng RSA để đóng gói (wrap/encapsulate) khóa đối xứng **AES-256** (`32 bytes` = `256 bits`), tuân thủ tuyệt đối giới hạn dữ liệu $\le 190$ bytes của RSA 2048-bit.
* **Cơ chế chữ ký số:** Hỗ trợ chuẩn **RSASSA-PKCS1-v1_5** và chuẩn ngẫu nhiên **RSASSA-PSS (RFC 8017)** với Muối ngẫu nhiên (Random Salt) giúp tạo chữ ký khác nhau mỗi lần ký cho cùng 1 dữ liệu.

---

## 2. Kết quả thực nghiệm chi tiết theo 9 yêu cầu đề bài

---

### 2.1. Sinh cặp khóa & Xuất ra file PEM (Yêu cầu 1 & 2)
Cặp khóa RSA 2048-bit được tạo tự động bằng thuật toán sinh số nguyên tố lớn ngẫu nhiên `RSA.Create(2048)`. Hai file PEM được xuất và lưu trữ thành công:
* **Public Key:** [`rsa_public_key.pem`](./rsa_public_key.pem) (Chuẩn PKCS#1, dung lượng 426 bytes).
* **Private Key:** [`rsa_private_key.pem`](./rsa_private_key.pem) (Chuẩn PKCS#1, dung lượng 1.674 bytes).

---

### 2.2. Phân tích cấu trúc format PEM & Bóc tách ASN.1 DER (Yêu cầu 3 & 4)

#### a) Định dạng PEM
PEM là dạng mã hóa Base64 của chuỗi nhị phân **DER (Distinguished Encoding Rules)** theo chuẩn **ASN.1 (Abstract Syntax Notation One)**, được kẹp giữa 2 dòng Header và Footer:
```text
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAw8x6... (Chuỗi dữ liệu Base64) ...aP4Aw==
-----END RSA PRIVATE KEY-----
```

#### b) Cấu trúc cây dữ liệu ASN.1 DER và ý nghĩa từng Byte/Trường:
Chuỗi DER bắt đầu bằng Tag `0x30` (`SEQUENCE`) bao gói danh sách các số nguyên lớn `0x02` (`INTEGER`):

| Tag ASN.1 | Tên trường | Ký hiệu toán học | Kích thước | Ý nghĩa & Vai trò trong hệ mật RSA |
| :--- | :--- | :--- | :--- | :--- |
| `0x02` (INTEGER) | **Version** | $v$ | 1 byte | Phiên bản RSA (`0x00` = two-prime tiêu chuẩn; `0x01` = multi-prime). |
| `0x02` (INTEGER) | **Modulus** | $n = p \times q$ | 256 bytes (2048 bits) | Số modulo công khai dùng chung cho cả quá trình mã hóa và giải mã. |
| `0x02` (INTEGER) | **Public Exponent** | $e$ | 3 bytes (17 bits) | Số mũ công khai. Luôn chọn giá trị số nguyên tố Fermat $F_4 = 65537$ (`0x010001`). |
| `0x02` (INTEGER) | **Private Exponent** | $d \equiv e^{-1} \pmod{\phi(n)}$ | 256 bytes (2048 bits) | Số mũ bí mật tối cao, nghịch đảo modulo của $e$ theo hàm Euler $\phi(n) = (p-1)(q-1)$. |
| `0x02` (INTEGER) | **Prime 1** | $p$ | 128 bytes (1024 bits) | Số nguyên tố lớn thứ nhất bí mật cấu thành nên $n$. |
| `0x02` (INTEGER) | **Prime 2** | $q$ | 128 bytes (1024 bits) | Số nguyên tố lớn thứ hai bí mật cấu thành nên $n$ ($p \neq q$). |
| `0x02` (INTEGER) | **Exponent 1** | $d_p = d \pmod{p-1}$ | 128 bytes (1024 bits) | Số mũ rút gọn theo modulo $p-1$, dùng cho **Định lý số dư Trung Hoa (CRT)**. |
| `0x02` (INTEGER) | **Exponent 2** | $d_q = d \pmod{q-1}$ | 128 bytes (1024 bits) | Số mũ rút gọn theo modulo $q-1$, dùng cho **Định lý số dư Trung Hoa (CRT)**. |
| `0x02` (INTEGER) | **Coefficient** | $iqmp = q^{-1} \pmod p$ | 128 bytes (1024 bits) | Hệ số nghịch đảo nhân CRT theo công thức Garner để ghép nghiệm giải mã siêu tốc. |

#### c) Kết quả trích xuất tham số thực tế từ file PEM:
* **Modulus $n$ (Hex Preview):**
  `CC 83 51 98 06 22 BC FF A8 8A FA 2D 31 D4 B5 1A ... [208 bytes] ... D8 47 F3 F8 08 81 A2 F7 84 BD 20 BD`
* **Public Exponent $e$:** `65537` (`0x010001`).
* **Private Exponent $d$ (Hex Preview):**
  `89 02 3C AA 6D 09 DE B6 23 B2 9F 71 A1 9D 8F 8A ... [208 bytes] ... 36 54 D9 9D FA 45 A0 A3 1F 17 1A 3D`

---

### 2.3. Mã hóa & Giải mã dữ liệu $\le 190$ bytes (Khóa AES-256) (Yêu cầu 5 & 6)

#### a) Lý do dữ liệu đầu vào $\le 190$ bytes:
Với khóa RSA 2048-bit, kích thước modulus là $2048 / 8 = 256$ bytes. Khi sử dụng cơ chế đệm an toàn **OAEP with SHA-256**, phần đệm tiêu tốn:
$$\text{Max Plaintext} = \text{KeyBytes} - 2 \times \text{HashBytes} - 2 = 256 - 2 \times 32 - 2 = 190 \text{ bytes}$$
Đây là lý do đề bài chỉ định rõ: *"dữ liệu là 1 mảng byte không quá 190 byte (ví dụ khóa AES 256 bit <=> 32 byte base64)"*.

#### b) Bảng số liệu thực nghiệm mã hóa và đối chiếu:

| Tiêu chí | Dữ liệu gốc (Khóa AES) | Bản mã sau khi mã hóa (RSA-2048) | Kết quả sau khi giải mã |
| :--- | :--- | :--- | :--- |
| **Dung lượng** | **32 bytes** (Base64: 44 ký tự) | **256 bytes** (Base64: 344 ký tự) | **32 bytes** (Base64: 44 ký tự) |
| **Giá trị** | `FdK0zE8oO6R0KMUre/oTHYO+5tw38YtHETCarPgtRW8=` | `ZACmSi3ouhQAG9VNCSF1X6SeFinI1lHX...` | `FdK0zE8oO6R0KMUre/oTHYO+5tw38YtHETCarPgtRW8=` |
| **Lưu trữ** | [`sample_aes_key.txt`](./sample_aes_key.txt) | [`rsa_encrypted_aes_key.base64`](./rsa_encrypted_aes_key.base64) | - |
| **Đối chiếu Byte** | - | Khác biệt hoàn toàn (Mã hóa mạnh) | **KHỚP 100% (SequenceEqual = True)** |

---

### 2.4. Đo lường & Đánh giá tốc độ mã hóa vs giải mã (Benchmark) (Yêu cầu 7)

Thực nghiệm đo đạc thực tế trên cùng một CPU thông qua 500 phép tính mã hóa/giải mã liên tục với RSA 2048-bit:

| Phép toán | Khóa sử dụng | Độ dài số mũ | Tổng thời gian (500 lần) | Tốc độ xử lý trung bình |
| :--- | :--- | :--- | :--- | :--- |
| **Mã hóa (hoặc Verify)** | **Public Key** ($n, e$) | $e = 65537$ (**17 bits**) | **10,04 ms** | **49.778,0 phép tính/giây** (`ops/s`) |
| **Giải mã (hoặc Sign)** | **Private Key** ($n, d$) | $d \approx$ **2048 bits** | **302,19 ms** | **1.654,6 phép tính/giây** (`ops/s`) |
| **TỶ LỆ CHÊNH LỆCH** | - | - | - | **PUBLIC KEY NHANH GẤP 30,1 LẦN!** |

#### 💡 Giải thích cơ chế toán học tại sao có sự chênh lệch lớn này:
1. **Phép toán Public Key ($C = M^e \pmod n$):**
   * Số mũ $e = 65537 = 2^{16} + 1$. Ở dạng nhị phân, $e = \text{0b10000000000000001}$ (chỉ có đúng **2 bit 1**).
   * Thuật toán lũy thừa nhị phân (**Square-and-Multiply**) chỉ cần **16 phép bình phương** và **1 phép nhân** modulo $n$.
   * Vì vậy, chi phí tính toán của CPU là cực kỳ thấp $\rightarrow$ Tốc độ đạt gần **50.000 phép tính/giây**.

2. **Phép toán Private Key ($M = C^d \pmod n$):**
   * Số mũ bí mật $d$ là một số nguyên 2048-bit ngẫu nhiên. Trung bình có khoảng $50\%$ số bit mang giá trị 1 (**~1024 bit 1**).
   * Thuật toán Square-and-Multiply bắt buộc phải thực hiện **~2047 phép bình phương** và **~1024 phép nhân số nguyên lớn**.
   * Dù .NET đã áp dụng kỹ thuật tối ưu hóa cao cấp **Định lý số dư Trung Hoa (CRT)** tính riêng trên 2 nửa $d_p, d_q$ theo modulo 1024-bit $p, q$, phép tính Private Key vẫn tốn nhiều chu kỳ xử lý của CPU hơn gấp **30 lần**.

---

### 2.5. Giao diện sinh chuỗi băm SHA-256 & Hiệu ứng Tuyết lở (Avalanche Effect) (Yêu cầu 8)

Hàm băm mật mã an toàn bắt buộc phải có **Hiệu ứng tuyết lở (Avalanche Effect)**: chỉ cần thay đổi dù chỉ 1 bit ở đầu vào thì toàn bộ chuỗi băm đầu ra phải bị biến đổi ngẫu nhiên khoảng $50\%$ số bit.

#### Bảng thực nghiệm đối chiếu bit khi đổi 1 ký tự:
* **Chuỗi gốc (Baseline):** `"Nguyen Thi Ngoc Linh - K59KTP.K01"`  
  $\rightarrow$ **SHA-256:** `eb69f9dedd33724b32f663c09bfef0fc9790228432a9d48be0462136492d501a`
* **Chuỗi thay đổi (Chỉ sửa chữ cái 'N' thành 'n'):** `"nguyen Thi Ngoc Linh - K59KTP.K01"`  
  $\rightarrow$ **SHA-256:** `6e893cb7b4ec173aec59450b09c7e2806d009c2207808cf8be7b3962215d299e`

#### Kết quả phân tích nhị phân (Hamming Distance):
* **Số bit biến đổi:** **128 / 256 bits**
* **Tỷ lệ biến đổi (Avalanche Rate):** đúng **50,00%** (khớp hoàn hảo với mức kỳ vọng lý thuyết xác suất ngẫu nhiên).
* **Kết luận:** Hàm băm SHA-256 đạt tiêu chuẩn mật mã học tuyệt đối, ngăn chặn hoàn toàn khả năng đảo ngược hoặc tấn công tìm tiền ảnh (pre-image attack).

---

### 2.6. Chữ ký số (Digital Signature) & Đề xuất giải pháp chữ ký ngẫu nhiên (Yêu cầu 9)

#### a) Khái niệm Chữ ký số RSA
Chữ ký số là kết quả mã hóa giá trị băm (Hash) của dữ liệu bằng **Private Key** của người ký:
$$S = \text{Hash}(M)^d \pmod n$$
Người nhận kiểm tra tính hợp lệ bằng **Public Key** của người ký:
$$V = S^e \pmod n \stackrel{?}{=} \text{Hash}(M)$$
Nếu khớp: xác nhận dữ liệu vẹn toàn 100% và đúng xuất xứ từ người sở hữu Private Key. Nếu dữ liệu bị hacker chỉnh sửa dù chỉ 1 dấu cách, chữ ký lập tức bị từ chối (**INVALID**).

#### b) Đề xuất giải pháp: Cùng 1 dữ liệu, Cùng 1 người ký $\rightarrow$ Chữ ký khác nhau mỗi lần ký
* **Vấn đề đặt ra:** Nếu dùng chuẩn đệm cũ deterministic (như PKCS#1 v1.5), với cùng 1 nội dung và cùng 1 private key, lần ký nào cũng ra một chuỗi chữ ký giống hệt nhau. Kẻ tấn công có thể nghe lén và thực hiện tấn công phát lại (**Replay Attack**).
* **Giải pháp đề xuất chuẩn quốc tế:** Áp dụng chuẩn **RSASSA-PSS (Probabilistic Signature Scheme - RFC 8017 / PKCS#1 v2.2)**:
  * **Cơ chế hoạt động:** Trong mỗi lần ký, hàm `RSA.SignData(..., RSASignaturePadding.Pss)` tự động sinh một chuỗi **Muối ngẫu nhiên (Random Salt)** gồm 32 bytes từ bộ sinh số ngẫu nhiên mật mã (CSPRNG).
  * Chuỗi muối này được trộn với mã băm dữ liệu qua hàm sinh mặt nạ **MGF1 (Mask Generation Function)** trước khi đưa vào lũy thừa số mũ bí mật $d$.
  * Nhờ chuỗi muối ngẫu nhiên độc lập này, **mỗi lần bấm nút Ký, ta thu được một chữ ký số Base64 hoàn toàn khác nhau 100%**.
  * **Cách thức xác thực:** Khi người nhận kiểm tra, Public Key sẽ giải mã khối PSS, bóc tách chuỗi muối ngẫu nhiên và tính toán lại giá trị băm kiểm chứng. Do đó, **cùng 1 Public Key có thể xác minh thành công toàn bộ các chữ ký ngẫu nhiên đó** mà không cần biết trước chuỗi muối!
* **Giải pháp bổ trợ (Application-level):** Đóng gói thêm trường **Timestamp** (thời điểm ký chính xác đến mili-giây) hoặc số ngẫu nhiên dùng một lần **Nonce** vào cấu trúc văn bản ký (chuẩn CMS / CAdES / XAdES).

#### c) Bảng kiểm chứng thực tế với RSASSA-PSS trên cùng 1 văn bản:
* **Dữ liệu ký:** `"Hop Dong Mua Ban - 100.000.000 VND"`
* **Khóa ký:** Cùng 1 Private Key RSA 2048-bit

| Lần ký | Chuẩn đệm | Chữ ký số thu được (Base64 Preview) | Xác thực bằng Public Key |
| :--- | :--- | :--- | :--- |
| **Lần ký 1** | RSASSA-PSS (Salt 1) | `jKJOQNmoxaaAuz1eZ/zie/rIf9xoLLQ/OJT...` | **HỢP LỆ (Valid = True) ✅** |
| **Lần ký 2** | RSASSA-PSS (Salt 2) | `t5uL/vf+b72gVkEan2Ms5d8agO6C9DN7A4o...` | **HỢP LỆ (Valid = True) ✅** |
| **Lần ký 3** | RSASSA-PSS (Salt 3) | `C/1u0T3CRlabpRZEfMsgcnFT0KaoXzqT9UY...` | **HỢP LỆ (Valid = True) ✅** |

$\Rightarrow$ **Kết luận:** Cả 3 chữ ký khác biệt nhau 100% nhưng đều được xác minh HỢP LỆ tuyệt đối với cùng một Public Key!

---

## 3. Hướng dẫn chạy và sử dụng phần mềm

### Cách 1: Khởi chạy giao diện đồ họa GUI (Windows Forms)
1. Mở file giải pháp [`BaiTap2_RSA.slnx`](./BaiTap2_RSA.slnx) bằng **Visual Studio 2022 / Rider / VS Code**.
2. Nhấn `F5` hoặc chạy lệnh PowerShell:
   ```powershell
   dotnet run --project BaiTap2_RSA\BaiTap2_RSA\BaiTap2_RSA.csproj
   ```
3. Giao diện sẽ hiển thị đầy đủ 6 tab trực quan, tự động sinh sẵn cặp khóa mẫu và sẵn sàng tương tác mọi tính năng.

### Cách 2: Chạy kiểm thử tự động toàn diện qua CLI Runner
```powershell
dotnet run --project BaiTap2_RSA\BaiTap2_RSA\BaiTap2_RSA.csproj -- --cli
```
Lệnh sẽ tự động chạy thông suốt cả 9 yêu cầu, in báo cáo chi tiết ra màn hình console và tạo các file mẫu `.pem`, `.base64`.
