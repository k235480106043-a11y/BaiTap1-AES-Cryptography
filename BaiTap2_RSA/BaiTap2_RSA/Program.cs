namespace BaiTap2_RSA;

static class Program
{
    /// <summary>
    ///  The main entry point for the application.
    /// </summary>
    [STAThread]
    static void Main(string[] args)
    {
        if (args.Length > 0 && (args[0] == "--samples" || args[0] == "--cli"))
        {
            RunCliMode();
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }

    static void RunCliMode()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("===============================================================");
        Console.WriteLine("💜 BÀI 2: MÃ HÓA RSA & CHỮ KÝ SỐ (.NET 10.0)");
        Console.WriteLine("🌸 Sinh viên: Nguyễn Thị Ngọc Linh - Lớp: K59KTP.K01");
        Console.WriteLine("===============================================================");

        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string targetDir = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", ".."));

        // 1 & 2. Sinh khóa & Xuất file PEM
        Console.WriteLine("\n[1 & 2] Đang sinh cặp khóa RSA 2048-bit...");
        var (pubPem, privPem, rsa) = RsaHelper.GenerateKeyPair(2048);

        string pubPath = Path.Combine(targetDir, "rsa_public_key.pem");
        string privPath = Path.Combine(targetDir, "rsa_private_key.pem");
        File.WriteAllText(pubPath, pubPem, System.Text.Encoding.UTF8);
        File.WriteAllText(privPath, privPem, System.Text.Encoding.UTF8);
        Console.WriteLine($"✅ Đã xuất Public Key: {pubPath}");
        Console.WriteLine($"✅ Đã xuất Private Key: {privPath}");

        // 3 & 4. Phân tích cấu trúc PEM
        Console.WriteLine("\n[3 & 4] Phân tích cấu trúc PEM & ASN.1 DER Private Key:");
        var detail = RsaHelper.AnalyzePem(privPem, rsa);
        Console.WriteLine(detail.GetParamSummary());

        // 5 & 6. Mã hóa & Giải mã khóa AES (32 bytes)
        Console.WriteLine("\n[5 & 6] Thử nghiệm mã hóa khóa AES 256-bit (32 bytes):");
        byte[] aesKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(aesKey);
        string aesB64 = Convert.ToBase64String(aesKey);
        string aesPlainPath = Path.Combine(targetDir, "sample_aes_key.txt");
        File.WriteAllText(aesPlainPath, aesB64, System.Text.Encoding.UTF8);
        Console.WriteLine($"🔑 Khóa AES gốc (Base64): {aesB64}");

        byte[] plainBytes = System.Text.Encoding.UTF8.GetBytes(aesB64);
        byte[] cipherBytes = RsaHelper.Encrypt(rsa, plainBytes, true);
        string cipherB64 = Convert.ToBase64String(cipherBytes);
        string cipherPath = Path.Combine(targetDir, "rsa_encrypted_aes_key.base64");
        File.WriteAllText(cipherPath, cipherB64, System.Text.Encoding.UTF8);
        Console.WriteLine($"🔒 Ciphertext (Base64 - {cipherBytes.Length} bytes): {cipherB64.Substring(0, 40)}...");
        Console.WriteLine($"💾 Đã lưu file mã hóa: {cipherPath}");

        byte[] decBytes = RsaHelper.Decrypt(rsa, cipherBytes, true);
        string decText = System.Text.Encoding.UTF8.GetString(decBytes);
        bool match = decBytes.SequenceEqual(plainBytes);
        Console.WriteLine($"🔓 Giải mã ngược lại: {decText}");
        Console.WriteLine($"🎉 Đối chiếu Byte-by-Byte: {(match ? "KHỚP 100% ✅" : "SAI LỆCH ❌")}");

        // 7. Benchmark
        Console.WriteLine("\n[7] Chạy Benchmark tốc độ (500 lần lặp):");
        var bench = RsaHelper.RunBenchmark(rsa, 500);
        Console.WriteLine(bench.GetDetailedReport());

        // 8. SHA-256 Avalanche Effect
        Console.WriteLine("\n[8] Đánh giá Avalanche Effect với SHA-256:");
        string t1 = "Nguyen Thi Ngoc Linh - K59KTP.K01";
        string t2 = "nguyen Thi Ngoc Linh - K59KTP.K01"; // chỉ đổi chữ hoa thành thường
        byte[] h1 = RsaHelper.ComputeSha256(System.Text.Encoding.UTF8.GetBytes(t1));
        byte[] h2 = RsaHelper.ComputeSha256(System.Text.Encoding.UTF8.GetBytes(t2));
        var (flipped, total, pct, _, _) = RsaHelper.EvaluateAvalanche(h1, h2);
        Console.WriteLine($"   Chuỗi 1: '{t1}' -> Hash: {Convert.ToHexString(h1).ToLower()}");
        Console.WriteLine($"   Chuỗi 2: '{t2}' -> Hash: {Convert.ToHexString(h2).ToLower()}");
        Console.WriteLine($"   ⚡ Đổi 1 ký tự: Lật {flipped}/{total} bits ({pct:F2}% ~ 50% tối ưu)");

        // 9. Digital Signature & PSS
        Console.WriteLine("\n[9] Thử nghiệm chữ ký số & Cơ chế PSS (RFC 8017):");
        byte[] docBytes = System.Text.Encoding.UTF8.GetBytes("Hop Dong Mua Ban - 100.000.000 VND");
        byte[] sig1 = RsaHelper.SignData(rsa, docBytes, true);
        byte[] sig2 = RsaHelper.SignData(rsa, docBytes, true);
        byte[] sig3 = RsaHelper.SignData(rsa, docBytes, true);
        Console.WriteLine($"   Chữ ký PSS 1: {Convert.ToBase64String(sig1).Substring(0, 35)}...");
        Console.WriteLine($"   Chữ ký PSS 2: {Convert.ToBase64String(sig2).Substring(0, 35)}...");
        Console.WriteLine($"   Chữ ký PSS 3: {Convert.ToBase64String(sig3).Substring(0, 35)}...");
        bool v1 = RsaHelper.VerifyData(rsa, docBytes, sig1, true);
        bool v2 = RsaHelper.VerifyData(rsa, docBytes, sig2, true);
        bool v3 = RsaHelper.VerifyData(rsa, docBytes, sig3, true);
        Console.WriteLine($"   ✅ Xác thực cả 3 chữ ký với cùng Public Key: v1={v1}, v2={v2}, v3={v3}");
        Console.WriteLine("\n================== HOÀN TẤT THỬ NGHIỆM ==================");
    }
}