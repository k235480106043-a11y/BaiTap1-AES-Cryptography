using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace BaiTap1_AES
{
    class Program
    {
        // Biến toàn cục lưu giữ Key (32 bytes = 256 bit) và IV (16 bytes = 128 bit) hiện tại
        static byte[] currentKey;
        static byte[] currentIV;

        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            while (true)
            {
                Console.WriteLine("\n================ BÀI 1: MÃ HÓA ĐỐI XỨNG AES ================");
                Console.WriteLine("1. Sinh khóa AES (256-bit)");
                Console.WriteLine("2. Lưu khóa ra file");
                Console.WriteLine("3. Import khóa từ file");
                Console.WriteLine("4. Mã hóa & Giải mã 1 đoạn văn bản -> Xuất ra màn hình");
                Console.WriteLine("5. Mã hóa, Giải mã File lớn (Hàng GB) & So sánh Bytes");
                Console.WriteLine("6. [Tiện ích] Tạo file giả lập dung lượng lớn (VD: 1GB) để test");
                Console.WriteLine("0. Thoát");
                Console.Write("Chọn chức năng (0-6): ");

                string choice = Console.ReadLine();
                Console.WriteLine("------------------------------------------------------------");

                try
                {
                    switch (choice)
                    {
                        case "1":
                            GenerateAESKey();
                            break;
                        case "2":
                            SaveKeyToFile("aes_key.txt");
                            break;
                        case "3":
                            LoadKeyFromFile("aes_key.txt");
                            break;
                        case "4":
                            EncryptDecryptTextDemo();
                            break;
                        case "5":
                            EncryptDecryptLargeFileDemo();
                            break;
                        case "6":
                            CreateDummyLargeFile("test_1GB.bin", 1024); // Tạo file 1024 MB = 1 GB
                            break;
                        case "0":
                            return;
                        default:
                            Console.WriteLine("Lựa chọn không hợp lệ!");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[LỖI]: {ex.Message}");
                }
            }
        }

        // =========================================================================
        // 1. SINH KHÓA AES
        // =========================================================================
        static void GenerateAESKey()
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256; // Sử dụng khóa 256-bit (32 bytes) bảo mật cao nhất
                aes.GenerateKey();
                aes.GenerateIV();

                currentKey = aes.Key;
                currentIV = aes.IV;

                Console.WriteLine("-> Đã sinh khóa AES-256 thành công!");
                Console.WriteLine($"- Key (Base64): {Convert.ToBase64String(currentKey)} ({currentKey.Length} bytes)");
                Console.WriteLine($"- IV  (Base64): {Convert.ToBase64String(currentIV)} ({currentIV.Length} bytes)");
            }
        }

        // =========================================================================
        // 2. LƯU KHÓA RA FILE
        // =========================================================================
        static void SaveKeyToFile(string filePath)
        {
            CheckKeyExists();
            // Lưu dòng 1 là Key, dòng 2 là IV dưới dạng chuỗi Base64
            string[] lines = {
                Convert.ToBase64String(currentKey),
                Convert.ToBase64String(currentIV)
            };
            File.WriteAllLines(filePath, lines);
            Console.WriteLine($"-> Đã lưu khóa và IV ra file: {Path.GetFullPath(filePath)}");
        }

        // =========================================================================
        // 3. IMPORT KHÓA TỪ FILE
        // =========================================================================
        static void LoadKeyFromFile(string filePath)
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine($"Không tìm thấy file khóa '{filePath}'!");
                return;
            }

            string[] lines = File.ReadAllLines(filePath);
            if (lines.Length < 2)
                throw new Exception("File khóa không đúng định dạng (cần 2 dòng chứa Key và IV).");

            currentKey = Convert.FromBase64String(lines[0]);
            currentIV = Convert.FromBase64String(lines[1]);

            Console.WriteLine($"-> Đã import khóa thành công từ file: {filePath}");
            Console.WriteLine($"- Key (Base64): {Convert.ToBase64String(currentKey)}");
            Console.WriteLine($"- IV  (Base64): {Convert.ToBase64String(currentIV)}");
        }

        // =========================================================================
        // 4. MÃ HÓA 1 ĐOẠN VĂN BẢN -> KẾT QUẢ RA MÀN HÌNH
        // =========================================================================
        static void EncryptDecryptTextDemo()
        {
            CheckKeyExists();
            Console.Write("Nhập đoạn văn bản cần mã hóa: ");
            string plainText = Console.ReadLine();

            // Mã hóa
            byte[] cipherBytes;
            using (Aes aes = Aes.Create())
            {
                aes.Key = currentKey;
                aes.IV = currentIV;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
                        cs.Write(inputBytes, 0, inputBytes.Length);
                        cs.FlushFinalBlock();
                    }
                    cipherBytes = ms.ToArray();
                }
            }

            string cipherBase64 = Convert.ToBase64String(cipherBytes);
            Console.WriteLine($"\n[+] Kết quả Mã hóa (Base64): {cipherBase64}");
            Console.WriteLine($"[+] Kết quả Mã hóa (Hex)   : {BitConverter.ToString(cipherBytes).Replace("-", "")}");

            // Giải mã kiểm chứng ngay trên màn hình
            using (Aes aes = Aes.Create())
            {
                aes.Key = currentKey;
                aes.IV = currentIV;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream(cipherBytes))
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (StreamReader sr = new StreamReader(cs, Encoding.UTF8))
                {
                    string decryptedText = sr.ReadToEnd();
                    Console.WriteLine($"[+] Giải mã ngược lại      : {decryptedText}");
                }
            }
        }

        // =========================================================================
        // 5. MÃ HÓA & GIẢI MÃ FILE LỚN (HÀNG GB), ĐO THỜI GIAN & SO SÁNH BYTES
        // =========================================================================
        static void EncryptDecryptLargeFileDemo()
        {
            CheckKeyExists();
            Console.Write("Nhập đường dẫn file nguồn (Nhấn Enter để dùng mặc định 'test_1GB.bin'): ");
            string sourceFile = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(sourceFile)) sourceFile = "test_1GB.bin";

            if (!File.Exists(sourceFile))
            {
                Console.WriteLine($"File '{sourceFile}' chưa tồn tại! Hãy chạy chức năng số 6 để tạo file 1GB trước, hoặc nhập đường dẫn file có sẵn trong máy.");
                return;
            }

            string encryptedFile = sourceFile + ".aes";
            string decryptedFile = sourceFile + ".decrypted" + Path.GetExtension(sourceFile);

            FileInfo fiSource = new FileInfo(sourceFile);
            double sizeInMB = fiSource.Length / (1024.0 * 1024.0);
            Console.WriteLine($"\n--- BẮT ĐẦU THỬ NGHIỆM VỚI FILE: {sourceFile} ({sizeInMB:F2} MB) ---");

            // 5.1. ĐO THỜI GIAN MÃ HÓA FILE
            Stopwatch swEncrypt = Stopwatch.StartNew();
            EncryptFileStream(sourceFile, encryptedFile, currentKey, currentIV);
            swEncrypt.Stop();
            FileInfo fiEnc = new FileInfo(encryptedFile);
            Console.WriteLine($"1. Mã hóa hoàn tất -> File: {encryptedFile} ({fiEnc.Length:N0} bytes)");
            Console.WriteLine($"   + Thời gian mã hóa : {swEncrypt.Elapsed.TotalSeconds:F3} giây ({swEncrypt.ElapsedMilliseconds} ms)");
            Console.WriteLine($"   + Tốc độ mã hóa    : {sizeInMB / swEncrypt.Elapsed.TotalSeconds:F2} MB/s");

            // 5.2. ĐO THỜI GIAN GIẢI MÃ FILE
            Stopwatch swDecrypt = Stopwatch.StartNew();
            DecryptFileStream(encryptedFile, decryptedFile, currentKey, currentIV);
            swDecrypt.Stop();
            FileInfo fiDec = new FileInfo(decryptedFile);
            Console.WriteLine($"\n2. Giải mã hoàn tất -> File: {decryptedFile} ({fiDec.Length:N0} bytes)");
            Console.WriteLine($"   + Thời gian giải mã: {swDecrypt.Elapsed.TotalSeconds:F3} giây ({swDecrypt.ElapsedMilliseconds} ms)");
            Console.WriteLine($"   + Tốc độ giải mã   : {sizeInMB / swDecrypt.Elapsed.TotalSeconds:F2} MB/s");

            // 5.3. SO SÁNH THEO TỪNG BYTE GIỮA FILE NGUỒN VÀ FILE GIẢI MÃ
            Console.WriteLine("\n3. Đang so sánh từng byte (Byte-by-Byte Comparison)...");
            Stopwatch swCompare = Stopwatch.StartNew();
            bool isIdentical = CompareFilesByBytes(sourceFile, decryptedFile);
            swCompare.Stop();

            Console.WriteLine($"   + Thời gian so sánh: {swCompare.Elapsed.TotalSeconds:F3} giây");
            Console.WriteLine($"   + KẾT QUẢ SO SÁNH  : {(isIdentical ? "GIỐNG NHAU 100% (Khớp từng byte)" : "KHÁC NHAU (Có lỗi xảy ra!)")}");
        }

        // Hàm Mã hóa File dùng FileStream + CryptoStream (Tối ưu cho file hàng GB)
        static void EncryptFileStream(string inputFile, string outputFile, byte[] key, byte[] iv)
        {
            // Buffer 1MB (1048576 bytes) giúp tối ưu tốc độ đọc/ghi ổ cứng SSD/HDD cho file lớn
            int bufferSize = 1024 * 1024;

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize))
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                using (CryptoStream cs = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
                {
                    byte[] buffer = new byte[bufferSize];
                    int bytesRead;
                    while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        cs.Write(buffer, 0, bytesRead);
                    }
                    cs.FlushFinalBlock();
                }
            }
        }

        // Hàm Giải mã File dùng FileStream + CryptoStream
        static void DecryptFileStream(string inputFile, string outputFile, byte[] key, byte[] iv)
        {
            int bufferSize = 1024 * 1024;

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize))
                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                using (CryptoStream cs = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write))
                {
                    byte[] buffer = new byte[bufferSize];
                    int bytesRead;
                    while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        cs.Write(buffer, 0, bytesRead);
                    }
                    cs.FlushFinalBlock();
                }
            }
        }

        // Hàm So sánh 2 file lớn theo từng byte (Đọc theo khối để không tràn RAM)
        static bool CompareFilesByBytes(string file1, string file2)
        {
            FileInfo fi1 = new FileInfo(file1);
            FileInfo fi2 = new FileInfo(file2);

            // Nếu kích thước lệch nhau dù chỉ 1 byte -> Chắc chắn khác nhau
            if (fi1.Length != fi2.Length)
                return false;

            int bufferSize = 1024 * 1024; // Đọc từng cụm 1MB để so sánh
            byte[] buffer1 = new byte[bufferSize];
            byte[] buffer2 = new byte[bufferSize];

            using (FileStream fs1 = new FileStream(file1, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize))
            using (FileStream fs2 = new FileStream(file2, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize))
            {
                int bytesRead1, bytesRead2;
                while ((bytesRead1 = fs1.Read(buffer1, 0, bufferSize)) > 0)
                {
                    bytesRead2 = fs2.Read(buffer2, 0, bufferSize);
                    if (bytesRead1 != bytesRead2)
                        return false;

                    // Sử dụng ReadOnlySpan<byte>.SequenceEqual được tối ưu hóa vector (SIMD) cực nhanh trong .NET
                    if (!buffer1.AsSpan(0, bytesRead1).SequenceEqual(buffer2.AsSpan(0, bytesRead2)))
                        return false;
                }
            }
            return true;
        }

        // =========================================================================
        // 6. TIỆN ÍCH TẠO FILE LỚN (1GB) ĐỂ TEST
        // =========================================================================
        static void CreateDummyLargeFile(string filePath, int sizeInMB)
        {
            Console.WriteLine($"Đang tạo file giả lập '{filePath}' dung lượng {sizeInMB} MB (Vui lòng đợi vài giây)...");
            byte[] buffer = new byte[1024 * 1024]; // 1 MB
            Random rng = new Random();

            using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
            {
                for (int i = 0; i < sizeInMB; i++)
                {
                    rng.NextBytes(buffer);
                    fs.Write(buffer, 0, buffer.Length);
                }
            }
            Console.WriteLine($"-> Đã tạo xong file '{filePath}' ({sizeInMB} MB)!");
        }

        static void CheckKeyExists()
        {
            if (currentKey == null || currentIV == null)
                throw new Exception("Chưa có khóa AES! Vui lòng chọn chức năng (1) Sinh khóa hoặc (3) Import khóa trước.");
        }
    }
}