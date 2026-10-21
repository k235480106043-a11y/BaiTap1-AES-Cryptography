using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace BaiTap2_RSA
{
    public class Asn1FieldInfo
    {
        public int Offset { get; set; }
        public int HeaderLength { get; set; }
        public int ContentLength { get; set; }
        public string TagName { get; set; } = string.Empty;
        public string FieldName { get; set; } = string.Empty;
        public string MathSymbol { get; set; } = string.Empty;
        public string ValueHexPreview { get; set; } = string.Empty;
        public string Explanation { get; set; } = string.Empty;
    }

    public class RsaKeyDetail
    {
        public bool IsPrivateKey { get; set; }
        public int KeySizeBits { get; set; }
        public string PemType { get; set; } = string.Empty;
        public byte[] RawDer { get; set; } = Array.Empty<byte>();
        public string PemContent { get; set; } = string.Empty;

        // Mathematical parameters
        public byte[]? Modulus { get; set; }
        public byte[]? Exponent { get; set; }
        public byte[]? D { get; set; }
        public byte[]? P { get; set; }
        public byte[]? Q { get; set; }
        public byte[]? DP { get; set; }
        public byte[]? DQ { get; set; }
        public byte[]? InverseQ { get; set; }

        public List<Asn1FieldInfo> ParsedFields { get; set; } = new List<Asn1FieldInfo>();

        public string GetParamSummary()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"[LOẠI KHÓA]: {(IsPrivateKey ? "RSA Private Key (Khóa Bí Mật)" : "RSA Public Key (Khóa Công Khai)")}");
            sb.AppendLine($"[KÍCH THƯỚC]: {KeySizeBits} bits ({KeySizeBits / 8} bytes)");
            sb.AppendLine($"[ĐỊNH DẠNG PEM]: {PemType}");
            sb.AppendLine($"[DUNG LƯỢNG DER]: {RawDer.Length} bytes");
            sb.AppendLine();

            if (Modulus != null)
            {
                sb.AppendLine($"🔹 Modulus (n = p * q) [{Modulus.Length * 8} bits / {Modulus.Length} bytes]:");
                sb.AppendLine("   " + BytesToHex(Modulus));
            }
            if (Exponent != null)
            {
                BigInteger eVal = new BigInteger(Exponent.Reverse().Concat(new byte[] { 0 }).ToArray());
                sb.AppendLine($"🔹 Public Exponent (e) [{Exponent.Length} bytes]: {eVal} (Hex: 0x{BytesToHex(Exponent).Replace(" ", "")})");
            }
            if (IsPrivateKey)
            {
                if (D != null)
                {
                    sb.AppendLine($"🔹 Private Exponent (d) [{D.Length * 8} bits / {D.Length} bytes]:");
                    sb.AppendLine("   " + BytesToHex(D));
                }
                if (P != null)
                {
                    sb.AppendLine($"🔹 Prime 1 (p) [{P.Length * 8} bits / {P.Length} bytes]:");
                    sb.AppendLine("   " + BytesToHex(P));
                }
                if (Q != null)
                {
                    sb.AppendLine($"🔹 Prime 2 (q) [{Q.Length * 8} bits / {Q.Length} bytes]:");
                    sb.AppendLine("   " + BytesToHex(Q));
                }
                if (DP != null)
                {
                    sb.AppendLine($"🔹 Exponent 1 (dp = d mod (p-1)) [{DP.Length * 8} bits]:");
                    sb.AppendLine("   " + BytesToHex(DP));
                }
                if (DQ != null)
                {
                    sb.AppendLine($"🔹 Exponent 2 (dq = d mod (q-1)) [{DQ.Length * 8} bits]:");
                    sb.AppendLine("   " + BytesToHex(DQ));
                }
                if (InverseQ != null)
                {
                    sb.AppendLine($"🔹 Coefficient (iqmp = q^-1 mod p) [{InverseQ.Length * 8} bits]:");
                    sb.AppendLine("   " + BytesToHex(InverseQ));
                }
            }
            return sb.ToString();
        }

        public static string BytesToHex(byte[] bytes, int maxBytes = 48)
        {
            if (bytes == null || bytes.Length == 0) return "(trống)";
            if (bytes.Length <= maxBytes)
            {
                return BitConverter.ToString(bytes).Replace("-", " ");
            }
            string head = BitConverter.ToString(bytes, 0, maxBytes / 2).Replace("-", " ");
            string tail = BitConverter.ToString(bytes, bytes.Length - maxBytes / 2, maxBytes / 2).Replace("-", " ");
            return $"{head} ... [{bytes.Length - maxBytes} bytes ẩn] ... {tail}";
        }
    }

    public static class RsaHelper
    {
        /// <summary>
        /// Sinh cặp khóa RSA theo kích thước (1024, 2048, 4096-bit).
        /// Xuất cả chuẩn PKCS#1 (BEGIN RSA PUBLIC/PRIVATE KEY) và SubjectPublicKeyInfo/PKCS#8.
        /// </summary>
        public static (string publicPem, string privatePem, RSA rsa) GenerateKeyPair(int keySizeBits = 2048)
        {
            RSA rsa = RSA.Create(keySizeBits);
            // Chuẩn PKCS#1 thuận tiện nhất cho việc phân tích toán học các trường n, e, d, p, q
            string publicPem = rsa.ExportRSAPublicKeyPem();
            string privatePem = rsa.ExportRSAPrivateKeyPem();
            return (publicPem, privatePem, rsa);
        }

        /// <summary>
        /// Import khóa từ chuỗi PEM bất kỳ (hỗ trợ cả PKCS#1, PKCS#8, SubjectPublicKeyInfo).
        /// </summary>
        public static (RSA rsa, RsaKeyDetail detail) ImportFromPemText(string pemText)
        {
            if (string.IsNullOrWhiteSpace(pemText))
                throw new ArgumentException("Nội dung PEM không được để trống.");

            RSA rsa = RSA.Create();
            rsa.ImportFromPem(pemText.AsSpan());

            RsaKeyDetail detail = AnalyzePem(pemText, rsa);
            return (rsa, detail);
        }

        /// <summary>
        /// Phân tích chi tiết format PEM: Header, Footer, Base64 DER bytes, và cấu trúc ASN.1 DER.
        /// </summary>
        public static RsaKeyDetail AnalyzePem(string pemText, RSA? existingRsa = null)
        {
            pemText = pemText.Trim();
            RSA rsa = existingRsa ?? RSA.Create();
            if (existingRsa == null)
            {
                rsa.ImportFromPem(pemText.AsSpan());
            }

            // Tách header, footer và Base64
            string[] lines = pemText.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            string header = lines.FirstOrDefault(l => l.StartsWith("-----BEGIN")) ?? "";
            string footer = lines.LastOrDefault(l => l.StartsWith("-----END")) ?? "";
            string base64 = string.Concat(lines.Where(l => !l.StartsWith("-----")));
            byte[] derBytes = Convert.FromBase64String(base64);

            bool isPrivate = header.Contains("PRIVATE KEY");
            RSAParameters prms = rsa.ExportParameters(isPrivate);

            RsaKeyDetail detail = new RsaKeyDetail
            {
                IsPrivateKey = isPrivate,
                KeySizeBits = rsa.KeySize,
                PemType = header.Trim('-'),
                RawDer = derBytes,
                PemContent = pemText,
                Modulus = prms.Modulus,
                Exponent = prms.Exponent,
                D = prms.D,
                P = prms.P,
                Q = prms.Q,
                DP = prms.DP,
                DQ = prms.DQ,
                InverseQ = prms.InverseQ
            };

            // Phân tích ASN.1 DER thành danh sách Asn1FieldInfo
            detail.ParsedFields = ParseDerStructure(derBytes, isPrivate, header);
            return detail;
        }

        private static List<Asn1FieldInfo> ParseDerStructure(byte[] derBytes, bool isPrivate, string header)
        {
            List<Asn1FieldInfo> fields = new List<Asn1FieldInfo>();

            try
            {
                AsnReader reader = new AsnReader(derBytes, AsnEncodingRules.DER);
                Asn1Tag rootTag = reader.PeekTag();

                if (rootTag == Asn1Tag.Sequence)
                {
                    AsnReader seqReader = reader.ReadSequence();

                    if (header.Contains("BEGIN RSA PRIVATE KEY"))
                    {
                        // PKCS#1 RSAPrivateKey:
                        // SEQUENCE { version, modulus n, publicExponent e, privateExponent d, prime1 p, prime2 q, exponent1 dp, exponent2 dq, coefficient iqmp }
                        BigInteger version = seqReader.ReadInteger();
                        fields.Add(new Asn1FieldInfo
                        {
                            TagName = "INTEGER (0x02)",
                            FieldName = "Version",
                            MathSymbol = "v",
                            ValueHexPreview = version.ToString(),
                            Explanation = "Phiên bản chuẩn RSA (0 = two-prime, 1 = multi-prime)."
                        });

                        byte[] n = seqReader.ReadIntegerBytes().ToArray();
                        fields.Add(new Asn1FieldInfo
                        {
                            TagName = "INTEGER (0x02)",
                            FieldName = "Modulus",
                            MathSymbol = "n = p × q",
                            ValueHexPreview = BitConverter.ToString(n.Take(16).ToArray()).Replace("-", " ") + $" ... ({n.Length} bytes)",
                            Explanation = "Số modulo công khai dùng chung trong mã hóa và giải mã. Độ dài xác định kích thước khóa."
                        });

                        byte[] e = seqReader.ReadIntegerBytes().ToArray();
                        BigInteger eVal = new BigInteger(e.Reverse().Concat(new byte[] { 0 }).ToArray());
                        fields.Add(new Asn1FieldInfo
                        {
                            TagName = "INTEGER (0x02)",
                            FieldName = "Public Exponent",
                            MathSymbol = "e",
                            ValueHexPreview = $"{eVal} (0x{BitConverter.ToString(e).Replace("-", "")})",
                            Explanation = "Số mũ công khai (thường chọn 65537 = 2^16 + 1 để tối ưu tốc độ mã hóa với chỉ 17 phép tính nhị phân)."
                        });

                        byte[] d = seqReader.ReadIntegerBytes().ToArray();
                        fields.Add(new Asn1FieldInfo
                        {
                            TagName = "INTEGER (0x02)",
                            FieldName = "Private Exponent",
                            MathSymbol = "d ≡ e⁻¹ (mod φ(n))",
                            ValueHexPreview = BitConverter.ToString(d.Take(16).ToArray()).Replace("-", " ") + $" ... ({d.Length} bytes)",
                            Explanation = "Số mũ bí mật dùng để giải mã và ký số. Độ dài ngang bằng n (~2048 bits), được bảo mật tuyệt đối."
                        });

                        byte[] p = seqReader.ReadIntegerBytes().ToArray();
                        fields.Add(new Asn1FieldInfo
                        {
                            TagName = "INTEGER (0x02)",
                            FieldName = "Prime 1",
                            MathSymbol = "p",
                            ValueHexPreview = BitConverter.ToString(p.Take(12).ToArray()).Replace("-", " ") + $" ... ({p.Length} bytes)",
                            Explanation = "Số nguyên tố lớn thứ nhất bí mật (kích thước n/2 bits, ví dụ 1024 bits)."
                        });

                        byte[] q = seqReader.ReadIntegerBytes().ToArray();
                        fields.Add(new Asn1FieldInfo
                        {
                            TagName = "INTEGER (0x02)",
                            FieldName = "Prime 2",
                            MathSymbol = "q",
                            ValueHexPreview = BitConverter.ToString(q.Take(12).ToArray()).Replace("-", " ") + $" ... ({q.Length} bytes)",
                            Explanation = "Số nguyên tố lớn thứ hai bí mật (p ≠ q)."
                        });

                        byte[] dp = seqReader.ReadIntegerBytes().ToArray();
                        fields.Add(new Asn1FieldInfo
                        {
                            TagName = "INTEGER (0x02)",
                            FieldName = "Exponent 1 (CRT)",
                            MathSymbol = "dp = d mod (p-1)",
                            ValueHexPreview = BitConverter.ToString(dp.Take(12).ToArray()).Replace("-", " ") + $" ... ({dp.Length} bytes)",
                            Explanation = "Số mũ phụ phục vụ thuật toán Định lý số dư Trung Hoa (CRT) giúp tăng tốc giải mã lên ~4 lần."
                        });

                        byte[] dq = seqReader.ReadIntegerBytes().ToArray();
                        fields.Add(new Asn1FieldInfo
                        {
                            TagName = "INTEGER (0x02)",
                            FieldName = "Exponent 2 (CRT)",
                            MathSymbol = "dq = d mod (q-1)",
                            ValueHexPreview = BitConverter.ToString(dq.Take(12).ToArray()).Replace("-", " ") + $" ... ({dq.Length} bytes)",
                            Explanation = "Số mũ phụ thứ hai cho CRT."
                        });

                        byte[] iqmp = seqReader.ReadIntegerBytes().ToArray();
                        fields.Add(new Asn1FieldInfo
                        {
                            TagName = "INTEGER (0x02)",
                            FieldName = "Coefficient (CRT)",
                            MathSymbol = "iqmp = q⁻¹ mod p",
                            ValueHexPreview = BitConverter.ToString(iqmp.Take(12).ToArray()).Replace("-", " ") + $" ... ({iqmp.Length} bytes)",
                            Explanation = "Hệ số nghịch đảo nhân CRT (Garner's formula) để ghép nghiệm."
                        });
                    }
                    else if (header.Contains("BEGIN RSA PUBLIC KEY"))
                    {
                        // PKCS#1 RSAPublicKey:
                        // SEQUENCE { modulus n, publicExponent e }
                        byte[] n = seqReader.ReadIntegerBytes().ToArray();
                        fields.Add(new Asn1FieldInfo
                        {
                            TagName = "INTEGER (0x02)",
                            FieldName = "Modulus",
                            MathSymbol = "n = p × q",
                            ValueHexPreview = BitConverter.ToString(n.Take(16).ToArray()).Replace("-", " ") + $" ... ({n.Length} bytes)",
                            Explanation = "Số modulo công khai dùng trong mã hóa RSA."
                        });

                        byte[] e = seqReader.ReadIntegerBytes().ToArray();
                        BigInteger eVal = new BigInteger(e.Reverse().Concat(new byte[] { 0 }).ToArray());
                        fields.Add(new Asn1FieldInfo
                        {
                            TagName = "INTEGER (0x02)",
                            FieldName = "Public Exponent",
                            MathSymbol = "e",
                            ValueHexPreview = $"{eVal} (0x{BitConverter.ToString(e).Replace("-", "")})",
                            Explanation = "Số mũ mã hóa công khai (thường 65537)."
                        });
                    }
                    else
                    {
                        // Generic SubjectPublicKeyInfo hoặc PKCS#8
                        fields.Add(new Asn1FieldInfo
                        {
                            TagName = "SEQUENCE (0x30)",
                            FieldName = header.Contains("PUBLIC") ? "SubjectPublicKeyInfo (X.509)" : "PrivateKeyInfo (PKCS#8)",
                            MathSymbol = "Container",
                            ValueHexPreview = $"Độ dài DER: {derBytes.Length} bytes",
                            Explanation = "Cấu trúc bao gói chứa AlgorithmIdentifier (1.2.840.113549.1.1.1 - rsaEncryption) và phần ruột PKCS#1."
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                fields.Add(new Asn1FieldInfo
                {
                    TagName = "PARSE_ERROR",
                    FieldName = "Thông báo",
                    MathSymbol = "!",
                    ValueHexPreview = "N/A",
                    Explanation = $"Lỗi khi parse ASN.1 chi tiết: {ex.Message}"
                });
            }

            return fields;
        }

        /// <summary>
        /// Mã hóa mảng bytes (< 190 bytes theo yêu cầu đề bài) bằng RSA Public Key.
        /// Mặc định dùng đệm an toàn OAEP-SHA256 (hoặc PKCS#1 v1.5).
        /// </summary>
        public static byte[] Encrypt(RSA rsa, byte[] data, bool useOaep = true)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("Dữ liệu cần mã hóa không được rỗng.");

            int maxBytes = useOaep ? (rsa.KeySize / 8 - 2 * 32 - 2) : (rsa.KeySize / 8 - 11);
            if (data.Length > maxBytes)
            {
                throw new ArgumentException($"Dữ liệu dài {data.Length} bytes, vượt quá giới hạn tối đa cho phép của RSA {rsa.KeySize}-bit ({maxBytes} bytes).");
            }

            RSAEncryptionPadding padding = useOaep ? RSAEncryptionPadding.OaepSHA256 : RSAEncryptionPadding.Pkcs1;
            return rsa.Encrypt(data, padding);
        }

        /// <summary>
        /// Giải mã mảng bytes bằng RSA Private Key.
        /// </summary>
        public static byte[] Decrypt(RSA rsa, byte[] encryptedData, bool useOaep = true)
        {
            RSAEncryptionPadding padding = useOaep ? RSAEncryptionPadding.OaepSHA256 : RSAEncryptionPadding.Pkcs1;
            return rsa.Decrypt(encryptedData, padding);
        }

        /// <summary>
        /// Tính băm SHA-256 (trả về 32 bytes = 256 bits).
        /// </summary>
        public static byte[] ComputeSha256(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return sha.ComputeHash(data);
            }
        }

        /// <summary>
        /// Đánh giá hiệu ứng tuyết lở (Avalanche Effect) giữa 2 chuỗi băm 256 bits:
        /// Tính khoảng cách Hamming (số bit bị lật) và tỷ lệ %.
        /// </summary>
        public static (int flippedBits, int totalBits, double percentage, string binary1, string binary2) EvaluateAvalanche(byte[] hash1, byte[] hash2)
        {
            int flipped = 0;
            StringBuilder bin1 = new StringBuilder();
            StringBuilder bin2 = new StringBuilder();

            for (int i = 0; i < 32; i++)
            {
                byte b1 = hash1[i];
                byte b2 = hash2[i];

                byte xor = (byte)(b1 ^ b2);
                for (int bit = 7; bit >= 0; bit--)
                {
                    if (((xor >> bit) & 1) == 1) flipped++;
                    bin1.Append((b1 >> bit) & 1);
                    bin2.Append((b2 >> bit) & 1);
                }
            }

            double pct = (double)flipped / 256.0 * 100.0;
            return (flipped, 256, pct, bin1.ToString(), bin2.ToString());
        }

        /// <summary>
        /// Ký số dữ liệu bằng RSA Private Key.
        /// </summary>
        public static byte[] SignData(RSA rsa, byte[] data, bool usePss = false)
        {
            RSASignaturePadding padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
            return rsa.SignData(data, HashAlgorithmName.SHA256, padding);
        }

        /// <summary>
        /// Xác minh chữ ký số bằng RSA Public Key.
        /// </summary>
        public static bool VerifyData(RSA rsa, byte[] data, byte[] signature, bool usePss = false)
        {
            RSASignaturePadding padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, padding);
        }

        /// <summary>
        /// Benchmark tốc độ: So sánh hiệu năng phép tính dùng Public Key (e bé = 65537) vs Private Key (d to đùng).
        /// </summary>
        public static BenchmarkResult RunBenchmark(RSA rsa, int iterations = 500)
        {
            // Chuẩn bị dữ liệu mẫu (32 bytes = tương đương khóa AES 256-bit)
            byte[] sampleData = new byte[32];
            RandomNumberGenerator.Fill(sampleData);

            byte[] cipherSample = rsa.Encrypt(sampleData, RSAEncryptionPadding.OaepSHA256);

            // 1. Đo tốc độ Public Key Operation (Mã hóa: C = M^e mod n)
            Stopwatch swPub = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                _ = rsa.Encrypt(sampleData, RSAEncryptionPadding.OaepSHA256);
            }
            swPub.Stop();
            double pubTotalMs = swPub.Elapsed.TotalMilliseconds;
            double pubOpsPerSec = (iterations / pubTotalMs) * 1000.0;

            // 2. Đo tốc độ Private Key Operation (Giải mã: M = C^d mod n)
            Stopwatch swPriv = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                _ = rsa.Decrypt(cipherSample, RSAEncryptionPadding.OaepSHA256);
            }
            swPriv.Stop();
            double privTotalMs = swPriv.Elapsed.TotalMilliseconds;
            double privOpsPerSec = (iterations / privTotalMs) * 1000.0;

            double ratio = privTotalMs / (pubTotalMs > 0 ? pubTotalMs : 0.001);

            return new BenchmarkResult
            {
                Iterations = iterations,
                KeySizeBits = rsa.KeySize,
                PublicTimeMs = pubTotalMs,
                PublicOpsPerSec = pubOpsPerSec,
                PrivateTimeMs = privTotalMs,
                PrivateOpsPerSec = privOpsPerSec,
                SpeedRatio = ratio
            };
        }
    }

    public class BenchmarkResult
    {
        public int Iterations { get; set; }
        public int KeySizeBits { get; set; }
        public double PublicTimeMs { get; set; }
        public double PublicOpsPerSec { get; set; }
        public double PrivateTimeMs { get; set; }
        public double PrivateOpsPerSec { get; set; }
        public double SpeedRatio { get; set; }

        public string GetDetailedReport()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"📊 KẾT QUẢ ĐO LƯỜNG HIỆU NĂNG RSA-{KeySizeBits} ({Iterations} LẦN LẶP)");
            sb.AppendLine("───────────────────────────────────────────────────────────────────────────────");
            sb.AppendLine($"1. PHÉP TOÁN PUBLIC KEY (Số mũ e = 65537 - Chỉ có 17 bits):");
            sb.AppendLine($"   • Tổng thời gian thực thi : {PublicTimeMs:F2} ms");
            sb.AppendLine($"   • Thời gian trung bình/phép: {PublicTimeMs / Iterations:F3} ms/phép tính");
            sb.AppendLine($"   • Tốc độ xử lý            : {PublicOpsPerSec:F1} phép tính/giây (ops/s)");
            sb.AppendLine();
            sb.AppendLine($"2. PHÉP TOÁN PRIVATE KEY (Số mũ d to ~{KeySizeBits} bits):");
            sb.AppendLine($"   • Tổng thời gian thực thi : {PrivateTimeMs:F2} ms");
            sb.AppendLine($"   • Thời gian trung bình/phép: {PrivateTimeMs / Iterations:F3} ms/phép tính");
            sb.AppendLine($"   • Tốc độ xử lý            : {PrivateOpsPerSec:F1} phép tính/giây (ops/s)");
            sb.AppendLine();
            sb.AppendLine("───────────────────────────────────────────────────────────────────────────────");
            sb.AppendLine($"⚡ SO SÁNH TỶ LỆ: Phép toán Public Key NHANH HƠN GẤP {SpeedRatio:F1} LẦN so với Private Key!");
            sb.AppendLine();
            sb.AppendLine("💡 GIẢI THÍCH LÝ THUYẾT TOÁN HỌC & MẬT MÃ:");
            sb.AppendLine("• Với Public Key (e): e = 65537 = 2¹⁶ + 1. Dạng nhị phân là 0b10000000000000001 (chỉ gồm 2 bit 1).");
            sb.AppendLine("  Thuật toán lũy thừa nhị phân (Square-and-Multiply) chỉ mất 16 phép bình phương và 1 phép nhân modulo n.");
            sb.AppendLine("  Do đó, mã hóa và xác minh chữ ký diễn ra với tốc độ cực kỳ nhanh chóng.");
            sb.AppendLine();
            sb.AppendLine("• Với Private Key (d): d là một số nguyên ngẫu nhiên cực lớn có cùng cấp độ dài với n (ví dụ 2048 bits).");
            sb.AppendLine("  Số bit 1 trung bình chiếm 50% (~1024 bits). Thuật toán Square-and-Multiply phải thực hiện ~2047 phép bình");
            sb.AppendLine("  phương và ~1024 phép nhân số lớn. Kể cả khi sử dụng tối ưu hóa Định lý số dư Trung Hoa (CRT)");
            sb.AppendLine("  để chia nhỏ tính theo modulo p và q, phép tính Private Key vẫn tốn nhiều chu kỳ CPU hơn hàng chục lần.");
            return sb.ToString();
        }
    }
}
