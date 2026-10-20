using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BaiTap1_AES
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            System.Windows.Forms.Application.EnableVisualStyles();
            System.Windows.Forms.Application.SetCompatibleTextRenderingDefault(false);
            System.Windows.Forms.Application.Run(new MainForm());
        }
    }

    #region Custom Cute & Rounded Controls
    public class CuteButton : System.Windows.Forms.Button
    {
        public int CornerRadius { get; set; } = 15;
        public Color NormalColor { get; set; } = Color.FromArgb(255, 117, 143);
        public Color HoverColor { get; set; } = Color.FromArgb(255, 92, 122);
        public Color PressedColor { get; set; } = Color.FromArgb(235, 70, 100);
        public Color BorderColor { get; set; } = Color.Transparent;
        public int BorderSize { get; set; } = 0;

        private bool isHovered = false;
        private bool isPressed = false;

        public CuteButton()
        {
            this.FlatStyle = FlatStyle.Flat;
            this.FlatAppearance.BorderSize = 0;
            this.BackColor = Color.Transparent;
            this.ForeColor = Color.White;
            this.Font = new System.Drawing.Font("Segoe UI", 9.5F, System.Drawing.FontStyle.Bold);
            this.Cursor = Cursors.Hand;
            this.DoubleBuffered = true;
            this.Size = new Size(160, 38);
        }

        protected override void OnMouseEnter(EventArgs e)
        {
            base.OnMouseEnter(e);
            isHovered = true;
            this.Invalidate();
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            isHovered = false;
            isPressed = false;
            this.Invalidate();
        }

        protected override void OnMouseDown(MouseEventArgs mevent)
        {
            base.OnMouseDown(mevent);
            isPressed = true;
            this.Invalidate();
        }

        protected override void OnMouseUp(MouseEventArgs mevent)
        {
            base.OnMouseUp(mevent);
            isPressed = false;
            this.Invalidate();
        }

        protected override void OnPaint(PaintEventArgs pevent)
        {
            Graphics g = pevent.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            Rectangle rect = new Rectangle(0, 0, this.Width, this.Height);
            Color fill = !this.Enabled ? Color.FromArgb(210, 195, 205) : (isPressed ? PressedColor : (isHovered ? HoverColor : NormalColor));

            using (GraphicsPath path = CreateRoundedPath(rect, CornerRadius))
            {
                this.Region = new Region(path);

                using (SolidBrush brush = new SolidBrush(fill))
                {
                    g.FillPath(brush, path);
                }

                if (BorderSize > 0 && BorderColor != Color.Transparent)
                {
                    using (Pen pen = new Pen(BorderColor, BorderSize))
                    {
                        g.DrawPath(pen, path);
                    }
                }
            }

            TextRenderer.DrawText(
                g,
                this.Text,
                this.Font,
                rect,
                this.ForeColor,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak
            );
        }

        private static GraphicsPath CreateRoundedPath(Rectangle rect, int radius)
        {
            GraphicsPath path = new GraphicsPath();
            int d = radius * 2;
            if (d > rect.Width) d = rect.Width;
            if (d > rect.Height) d = rect.Height;
            Rectangle arc = new Rectangle(rect.X, rect.Y, d, d);

            path.AddArc(arc, 180, 90);
            arc.X = rect.Right - d;
            path.AddArc(arc, 270, 90);
            arc.Y = rect.Bottom - d;
            path.AddArc(arc, 0, 90);
            arc.X = rect.Left;
            path.AddArc(arc, 90, 90);
            path.CloseFigure();
            return path;
        }
    }

    public class CuteCard : System.Windows.Forms.Panel
    {
        public int CornerRadius { get; set; } = 16;
        public Color CardBackground { get; set; } = Color.White;
        public Color BorderColor { get; set; } = Color.FromArgb(255, 218, 228);
        public int BorderThickness { get; set; } = 1;

        public CuteCard()
        {
            this.DoubleBuffered = true;
            this.BackColor = Color.Transparent;
            this.Padding = new Padding(12);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            Rectangle rect = new Rectangle(0, 0, this.Width - 1, this.Height - 1);
            using (GraphicsPath path = CreateRoundedPath(rect, CornerRadius))
            {
                using (SolidBrush brush = new SolidBrush(CardBackground))
                {
                    g.FillPath(brush, path);
                }
                if (BorderThickness > 0)
                {
                    using (Pen pen = new Pen(BorderColor, BorderThickness))
                    {
                        g.DrawPath(pen, path);
                    }
                }
            }
        }

        private static GraphicsPath CreateRoundedPath(Rectangle rect, int radius)
        {
            GraphicsPath path = new GraphicsPath();
            int d = radius * 2;
            if (d > rect.Width) d = rect.Width;
            if (d > rect.Height) d = rect.Height;
            Rectangle arc = new Rectangle(rect.X, rect.Y, d, d);

            path.AddArc(arc, 180, 90);
            arc.X = rect.Right - d;
            path.AddArc(arc, 270, 90);
            arc.Y = rect.Bottom - d;
            path.AddArc(arc, 0, 90);
            arc.X = rect.Left;
            path.AddArc(arc, 90, 90);
            path.CloseFigure();
            return path;
        }
    }
    #endregion

    public class MainForm : System.Windows.Forms.Form
    {
        private byte[]? currentKey;
        private byte[]? currentIV;
        private System.Windows.Forms.TextBox txtLog;
        private System.Windows.Forms.TextBox txtPlainText;
        private string lastEncryptedBase64 = string.Empty;

        // Các nút bấm chính
        private CuteButton btnGenKey;
        private CuteButton btnSaveKey;
        private CuteButton btnLoadKey;
        private CuteButton btnEncryptText;
        private CuteButton btnDecryptText;
        private CuteButton btnEncryptFile;
        private CuteButton btnDecryptFile;
        private CuteButton btnClearLog;
        private CuteButton btnFileLarge;

        public MainForm()
        {
            // Thiết lập cửa sổ chính phong cách Soft Pastel Aesthetic
            this.Text = "🌸 Mã Hóa Đối Xứng AES-256 • Nguyễn Thị Ngọc Linh (K59KTP.K01)";
            this.Size = new Size(980, 780);
            this.MinimumSize = new Size(960, 740);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(255, 245, 248); // Hồng phấn nhẹ nhàng
            this.Font = new System.Drawing.Font("Segoe UI", 9.5F);

            // ==============================================================
            // 1. BANNER TIÊU ĐỀ NỮ TÍNH DỄ THƯƠNG
            // ==============================================================
            CuteCard cardHeader = new CuteCard()
            {
                Location = new Point(20, 15),
                Size = new Size(925, 70),
                CardBackground = Color.FromArgb(255, 255, 255),
                BorderColor = Color.FromArgb(255, 204, 218),
                CornerRadius = 18
            };

            System.Windows.Forms.Label lblHeaderTitle = new System.Windows.Forms.Label()
            {
                Text = "💖 BÀI 1: MÃ HÓA ĐỐI XỨNG AES-256 (CBC • PKCS7)",
                Font = new System.Drawing.Font("Segoe UI", 13.5F, System.Drawing.FontStyle.Bold),
                ForeColor = Color.FromArgb(216, 27, 96), // Hồng đậm sang trọng
                Location = new Point(16, 10),
                AutoSize = true
            };

            System.Windows.Forms.Label lblHeaderSub = new System.Windows.Forms.Label()
            {
                Text = "🌸 Sinh viên: Nguyễn Thị Ngọc Linh  |  Lớp: K59KTP.K01  |  Học phần: An toàn và bảo mật thông tin",
                Font = new System.Drawing.Font("Segoe UI", 9.25F, System.Drawing.FontStyle.Regular),
                ForeColor = Color.FromArgb(156, 39, 100),
                Location = new Point(18, 38),
                AutoSize = true
            };

            cardHeader.Controls.Add(lblHeaderTitle);
            cardHeader.Controls.Add(lblHeaderSub);
            this.Controls.Add(cardHeader);

            // ==============================================================
            // 2. CARD: QUẢN LÝ KHÓA AES (Yêu cầu 1, 2, 3)
            // ==============================================================
            CuteCard cardKey = new CuteCard()
            {
                Location = new Point(20, 95),
                Size = new Size(925, 68),
                CardBackground = Color.White,
                BorderColor = Color.FromArgb(255, 215, 225),
                CornerRadius = 16
            };

            System.Windows.Forms.Label lblKeyTitle = new System.Windows.Forms.Label()
            {
                Text = "🔑 Khóa AES:",
                Font = new System.Drawing.Font("Segoe UI", 9.5F, System.Drawing.FontStyle.Bold),
                ForeColor = Color.FromArgb(173, 20, 87),
                Location = new Point(15, 24),
                AutoSize = true
            };

            btnGenKey = new CuteButton()
            {
                Text = "✨ 1. Sinh khóa AES",
                Location = new Point(125, 14),
                Size = new Size(245, 40),
                NormalColor = Color.FromArgb(255, 117, 143), // Hồng đào
                HoverColor = Color.FromArgb(255, 89, 120),
                PressedColor = Color.FromArgb(230, 65, 95)
            };

            btnSaveKey = new CuteButton()
            {
                Text = "💾 2. Lưu khóa ra file",
                Location = new Point(385, 14),
                Size = new Size(250, 40),
                NormalColor = Color.FromArgb(165, 148, 249), // Tím Lavender dễ thương
                HoverColor = Color.FromArgb(145, 126, 242),
                PressedColor = Color.FromArgb(125, 105, 225)
            };

            btnLoadKey = new CuteButton()
            {
                Text = "📂 3. Import khóa từ file",
                Location = new Point(650, 14),
                Size = new Size(255, 40),
                NormalColor = Color.FromArgb(112, 185, 235), // Xanh Baby Blue
                HoverColor = Color.FromArgb(85, 168, 225),
                PressedColor = Color.FromArgb(60, 145, 205)
            };

            cardKey.Controls.Add(lblKeyTitle);
            cardKey.Controls.Add(btnGenKey);
            cardKey.Controls.Add(btnSaveKey);
            cardKey.Controls.Add(btnLoadKey);
            this.Controls.Add(cardKey);

            // ==============================================================
            // 3. CARD: MÃ HÓA & GIẢI MÃ VĂN BẢN (Yêu cầu 4)
            // ==============================================================
            CuteCard cardText = new CuteCard()
            {
                Location = new Point(20, 172),
                Size = new Size(925, 68),
                CardBackground = Color.White,
                BorderColor = Color.FromArgb(255, 215, 225),
                CornerRadius = 16
            };

            System.Windows.Forms.Label lblTextTitle = new System.Windows.Forms.Label()
            {
                Text = "📝 Văn bản:",
                Font = new System.Drawing.Font("Segoe UI", 9.5F, System.Drawing.FontStyle.Bold),
                ForeColor = Color.FromArgb(173, 20, 87),
                Location = new Point(15, 24),
                AutoSize = true
            };

            txtPlainText = new System.Windows.Forms.TextBox()
            {
                Text = "Nguyen Thi Ngoc Linh - K59KTP.K01",
                Location = new Point(125, 20),
                Size = new Size(465, 28),
                Font = new System.Drawing.Font("Segoe UI", 10F),
                BackColor = Color.FromArgb(255, 247, 250),
                ForeColor = Color.FromArgb(65, 30, 45),
                BorderStyle = BorderStyle.FixedSingle
            };

            btnEncryptText = new CuteButton()
            {
                Text = "🔒 4a. Mã hóa",
                Location = new Point(605, 14),
                Size = new Size(145, 40),
                NormalColor = Color.FromArgb(247, 37, 133), // Hồng Sen Rực Rỡ
                HoverColor = Color.FromArgb(220, 20, 110),
                PressedColor = Color.FromArgb(195, 10, 95)
            };

            btnDecryptText = new CuteButton()
            {
                Text = "🔓 4b. Giải mã",
                Location = new Point(760, 14),
                Size = new Size(145, 40),
                NormalColor = Color.FromArgb(72, 191, 165), // Xanh Mint Pastel
                HoverColor = Color.FromArgb(50, 175, 148),
                PressedColor = Color.FromArgb(35, 150, 125)
            };

            cardText.Controls.Add(lblTextTitle);
            cardText.Controls.Add(txtPlainText);
            cardText.Controls.Add(btnEncryptText);
            cardText.Controls.Add(btnDecryptText);
            this.Controls.Add(cardText);

            // ==============================================================
            // 4. CARD: MÃ HÓA TẬP TIN & BENCHMARK FILE 1GB (Yêu cầu 5)
            // ==============================================================
            CuteCard cardFile = new CuteCard()
            {
                Location = new Point(20, 249),
                Size = new Size(925, 115),
                CardBackground = Color.White,
                BorderColor = Color.FromArgb(255, 215, 225),
                CornerRadius = 16
            };

            btnEncryptFile = new CuteButton()
            {
                Text = "📦 5a. Chọn file để Mã hóa (.aes)",
                Location = new Point(15, 12),
                Size = new Size(295, 40),
                NormalColor = Color.FromArgb(181, 70, 190), // Tím hồng mộng mơ
                HoverColor = Color.FromArgb(160, 50, 170),
                PressedColor = Color.FromArgb(140, 30, 150)
            };

            btnDecryptFile = new CuteButton()
            {
                Text = "🔓 5b. Chọn file .aes để Giải mã",
                Location = new Point(325, 12),
                Size = new Size(295, 40),
                NormalColor = Color.FromArgb(250, 145, 80), // Cam đào tươi tắn
                HoverColor = Color.FromArgb(235, 125, 60),
                PressedColor = Color.FromArgb(215, 105, 40)
            };

            btnClearLog = new CuteButton()
            {
                Text = "🧹 Xóa Log",
                Location = new Point(780, 12),
                Size = new Size(125, 40),
                NormalColor = Color.FromArgb(235, 215, 225), // Xám hồng tinh tế
                HoverColor = Color.FromArgb(220, 195, 210),
                PressedColor = Color.FromArgb(200, 175, 190),
                ForeColor = Color.FromArgb(105, 55, 75)
            };

            // Nút Hero Benchmark 1GB dài toàn bộ bề ngang
            btnFileLarge = new CuteButton()
            {
                Text = "🚀 5c. Thử nghiệm Benchmark File Lớn (1 GB) & So sánh Byte-by-Byte (SIMD) 💖",
                Location = new Point(15, 60),
                Size = new Size(890, 44),
                CornerRadius = 18,
                Font = new System.Drawing.Font("Segoe UI", 10.5F, System.Drawing.FontStyle.Bold),
                NormalColor = Color.FromArgb(235, 65, 120), // Hồng Pastel Hot Pink
                HoverColor = Color.FromArgb(215, 45, 100),
                PressedColor = Color.FromArgb(190, 25, 80)
            };

            cardFile.Controls.Add(btnEncryptFile);
            cardFile.Controls.Add(btnDecryptFile);
            cardFile.Controls.Add(btnClearLog);
            cardFile.Controls.Add(btnFileLarge);
            this.Controls.Add(cardFile);

            // ==============================================================
            // 5. CARD: HỘP LOG KẾT QUẢ PASTEL TERMINAL
            // ==============================================================
            CuteCard cardLog = new CuteCard()
            {
                Location = new Point(20, 373),
                Size = new Size(925, 345),
                CardBackground = Color.FromArgb(35, 26, 48), // Tím đêm huyền ảo, cực kỳ sang và cute
                BorderColor = Color.FromArgb(255, 175, 204),
                BorderThickness = 1,
                CornerRadius = 18
            };

            txtLog = new System.Windows.Forms.TextBox()
            {
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                ReadOnly = true,
                Location = new Point(14, 14),
                Size = new Size(895, 317),
                Font = new System.Drawing.Font("Consolas", 10F, System.Drawing.FontStyle.Regular),
                BackColor = Color.FromArgb(35, 26, 48),
                ForeColor = Color.FromArgb(168, 230, 207), // Xanh ngọc pastel dịu mắt
                BorderStyle = BorderStyle.None
            };

            cardLog.Controls.Add(txtLog);
            this.Controls.Add(cardLog);

            // In thông điệp chào mừng dễ thương
            Log("🎀 Chào mừng bạn đến với Ứng dụng Mã hóa AES-256 (Giao diện Cute Pastel)");
            Log("🌸 Sinh viên thực hiện: Nguyễn Thị Ngọc Linh - K59KTP.K01");
            Log("💡 Hướng dẫn: Bấm [1. Sinh khóa] hoặc [3. Import khóa] để bắt đầu trải nghiệm!");
            Log("--------------------------------------------------------------------------------------");

            // ==============================================================
            // CÁC SỰ KIỆN XỬ LÝ
            // ==============================================================

            // 1. SINH KHÓA
            btnGenKey.Click += (s, e) => {
                try
                {
                    using (Aes aes = Aes.Create())
                    {
                        aes.KeySize = 256;
                        aes.GenerateKey();
                        aes.GenerateIV();
                        currentKey = aes.Key;
                        currentIV = aes.IV;
                        Log("\n🌸 ======================================================================================");
                        Log(">>> [1] ĐÃ SINH KHÓA AES-256 MỚI THÀNH CÔNG ✨:");
                        Log($"    💖 Khóa Bí mật Key (Base64 - 256 bits): {Convert.ToBase64String(currentKey)}");
                        Log($"    🎀 Vector khởi tạo IV (Base64 - 128 bits): {Convert.ToBase64String(currentIV)}");
                        Log("======================================================================================\n");
                    }
                }
                catch (Exception ex) { Log($"❌ [LỖI]: {ex.Message}"); }
            };

            // 2. LƯU KHÓA RA FILE
            btnSaveKey.Click += (s, e) => {
                try
                {
                    EnsureKey();
                    using (SaveFileDialog sfd = new SaveFileDialog())
                    {
                        sfd.Title = "Lưu khóa bí mật AES ra file";
                        sfd.FileName = "aes_key.txt";
                        sfd.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*";
                        if (sfd.ShowDialog() == DialogResult.OK)
                        {
                            File.WriteAllLines(sfd.FileName, new string[] {
                                Convert.ToBase64String(currentKey!),
                                Convert.ToBase64String(currentIV!)
                            });
                            Log($">>> [2] ĐÃ LƯU KHÓA RA FILE THÀNH CÔNG: 💾 {sfd.FileName}");
                        }
                    }
                }
                catch (Exception ex) { Log($"❌ [LỖI]: {ex.Message}"); }
            };

            // 3. IMPORT KHÓA TỪ FILE
            btnLoadKey.Click += (s, e) => {
                try
                {
                    using (OpenFileDialog ofd = new OpenFileDialog())
                    {
                        ofd.Title = "Chọn file chứa khóa AES (aes_key.txt)";
                        ofd.FileName = "aes_key.txt";
                        ofd.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*";
                        if (ofd.ShowDialog() == DialogResult.OK)
                        {
                            string[] lines = File.ReadAllLines(ofd.FileName);
                            if (lines.Length < 2) throw new Exception("File khóa không hợp lệ (cần ít nhất 2 dòng: Key và IV)!");
                            currentKey = Convert.FromBase64String(lines[0].Trim());
                            currentIV = Convert.FromBase64String(lines[1].Trim());
                            Log("\n🌸 ======================================================================================");
                            Log($">>> [3] ĐÃ NẠP (IMPORT) KHÓA THÀNH CÔNG TỪ FILE 📂: {ofd.FileName}");
                            Log($"    💖 Key (Base64): {Convert.ToBase64String(currentKey)}");
                            Log($"    🎀 IV  (Base64): {Convert.ToBase64String(currentIV)}");
                            Log("======================================================================================\n");
                        }
                    }
                }
                catch (Exception ex) { Log($"❌ [LỖI]: {ex.Message}"); }
            };

            // 4A. MÃ HÓA VĂN BẢN
            btnEncryptText.Click += (s, e) => {
                try
                {
                    EnsureKey();
                    string plain = txtPlainText.Text;
                    if (string.IsNullOrEmpty(plain)) { Log("⚠️ Vui lòng nhập văn bản cần mã hóa!"); return; }

                    byte[] cipherBytes;
                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = currentKey!;
                        aes.IV = currentIV!;
                        aes.Mode = CipherMode.CBC;
                        aes.Padding = PaddingMode.PKCS7;

                        using (MemoryStream ms = new MemoryStream())
                        using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            byte[] data = Encoding.UTF8.GetBytes(plain);
                            cs.Write(data, 0, data.Length);
                            cs.FlushFinalBlock();
                            cipherBytes = ms.ToArray();
                        }
                    }

                    lastEncryptedBase64 = Convert.ToBase64String(cipherBytes);
                    string hex = Convert.ToHexString(cipherBytes);
                    Log("--------------------------------------------------------------------------------------");
                    Log(">>> [4a] KẾT QUẢ MÃ HÓA ĐOẠN VĂN BẢN 🔒:");
                    Log($"    📝 Bản rõ (Plaintext) : {plain}");
                    Log($"    ✨ Bản mã (Base64)    : {lastEncryptedBase64}");
                    Log($"    💎 Bản mã (Hex)       : {hex}");
                    Log("--------------------------------------------------------------------------------------");
                }
                catch (Exception ex) { Log($"❌ [LỖI]: {ex.Message}"); }
            };

            // 4B. GIẢI MÃ VĂN BẢN
            btnDecryptText.Click += (s, e) => {
                try
                {
                    EnsureKey();
                    if (string.IsNullOrEmpty(lastEncryptedBase64))
                    {
                        Log("⚠️ Chưa có bản mã nào! Hãy bấm '🔒 4a. Mã hóa' trước nhé.");
                        return;
                    }

                    byte[] cipherBytes = Convert.FromBase64String(lastEncryptedBase64);
                    string decryptedText;
                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = currentKey!;
                        aes.IV = currentIV!;
                        aes.Mode = CipherMode.CBC;
                        aes.Padding = PaddingMode.PKCS7;

                        using (MemoryStream ms = new MemoryStream(cipherBytes))
                        using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                        using (StreamReader reader = new StreamReader(cs, Encoding.UTF8))
                        {
                            decryptedText = reader.ReadToEnd();
                        }
                    }

                    bool match = (decryptedText == txtPlainText.Text);
                    Log(">>> [4b] KẾT QUẢ GIẢI MÃ ĐOẠN VĂN BẢN 🔓:");
                    Log($"    📝 Văn bản sau giải mã : {decryptedText}");
                    Log($"    💖 Đối chứng với gốc   : {(match ? "✅ CHÍNH XÁC 100% (Khớp tuyệt đối)" : "❌ KHÔNG KHỚP")}");
                    Log("--------------------------------------------------------------------------------------");
                }
                catch (Exception ex) { Log($"❌ [LỖI]: {ex.Message}"); }
            };

            // 5A. MÃ HÓA FILE TÙY Ý
            btnEncryptFile.Click += async (s, e) => {
                try
                {
                    EnsureKey();
                    using (OpenFileDialog ofd = new OpenFileDialog())
                    {
                        ofd.Title = "Chọn tập tin bất kỳ để mã hóa AES";
                        if (ofd.ShowDialog() == DialogResult.OK)
                        {
                            string src = ofd.FileName;
                            string dest = src + ".aes";
                            btnEncryptFile.Enabled = false;
                            Log($">>> [5a] 📦 Đang tiến hành mã hóa tập tin: {Path.GetFileName(src)}...");

                            Stopwatch sw = Stopwatch.StartNew();
                            await Task.Run(() => ProcessFile(src, dest, true));
                            sw.Stop();

                            FileInfo fiSrc = new FileInfo(src);
                            FileInfo fiDest = new FileInfo(dest);
                            Log($"    ✅ Mã hóa file thành công -> {Path.GetFileName(dest)}");
                            Log($"    📊 Dung lượng: Gốc {fiSrc.Length:N0} bytes ➡️ Mã hóa {fiDest.Length:N0} bytes");
                            Log($"    ⏱️ Thời gian thực thi: {sw.Elapsed.TotalSeconds:F3} giây");
                        }
                    }
                }
                catch (Exception ex) { Log($"❌ [LỖI]: {ex.Message}"); }
                finally { btnEncryptFile.Enabled = true; }
            };

            // 5B. GIẢI MÃ FILE .AES TÙY Ý
            btnDecryptFile.Click += async (s, e) => {
                try
                {
                    EnsureKey();
                    using (OpenFileDialog ofd = new OpenFileDialog())
                    {
                        ofd.Title = "Chọn tập tin .aes để giải mã";
                        ofd.Filter = "AES Encrypted File (*.aes)|*.aes|All Files (*.*)|*.*";
                        if (ofd.ShowDialog() == DialogResult.OK)
                        {
                            string src = ofd.FileName;
                            string dest = src.EndsWith(".aes") ? src.Substring(0, src.Length - 4) + ".decrypted" + Path.GetExtension(src.Substring(0, src.Length - 4)) : src + ".decrypted";
                            btnDecryptFile.Enabled = false;
                            Log($">>> [5b] 🔓 Đang tiến hành giải mã tập tin: {Path.GetFileName(src)}...");

                            Stopwatch sw = Stopwatch.StartNew();
                            await Task.Run(() => ProcessFile(src, dest, false));
                            sw.Stop();

                            FileInfo fiDest = new FileInfo(dest);
                            Log($"    ✅ Giải mã file thành công -> {Path.GetFileName(dest)} ({fiDest.Length:N0} bytes)");
                            Log($"    ⏱️ Thời gian thực thi: {sw.Elapsed.TotalSeconds:F3} giây");
                        }
                    }
                }
                catch (Exception ex) { Log($"❌ [LỖI]: {ex.Message}"); }
                finally { btnDecryptFile.Enabled = true; }
            };

            // XÓA LOG
            btnClearLog.Click += (s, e) => txtLog.Clear();

            // 5C. TEST FILE LỚN 1GB
            btnFileLarge.Click += async (s, e) => {
                try
                {
                    EnsureKey();
                    btnFileLarge.Enabled = false;
                    btnFileLarge.Text = "⏳ Đang chạy thử nghiệm Benchmark File 1GB, vui lòng đợi trong giây lát...";

                    string src = "test_1GB.bin";
                    if (!File.Exists(src))
                    {
                        Log(">>> ⏳ Đang tự động tạo file mẫu 1GB (test_1GB.bin), vui lòng chờ...");
                        await Task.Run(() => CreateDummyFile(src, 1024));
                        Log("    -> Đã tạo xong file giả lập 1GB!");
                    }

                    string enc = src + ".aes";
                    string dec = src + ".decrypted.bin";
                    FileInfo fiSrc = new FileInfo(src);
                    double sizeInMB = fiSrc.Length / (1024.0 * 1024.0);

                    Log("\n🌸 ======================================================================================");
                    Log($">>> [5c] BẮT ĐẦU THỬ NGHIỆM ĐO HIỆU NĂNG FILE 1GB ({sizeInMB:N2} MB)...");

                    // 1. Mã hóa
                    Stopwatch sw1 = Stopwatch.StartNew();
                    await Task.Run(() => ProcessFile(src, enc, true));
                    sw1.Stop();
                    FileInfo fiEnc = new FileInfo(enc);
                    double encSpeed = sizeInMB / sw1.Elapsed.TotalSeconds;
                    Log($"    1. 🔒 Mã hóa hoàn tất -> {enc} ({fiEnc.Length:N0} bytes)");
                    Log($"       + Thời gian mã hóa : {sw1.Elapsed.TotalSeconds:F3} s ({sw1.ElapsedMilliseconds} ms)");
                    Log($"       + Tốc độ trung bình: {encSpeed:F2} MB/s");

                    // 2. Giải mã
                    Stopwatch sw2 = Stopwatch.StartNew();
                    await Task.Run(() => ProcessFile(enc, dec, false));
                    sw2.Stop();
                    FileInfo fiDec = new FileInfo(dec);
                    double decSpeed = sizeInMB / sw2.Elapsed.TotalSeconds;
                    Log($"    2. 🔓 Giải mã hoàn tất -> {dec} ({fiDec.Length:N0} bytes)");
                    Log($"       + Thời gian giải mã: {sw2.Elapsed.TotalSeconds:F3} s ({sw2.ElapsedMilliseconds} ms)");
                    Log($"       + Tốc độ trung bình: {decSpeed:F2} MB/s");

                    // 3. So sánh Byte SIMD
                    Log("    3. ⚡ Đang so sánh từng byte giữa file nguồn và file giải mã (SIMD Vector)...");
                    Stopwatch sw3 = Stopwatch.StartNew();
                    bool match = await Task.Run(() => CompareFiles(src, dec));
                    sw3.Stop();
                    Log($"       + Thời gian so sánh: {sw3.Elapsed.TotalSeconds:F3} s");
                    Log($"       + KẾT QUẢ ĐỐI CHỨNG : {(match ? "💖 GIỐNG NHAU 100% (Khớp tuyệt đối từng byte!)" : "❌ KHÁC NHAU")}");
                    Log("======================================================================================\n");
                }
                catch (Exception ex) { Log($"❌ [LỖI]: {ex.Message}"); }
                finally
                {
                    btnFileLarge.Enabled = true;
                    btnFileLarge.Text = "🚀 5c. Thử nghiệm Benchmark File Lớn (1 GB) & So sánh Byte-by-Byte (SIMD) 💖";
                }
            };
        }

        private void EnsureKey()
        {
            if (currentKey == null || currentIV == null)
                throw new InvalidOperationException("Chưa có khóa AES! Bạn hãy bấm '✨ 1. Sinh khóa' hoặc '📂 3. Import khóa' trước nhé 🌸.");
        }

        private void Log(string msg)
        {
            if (txtLog.InvokeRequired)
            {
                txtLog.Invoke(new Action(() => Log(msg)));
                return;
            }
            txtLog.AppendText(msg + "\r\n");
        }

        private void ProcessFile(string inPath, string outPath, bool encrypt)
        {
            int bufSize = 1024 * 1024; // Buffer 1MB tối ưu tốc độ đọc/ghi I/O
            using (Aes aes = Aes.Create())
            {
                aes.Key = currentKey!;
                aes.IV = currentIV!;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (FileStream fsIn = new FileStream(inPath, FileMode.Open, FileAccess.Read, FileShare.Read, bufSize))
                using (FileStream fsOut = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None, bufSize))
                using (CryptoStream cs = new CryptoStream(fsOut, encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    byte[] buf = new byte[bufSize];
                    int read;
                    while ((read = fsIn.Read(buf, 0, buf.Length)) > 0)
                    {
                        cs.Write(buf, 0, read);
                    }
                    cs.FlushFinalBlock();
                }
            }
        }

        private bool CompareFiles(string f1, string f2)
        {
            FileInfo fi1 = new FileInfo(f1);
            FileInfo fi2 = new FileInfo(f2);
            if (fi1.Length != fi2.Length) return false;

            int bufSize = 1024 * 1024;
            byte[] b1 = new byte[bufSize];
            byte[] b2 = new byte[bufSize];

            using (FileStream fs1 = new FileStream(f1, FileMode.Open, FileAccess.Read, FileShare.Read, bufSize))
            using (FileStream fs2 = new FileStream(f2, FileMode.Open, FileAccess.Read, FileShare.Read, bufSize))
            {
                int r1;
                while ((r1 = fs1.Read(b1, 0, bufSize)) > 0)
                {
                    int r2 = fs2.Read(b2, 0, bufSize);
                    if (r1 != r2) return false;

                    // Sử dụng ReadOnlySpan<byte>.SequenceEqual tối ưu vector hóa SIMD của .NET
                    if (!b1.AsSpan(0, r1).SequenceEqual(b2.AsSpan(0, r2)))
                        return false;
                }
            }
            return true;
        }

        private void CreateDummyFile(string path, int mb)
        {
            byte[] buf = new byte[1024 * 1024];
            Random r = new Random();
            using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, buf.Length))
            {
                for (int i = 0; i < mb; i++)
                {
                    r.NextBytes(buf);
                    fs.Write(buf, 0, buf.Length);
                }
            }
        }
    }
}