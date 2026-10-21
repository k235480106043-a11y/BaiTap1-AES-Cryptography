using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BaiTap2_RSA
{
    public class MainForm : Form
    {
        // Trạng thái hệ thống RSA
        private RSA? currentRsa;
        private string currentPublicPem = string.Empty;
        private string currentPrivatePem = string.Empty;
        private RsaKeyDetail? currentKeyDetail;

        // Dữ liệu mã hóa/giải mã
        private byte[]? lastPlainBytes;
        private byte[]? lastEncryptedBytes;

        // Dữ liệu băm SHA-256
        private byte[]? previousHash;
        private string previousText = string.Empty;

        // Controls giao diện chính
        private TabControl tabMain = null!;
        private TextBox txtGlobalLog = null!;

        // Tab 1: Sinh khóa
        private ComboBox cboKeySize = null!;
        private TextBox txtPublicPemTab1 = null!;
        private TextBox txtPrivatePemTab1 = null!;
        private CuteBadge badgeKeyStatus = null!;

        // Tab 2: Cấu trúc PEM & ASN.1
        private TextBox txtPemInput = null!;
        private DataGridView dgvAsn1 = null!;
        private TextBox txtParamSummary = null!;

        // Tab 3: Mã hóa / Giải mã
        private TextBox txtPlainText = null!;
        private Label lblByteCount = null!;
        private TextBox txtCipherBase64 = null!;
        private TextBox txtCipherHex = null!;
        private TextBox txtDecryptedResult = null!;
        private CuteBadge badgeComparison = null!;
        private RadioButton radOaep = null!;
        private RadioButton radPkcs1 = null!;

        // Tab 4: Benchmark
        private NumericUpDown numIterations = null!;
        private TextBox txtBenchmarkReport = null!;
        private ProgressBar prgBenchmark = null!;
        private Label lblPubOps = null!;
        private Label lblPrivOps = null!;
        private Label lblSpeedRatio = null!;

        // Tab 5: SHA-256
        private TextBox txtShaInput = null!;
        private TextBox txtCurrentHashHex = null!;
        private TextBox txtPrevHashHex = null!;
        private Label lblFlippedBits = null!;
        private Label lblAvalanchePct = null!;
        private RichTextBox rtbBitDiff = null!;

        // Tab 6: Chữ ký số
        private TextBox txtSignInput = null!;
        private TextBox txtSignatureOutput = null!;
        private CuteBadge badgeSigStatus = null!;
        private TextBox txtPssResult1 = null!;
        private TextBox txtPssResult2 = null!;
        private TextBox txtPssResult3 = null!;
        private CuteBadge badgePssVerify = null!;

        public MainForm()
        {
            InitializeCustomComponents();
            AppendLog("🚀 Khởi động ứng dụng Bài 2: Mã hóa RSA & Chữ ký số (.NET 10.0)");
            AppendLog("🌸 Sinh viên thực hiện: Nguyễn Thị Ngọc Linh - Lớp: K59KTP.K01");

            // Tự động sinh sẵn cặp khóa 2048-bit ban đầu để tiện thử nghiệm
            this.Shown += (s, e) =>
            {
                btnGenKey_Click(this, EventArgs.Empty);
            };
        }

        private void InitializeCustomComponents()
        {
            // Thiết lập cửa sổ chính
            this.Text = "💜 Bài 2: Mã Hóa Bất Đối Xứng RSA & Chữ Ký Số (.NET) • Nguyễn Thị Ngọc Linh";
            this.Size = new Size(1250, 845);
            this.MinimumSize = new Size(1150, 750);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(248, 246, 252);
            this.Font = new Font("Segoe UI", 9.5F, FontStyle.Regular);
            this.AutoScroll = true;

            // ==============================================================
            // 1. BANNER TIÊU ĐỀ SANG TRỌNG
            // ==============================================================
            CuteCard cardHeader = new CuteCard
            {
                Location = new Point(16, 10),
                Size = new Size(1202, 68),
                CardBackground = Color.White,
                BorderColor = Color.FromArgb(225, 215, 245),
                CornerRadius = 14
            };

            Label lblTitle = new Label
            {
                Text = "🔐 BÀI 2: MÃ HÓA BẤT ĐỐI XỨNG RSA & CHỮ KÝ SỐ (.NET C#)",
                UseMnemonic = false,
                Font = new Font("Segoe UI", 13F, FontStyle.Bold),
                ForeColor = Color.FromArgb(106, 27, 154),
                Location = new Point(16, 9),
                AutoSize = true
            };

            Label lblSubtitle = new Label
            {
                Text = "🌸 Sinh viên: Nguyễn Thị Ngọc Linh  |  Lớp: K59KTP.K01  |  Học phần: An toàn và bảo mật thông tin",
                UseMnemonic = false,
                Font = new Font("Segoe UI", 9.25F, FontStyle.Regular),
                ForeColor = Color.FromArgb(142, 36, 170),
                Location = new Point(18, 37),
                AutoSize = true
            };

            CuteButton btnCopyLog = new CuteButton
            {
                Text = "📋 Sao chép Log",
                Size = new Size(135, 34),
                Location = new Point(920, 17),
                NormalColor = Color.FromArgb(156, 39, 176),
                HoverColor = Color.FromArgb(142, 36, 170)
            };
            btnCopyLog.Click += (s, e) =>
            {
                if (!string.IsNullOrEmpty(txtGlobalLog.Text))
                {
                    Clipboard.SetText(txtGlobalLog.Text);
                    MessageBox.Show("Đã sao chép toàn bộ nhật ký vào Clipboard!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            };

            CuteButton btnClearLog = new CuteButton
            {
                Text = "🧹 Xóa Log",
                Size = new Size(115, 34),
                Location = new Point(1065, 17),
                NormalColor = Color.FromArgb(186, 104, 200),
                HoverColor = Color.FromArgb(171, 71, 188)
            };
            btnClearLog.Click += (s, e) => txtGlobalLog.Clear();

            cardHeader.Controls.AddRange(new Control[] { lblTitle, lblSubtitle, btnCopyLog, btnClearLog });
            this.Controls.Add(cardHeader);

            // ==============================================================
            // 2. TAB CONTROL CHÍNH (6 TABS PHỦ 9 YÊU CẦU)
            // ==============================================================
            tabMain = new TabControl
            {
                Location = new Point(16, 85),
                Size = new Size(1202, 540),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Padding = new Point(12, 7)
            };

            TabPage tab1 = BuildTab1KeyGen();
            TabPage tab2 = BuildTab2PemAnalyzer();
            TabPage tab3 = BuildTab3EncryptDecrypt();
            TabPage tab4 = BuildTab4Benchmark();
            TabPage tab5 = BuildTab5Sha256();
            TabPage tab6 = BuildTab6DigitalSignature();

            tabMain.TabPages.AddRange(new TabPage[] { tab1, tab2, tab3, tab4, tab5, tab6 });
            this.Controls.Add(tabMain);

            // ==============================================================
            // 3. KHUNG NHẬT KÝ HOẠT ĐỘNG (GLOBAL LOG)
            // ==============================================================
            CuteCard cardLog = new CuteCard
            {
                Location = new Point(16, 632),
                Size = new Size(1202, 160),
                CardBackground = Color.White,
                BorderColor = Color.FromArgb(225, 215, 245),
                CornerRadius = 14
            };

            Label lblLogTitle = new Label
            {
                Text = "📋 NHẬT KÝ THAO TÁC HỆ THỐNG (SYSTEM ACTIVITY LOG)",
                UseMnemonic = false,
                Font = new Font("Segoe UI", 9.0F, FontStyle.Bold),
                ForeColor = Color.FromArgb(106, 27, 154),
                Location = new Point(12, 8),
                AutoSize = true
            };

            txtGlobalLog = new TextBox
            {
                Location = new Point(12, 28),
                Size = new Size(1178, 122),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                ReadOnly = true,
                BackColor = Color.FromArgb(250, 248, 255),
                ForeColor = Color.FromArgb(40, 40, 50),
                Font = new Font("Consolas", 9.0F)
            };

            cardLog.Controls.AddRange(new Control[] { lblLogTitle, txtGlobalLog });
            this.Controls.Add(cardLog);
        }

        #region TAB 1: SINH KHÓA & XUẤT PEM (Yêu cầu 1, 2)
        private TabPage BuildTab1KeyGen()
        {
            TabPage tab = new TabPage("🔑 1. Sinh & Xuất Khóa");
            tab.BackColor = Color.FromArgb(252, 250, 255);

            CuteCard cardGen = new CuteCard
            {
                Location = new Point(14, 10),
                Size = new Size(1174, 66),
                CardBackground = Color.White
            };

            Label lblSize = new Label
            {
                Text = "Độ dài khóa (Key Size):",
                Location = new Point(16, 22),
                AutoSize = true,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(70, 70, 80)
            };

            cboKeySize = new ComboBox
            {
                Location = new Point(190, 19),
                Size = new Size(210, 28),
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font = new Font("Segoe UI", 9.5F)
            };
            cboKeySize.Items.AddRange(new object[] { "1024 bits (Cũ)", "2048 bits (Khuyên dùng)", "4096 bits (Bảo mật cao)" });
            cboKeySize.SelectedIndex = 1;

            CuteButton btnGenKey = new CuteButton
            {
                Text = "🎲 Sinh Cặp Khóa RSA Mới",
                Size = new Size(230, 38),
                Location = new Point(415, 14),
                NormalColor = Color.FromArgb(124, 77, 255),
                HoverColor = Color.FromArgb(101, 51, 238)
            };
            btnGenKey.Click += btnGenKey_Click;

            badgeKeyStatus = new CuteBadge
            {
                Text = "Chưa sinh khóa",
                Size = new Size(500, 36),
                Location = new Point(660, 15)
            };

            cardGen.Controls.AddRange(new Control[] { lblSize, cboKeySize, btnGenKey, badgeKeyStatus });
            tab.Controls.Add(cardGen);

            // Khung hiển thị Public Key
            CuteCard cardPublic = new CuteCard
            {
                Location = new Point(14, 84),
                Size = new Size(577, 416),
                CardBackground = Color.White
            };
            Label lblPub = new Label
            {
                Text = "🌐 Public Key (Khóa Công Khai - PKCS#1):",
                Font = new Font("Segoe UI", 10F, FontStyle.Bold),
                ForeColor = Color.FromArgb(46, 125, 50),
                Location = new Point(14, 12),
                AutoSize = true
            };
            txtPublicPemTab1 = new TextBox
            {
                Location = new Point(14, 38),
                Size = new Size(547, 305),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 9F),
                ReadOnly = true,
                BackColor = Color.FromArgb(248, 255, 248)
            };
            CuteButton btnSavePub = new CuteButton
            {
                Text = "💾 Xuất file Public (.pem)",
                Size = new Size(240, 42),
                Location = new Point(14, 355),
                NormalColor = Color.FromArgb(46, 125, 50),
                HoverColor = Color.FromArgb(36, 105, 40)
            };
            btnSavePub.Click += (s, e) => ExportPemToFile(currentPublicPem, "rsa_public_key.pem");

            CuteButton btnCopyPub = new CuteButton
            {
                Text = "📋 Copy Public PEM",
                Size = new Size(210, 42),
                Location = new Point(270, 355),
                NormalColor = Color.FromArgb(67, 160, 71),
                HoverColor = Color.FromArgb(56, 142, 60)
            };
            btnCopyPub.Click += (s, e) =>
            {
                if (!string.IsNullOrEmpty(txtPublicPemTab1.Text))
                {
                    Clipboard.SetText(txtPublicPemTab1.Text);
                    MessageBox.Show("Đã copy Public Key PEM vào Clipboard!", "Thành công", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            };
            cardPublic.Controls.AddRange(new Control[] { lblPub, txtPublicPemTab1, btnSavePub, btnCopyPub });
            tab.Controls.Add(cardPublic);

            // Khung hiển thị Private Key
            CuteCard cardPrivate = new CuteCard
            {
                Location = new Point(611, 84),
                Size = new Size(577, 416),
                CardBackground = Color.White
            };
            Label lblPriv = new Label
            {
                Text = "🔒 Private Key (Khóa Bí Mật - PKCS#1):",
                Font = new Font("Segoe UI", 10F, FontStyle.Bold),
                ForeColor = Color.FromArgb(198, 40, 40),
                Location = new Point(14, 12),
                AutoSize = true
            };
            txtPrivatePemTab1 = new TextBox
            {
                Location = new Point(14, 38),
                Size = new Size(547, 305),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 9F),
                ReadOnly = true,
                BackColor = Color.FromArgb(255, 248, 248)
            };
            CuteButton btnSavePriv = new CuteButton
            {
                Text = "💾 Xuất file Private (.pem)",
                Size = new Size(240, 42),
                Location = new Point(14, 355),
                NormalColor = Color.FromArgb(198, 40, 40),
                HoverColor = Color.FromArgb(170, 30, 30)
            };
            btnSavePriv.Click += (s, e) => ExportPemToFile(currentPrivatePem, "rsa_private_key.pem");

            CuteButton btnCopyPriv = new CuteButton
            {
                Text = "📋 Copy Private PEM",
                Size = new Size(210, 42),
                Location = new Point(270, 355),
                NormalColor = Color.FromArgb(216, 27, 96),
                HoverColor = Color.FromArgb(190, 20, 80)
            };
            btnCopyPriv.Click += (s, e) =>
            {
                if (!string.IsNullOrEmpty(txtPrivatePemTab1.Text))
                {
                    Clipboard.SetText(txtPrivatePemTab1.Text);
                    MessageBox.Show("Đã copy Private Key PEM vào Clipboard!", "Thành công", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            };
            cardPrivate.Controls.AddRange(new Control[] { lblPriv, txtPrivatePemTab1, btnSavePriv, btnCopyPriv });
            tab.Controls.Add(cardPrivate);

            return tab;
        }

        private void btnGenKey_Click(object? sender, EventArgs e)
        {
            try
            {
                int bits = cboKeySize.SelectedIndex switch
                {
                    0 => 1024,
                    2 => 4096,
                    _ => 2048
                };

                AppendLog($"⏳ Đang khởi tạo cặp khóa RSA-{bits} bits...");
                var (pubPem, privPem, rsa) = RsaHelper.GenerateKeyPair(bits);
                currentRsa?.Dispose();
                currentRsa = rsa;
                currentPublicPem = pubPem;
                currentPrivatePem = privPem;

                txtPublicPemTab1.Text = pubPem;
                txtPrivatePemTab1.Text = privPem;

                badgeKeyStatus.Text = $"✅ RSA-{bits} Đã Sinh Thành Công ({DateTime.Now:HH:mm:ss})";
                badgeKeyStatus.BadgeColor = Color.FromArgb(232, 245, 233);
                badgeKeyStatus.ForeColor = Color.FromArgb(46, 125, 50);

                AppendLog($"✅ Đã sinh thành công cặp khóa RSA-{bits}-bit chuẩn PKCS#1.");

                // Cập nhật tab 2 phân tích tự động khóa private
                txtPemInput.Text = privPem;
                AnalyzePemAndDisplay(privPem);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi sinh khóa RSA: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                AppendLog($"❌ Lỗi sinh khóa: {ex.Message}");
            }
        }

        private void ExportPemToFile(string pemContent, string defaultFileName)
        {
            if (string.IsNullOrEmpty(pemContent))
            {
                MessageBox.Show("Chưa có khóa để xuất ra file! Vui lòng sinh khóa trước.", "Cảnh báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                sfd.FileName = defaultFileName;
                sfd.Filter = "PEM Files (*.pem)|*.pem|Text Files (*.txt)|*.txt|All Files (*.*)|*.*";
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    File.WriteAllText(sfd.FileName, pemContent, Encoding.UTF8);
                    MessageBox.Show($"Đã xuất file thành công tại:\n{sfd.FileName}", "Thành công", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    AppendLog($"💾 Đã lưu file khóa: {sfd.FileName} ({new FileInfo(sfd.FileName).Length} bytes)");
                }
            }
        }
        #endregion

        #region TAB 2: CẤU TRÚC PEM & ASN.1 DER (Yêu cầu 3, 4)
        private TabPage BuildTab2PemAnalyzer()
        {
            TabPage tab = new TabPage("📜 2. Phân Tích PEM & ASN.1");
            tab.BackColor = Color.FromArgb(252, 250, 255);

            CuteCard cardTop = new CuteCard
            {
                Location = new Point(14, 10),
                Size = new Size(1174, 64),
                CardBackground = Color.White
            };

            CuteButton btnImportPemFile = new CuteButton
            {
                Text = "📂 Nhập File PEM (.pem/.txt)",
                Size = new Size(230, 38),
                Location = new Point(14, 13),
                NormalColor = Color.FromArgb(106, 27, 154),
                HoverColor = Color.FromArgb(74, 20, 140)
            };
            btnImportPemFile.Click += btnImportPemFile_Click;

            CuteButton btnUseGenPub = new CuteButton
            {
                Text = "🌐 Nạp Public Key Vừa Sinh",
                Size = new Size(220, 38),
                Location = new Point(255, 13),
                NormalColor = Color.FromArgb(46, 125, 50),
                HoverColor = Color.FromArgb(36, 105, 40)
            };
            btnUseGenPub.Click += (s, e) =>
            {
                if (string.IsNullOrEmpty(currentPublicPem))
                {
                    MessageBox.Show("Chưa sinh khóa!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                txtPemInput.Text = currentPublicPem;
                AnalyzePemAndDisplay(currentPublicPem);
            };

            CuteButton btnUseGenPriv = new CuteButton
            {
                Text = "🔒 Nạp Private Key Vừa Sinh",
                Size = new Size(220, 38),
                Location = new Point(485, 13),
                NormalColor = Color.FromArgb(198, 40, 40),
                HoverColor = Color.FromArgb(170, 30, 30)
            };
            btnUseGenPriv.Click += (s, e) =>
            {
                if (string.IsNullOrEmpty(currentPrivatePem))
                {
                    MessageBox.Show("Chưa sinh khóa!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                txtPemInput.Text = currentPrivatePem;
                AnalyzePemAndDisplay(currentPrivatePem);
            };

            cardTop.Controls.AddRange(new Control[] { btnImportPemFile, btnUseGenPub, btnUseGenPriv });
            tab.Controls.Add(cardTop);

            // Bảng phân tích cấu trúc ASN.1
            CuteCard cardTable = new CuteCard
            {
                Location = new Point(14, 82),
                Size = new Size(746, 420),
                CardBackground = Color.White
            };
            Label lblGrid = new Label
            {
                Text = "📊 Bóc Tách Các Trường ASN.1 DER (Ý nghĩa từng Byte/Tham số):",
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(70, 70, 80),
                Location = new Point(12, 10),
                AutoSize = true
            };
            dgvAsn1 = new DataGridView
            {
                Location = new Point(12, 35),
                Size = new Size(722, 372),
                BackgroundColor = Color.White,
                BorderStyle = BorderStyle.None,
                RowHeadersVisible = false,
                AllowUserToAddRows = false,
                ReadOnly = true,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None,
                EnableHeadersVisualStyles = false,
                ColumnHeadersHeight = 32
            };
            dgvAsn1.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(243, 238, 252);
            dgvAsn1.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(74, 20, 140);
            dgvAsn1.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            dgvAsn1.DefaultCellStyle.Font = new Font("Segoe UI", 8.5F);
            dgvAsn1.RowTemplate.Height = 28;

            int c0 = dgvAsn1.Columns.Add("Field", "Tên Trường");
            dgvAsn1.Columns[c0].Width = 125;
            int c1 = dgvAsn1.Columns.Add("Symbol", "Ký Hiệu");
            dgvAsn1.Columns[c1].Width = 75;
            int c2 = dgvAsn1.Columns.Add("Tag", "Tag ASN.1");
            dgvAsn1.Columns[c2].Width = 105;
            int c3 = dgvAsn1.Columns.Add("Preview", "Giá Trị Hex Mẫu");
            dgvAsn1.Columns[c3].Width = 145;
            int c4 = dgvAsn1.Columns.Add("Explanation", "Ý Nghĩa Toán Học / Mật Mã");
            dgvAsn1.Columns[c4].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            dgvAsn1.Columns[c4].MinimumWidth = 240;

            cardTable.Controls.AddRange(new Control[] { lblGrid, dgvAsn1 });
            tab.Controls.Add(cardTable);

            // Khung tóm tắt tham số (n, e) hoặc (n, e, d, p, q, dp, dq, iqmp)
            CuteCard cardSummary = new CuteCard
            {
                Location = new Point(768, 82),
                Size = new Size(420, 420),
                CardBackground = Color.White
            };
            Label lblSum = new Label
            {
                Text = "📐 Tham Số Toán Học Đã Trích Xuất:",
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(70, 70, 80),
                Location = new Point(12, 10),
                AutoSize = true
            };
            txtParamSummary = new TextBox
            {
                Location = new Point(12, 35),
                Size = new Size(396, 215),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 8.5F),
                ReadOnly = true,
                BackColor = Color.FromArgb(250, 248, 255)
            };

            Label lblPemRaw = new Label
            {
                Text = "Nội dung PEM đang kiểm tra:",
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(100, 100, 110),
                Location = new Point(12, 258),
                AutoSize = true
            };
            txtPemInput = new TextBox
            {
                Location = new Point(12, 280),
                Size = new Size(396, 127),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 8F),
                ReadOnly = true,
                BackColor = Color.FromArgb(245, 245, 250)
            };

            cardSummary.Controls.AddRange(new Control[] { lblSum, txtParamSummary, lblPemRaw, txtPemInput });
            tab.Controls.Add(cardSummary);

            return tab;
        }

        private void btnImportPemFile_Click(object? sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Filter = "PEM Files (*.pem;*.key;*.pub)|*.pem;*.key;*.pub|Text Files (*.txt)|*.txt|All Files (*.*)|*.*";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        string pem = File.ReadAllText(ofd.FileName, Encoding.UTF8);
                        txtPemInput.Text = pem;
                        AnalyzePemAndDisplay(pem);
                        AppendLog($"📂 Đã nhập file PEM: {Path.GetFileName(ofd.FileName)} ({new FileInfo(ofd.FileName).Length} bytes)");
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Lỗi nạp file PEM: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        AppendLog($"❌ Lỗi nạp file PEM: {ex.Message}");
                    }
                }
            }
        }

        private void AnalyzePemAndDisplay(string pemText)
        {
            try
            {
                var (rsa, detail) = RsaHelper.ImportFromPemText(pemText);
                currentKeyDetail = detail;

                // Điền thông tin vào bảng ASN.1 DataGridView
                dgvAsn1.Rows.Clear();
                foreach (var f in detail.ParsedFields)
                {
                    dgvAsn1.Rows.Add(f.FieldName, f.MathSymbol, f.TagName, f.ValueHexPreview, f.Explanation);
                }

                // Điền tóm tắt tham số
                txtParamSummary.Text = detail.GetParamSummary();
                AppendLog($"📜 Phân tích PEM thành công: {detail.PemType} - Khóa {detail.KeySizeBits} bits - {detail.RawDer.Length} bytes DER.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Không thể phân tích định dạng PEM: {ex.Message}", "Lỗi Phân Tích", MessageBoxButtons.OK, MessageBoxIcon.Error);
                AppendLog($"❌ Lỗi phân tích PEM: {ex.Message}");
            }
        }
        #endregion

        #region TAB 3: MÃ HÓA & GIẢI MÃ (< 190 BYTES / KHÓA AES) (Yêu cầu 5, 6)
        private TabPage BuildTab3EncryptDecrypt()
        {
            TabPage tab = new TabPage("🔒 3. Mã Hóa & Giải Mã");
            tab.BackColor = Color.FromArgb(252, 250, 255);

            // Khung nhập Plaintext
            CuteCard cardInput = new CuteCard
            {
                Location = new Point(14, 10),
                Size = new Size(1174, 118),
                CardBackground = Color.White
            };

            Label lblInputTitle = new Label
            {
                Text = "📥 Dữ liệu đầu vào (Plaintext) - Tối đa 190 bytes (Mã hóa khóa AES 256-bit hoặc văn bản ngắn):",
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(70, 70, 80),
                Location = new Point(14, 10),
                AutoSize = true
            };

            lblByteCount = new Label
            {
                Text = "0 / 190 bytes",
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                ForeColor = Color.FromArgb(46, 125, 50),
                Location = new Point(960, 10),
                AutoSize = true
            };

            txtPlainText = new TextBox
            {
                Location = new Point(14, 34),
                Size = new Size(830, 46),
                Multiline = true,
                Font = new Font("Consolas", 9.5F)
            };
            txtPlainText.TextChanged += (s, e) =>
            {
                byte[] bytes = Encoding.UTF8.GetBytes(txtPlainText.Text);
                lblByteCount.Text = $"{bytes.Length} / 190 bytes " + (bytes.Length <= 190 ? "✅" : "⚠️ VƯỢT QUÁ");
                lblByteCount.ForeColor = bytes.Length <= 190 ? Color.FromArgb(46, 125, 50) : Color.Red;
            };

            CuteButton btnGenAesKey = new CuteButton
            {
                Text = "🔑 Tạo Khóa AES (32 bytes)",
                Size = new Size(305, 42),
                Location = new Point(855, 34),
                NormalColor = Color.FromArgb(124, 77, 255),
                HoverColor = Color.FromArgb(101, 51, 238)
            };
            btnGenAesKey.Click += (s, e) =>
            {
                byte[] aesKey = new byte[32];
                RandomNumberGenerator.Fill(aesKey);
                string b64 = Convert.ToBase64String(aesKey);
                txtPlainText.Text = b64;
                AppendLog($"🎲 Đã tạo mẫu khóa đối xứng AES-256 (32 bytes Base64): {b64}");
            };

            Label lblPadding = new Label
            {
                Text = "Cơ chế đệm (Padding):",
                Location = new Point(14, 88),
                AutoSize = true,
                Font = new Font("Segoe UI", 9F, FontStyle.Bold)
            };

            radOaep = new RadioButton
            {
                Text = "OAEP with SHA-256 (Chuẩn an toàn hiện đại - Max 190 bytes)",
                Location = new Point(175, 86),
                Size = new Size(430, 24),
                Checked = true
            };

            radPkcs1 = new RadioButton
            {
                Text = "PKCS#1 v1.5 (Tương thích cũ - Max 245 bytes)",
                Location = new Point(615, 86),
                Size = new Size(350, 24)
            };

            cardInput.Controls.AddRange(new Control[] { lblInputTitle, lblByteCount, txtPlainText, btnGenAesKey, lblPadding, radOaep, radPkcs1 });
            tab.Controls.Add(cardInput);

            // Khung Mã Hóa (Dùng Public Key)
            CuteCard cardEnc = new CuteCard
            {
                Location = new Point(14, 134),
                Size = new Size(577, 370),
                CardBackground = Color.White
            };
            Label lblEnc = new Label
            {
                Text = "🔒 Mã Hóa bằng RSA Public Key (Yêu cầu 5):",
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(46, 125, 50),
                Location = new Point(14, 8),
                AutoSize = true
            };
            CuteButton btnEncrypt = new CuteButton
            {
                Text = "🔒 Tiến Hành Mã Hóa",
                Size = new Size(220, 36),
                Location = new Point(14, 30),
                NormalColor = Color.FromArgb(46, 125, 50),
                HoverColor = Color.FromArgb(36, 105, 40)
            };
            btnEncrypt.Click += btnEncrypt_Click;

            CuteButton btnSaveCipher = new CuteButton
            {
                Text = "💾 Lưu Ciphertext Ra File",
                Size = new Size(235, 36),
                Location = new Point(245, 30),
                NormalColor = Color.FromArgb(56, 142, 60),
                HoverColor = Color.FromArgb(46, 125, 50)
            };
            btnSaveCipher.Click += btnSaveCipher_Click;

            Label lblB64 = new Label
            {
                Text = "Bản mã (Ciphertext dạng Base64):",
                Location = new Point(14, 70),
                AutoSize = true,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold)
            };
            txtCipherBase64 = new TextBox
            {
                Location = new Point(14, 90),
                Size = new Size(547, 102),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 8.5F),
                ReadOnly = true,
                BackColor = Color.FromArgb(248, 255, 248)
            };

            Label lblHex = new Label
            {
                Text = "Bản mã (Dạng Hex dump):",
                Location = new Point(14, 198),
                AutoSize = true,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold)
            };
            txtCipherHex = new TextBox
            {
                Location = new Point(14, 218),
                Size = new Size(547, 138),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 8.5F),
                ReadOnly = true,
                BackColor = Color.FromArgb(248, 255, 248)
            };
            cardEnc.Controls.AddRange(new Control[] { lblEnc, btnEncrypt, btnSaveCipher, lblB64, txtCipherBase64, lblHex, txtCipherHex });
            tab.Controls.Add(cardEnc);

            // Khung Giải Mã & So sánh (Dùng Private Key)
            CuteCard cardDec = new CuteCard
            {
                Location = new Point(611, 134),
                Size = new Size(577, 370),
                CardBackground = Color.White
            };
            Label lblDec = new Label
            {
                Text = "🔓 Giải Mã bằng RSA Private Key & So Sánh (Yêu cầu 6):",
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(198, 40, 40),
                Location = new Point(14, 8),
                AutoSize = true
            };
            CuteButton btnLoadCipher = new CuteButton
            {
                Text = "📂 Nạp File Cipher",
                Size = new Size(200, 36),
                Location = new Point(14, 30),
                NormalColor = Color.FromArgb(198, 40, 40),
                HoverColor = Color.FromArgb(170, 30, 30)
            };
            btnLoadCipher.Click += btnLoadCipher_Click;

            CuteButton btnDecrypt = new CuteButton
            {
                Text = "🔓 Tiến Hành Giải Mã",
                Size = new Size(220, 36),
                Location = new Point(225, 30),
                NormalColor = Color.FromArgb(216, 27, 96),
                HoverColor = Color.FromArgb(190, 20, 80)
            };
            btnDecrypt.Click += btnDecrypt_Click;

            badgeComparison = new CuteBadge
            {
                Text = "Chờ giải mã để đối chiếu",
                Size = new Size(547, 32),
                Location = new Point(14, 72),
                BadgeColor = Color.FromArgb(245, 245, 245),
                ForeColor = Color.FromArgb(100, 100, 100)
            };

            Label lblDecResult = new Label
            {
                Text = "Kết quả sau khi giải mã (Decrypted Plaintext):",
                Location = new Point(14, 110),
                AutoSize = true,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold)
            };
            txtDecryptedResult = new TextBox
            {
                Location = new Point(14, 130),
                Size = new Size(547, 226),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 9F),
                ReadOnly = true,
                BackColor = Color.FromArgb(255, 248, 248)
            };

            cardDec.Controls.AddRange(new Control[] { lblDec, btnLoadCipher, btnDecrypt, badgeComparison, lblDecResult, txtDecryptedResult });
            tab.Controls.Add(cardDec);

            return tab;
        }

        private void btnEncrypt_Click(object? sender, EventArgs e)
        {
            try
            {
                if (currentRsa == null)
                {
                    MessageBox.Show("Chưa có khóa RSA trong bộ nhớ! Hãy sinh hoặc import khóa ở Tab 1 hoặc Tab 2.", "Cảnh báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(txtPlainText.Text))
                {
                    MessageBox.Show("Vui lòng nhập văn bản hoặc bấm 'Tạo Khóa AES' trước khi mã hóa.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                byte[] plainBytes = Encoding.UTF8.GetBytes(txtPlainText.Text);
                bool useOaep = radOaep.Checked;

                lastPlainBytes = plainBytes;
                lastEncryptedBytes = RsaHelper.Encrypt(currentRsa, plainBytes, useOaep);

                string b64 = Convert.ToBase64String(lastEncryptedBytes);
                string hex = BitConverter.ToString(lastEncryptedBytes).Replace("-", " ");

                txtCipherBase64.Text = b64;
                txtCipherHex.Text = hex;

                string padName = useOaep ? "OAEP-SHA256" : "PKCS1";
                AppendLog($"🔒 Đã mã hóa {plainBytes.Length} bytes dữ liệu bằng Public Key RSA-{currentRsa.KeySize} -> {lastEncryptedBytes.Length} bytes Ciphertext ({padName}).");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi mã hóa RSA: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                AppendLog($"❌ Lỗi mã hóa: {ex.Message}");
            }
        }

        private void btnSaveCipher_Click(object? sender, EventArgs e)
        {
            if (lastEncryptedBytes == null || lastEncryptedBytes.Length == 0)
            {
                MessageBox.Show("Chưa có dữ liệu đã mã hóa để lưu!", "Cảnh báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                sfd.FileName = "rsa_encrypted_data.base64";
                sfd.Filter = "Base64 Text File (*.base64;*.txt)|*.base64;*.txt|Binary File (*.bin;*.dat)|*.bin;*.dat|All Files (*.*)|*.*";
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    if (sfd.FileName.EndsWith(".bin") || sfd.FileName.EndsWith(".dat"))
                    {
                        File.WriteAllBytes(sfd.FileName, lastEncryptedBytes);
                    }
                    else
                    {
                        File.WriteAllText(sfd.FileName, Convert.ToBase64String(lastEncryptedBytes), Encoding.UTF8);
                    }
                    MessageBox.Show($"Đã lưu bản mã thành công tại:\n{sfd.FileName}", "Thành công", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    AppendLog($"💾 Đã lưu ciphertext ra file: {sfd.FileName}");
                }
            }
        }

        private void btnLoadCipher_Click(object? sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Filter = "Cipher Files (*.base64;*.txt;*.bin)|*.base64;*.txt;*.bin|All Files (*.*)|*.*";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        if (ofd.FileName.EndsWith(".bin") || ofd.FileName.EndsWith(".dat"))
                        {
                            lastEncryptedBytes = File.ReadAllBytes(ofd.FileName);
                            txtCipherBase64.Text = Convert.ToBase64String(lastEncryptedBytes);
                        }
                        else
                        {
                            string b64 = File.ReadAllText(ofd.FileName, Encoding.UTF8).Trim();
                            lastEncryptedBytes = Convert.FromBase64String(b64);
                            txtCipherBase64.Text = b64;
                        }
                        txtCipherHex.Text = BitConverter.ToString(lastEncryptedBytes).Replace("-", " ");
                        AppendLog($"📂 Đã nạp file Ciphertext: {Path.GetFileName(ofd.FileName)} ({lastEncryptedBytes.Length} bytes)");
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Lỗi nạp file Ciphertext: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        AppendLog($"❌ Lỗi đọc ciphertext: {ex.Message}");
                    }
                }
            }
        }

        private void btnDecrypt_Click(object? sender, EventArgs e)
        {
            try
            {
                if (currentRsa == null)
                {
                    MessageBox.Show("Chưa có khóa RSA trong bộ nhớ!", "Cảnh báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (lastEncryptedBytes == null || lastEncryptedBytes.Length == 0)
                {
                    if (!string.IsNullOrEmpty(txtCipherBase64.Text))
                    {
                        lastEncryptedBytes = Convert.FromBase64String(txtCipherBase64.Text.Trim());
                    }
                    else
                    {
                        MessageBox.Show("Chưa có dữ liệu bản mã để giải mã!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                }

                bool useOaep = radOaep.Checked;
                byte[] decBytes = RsaHelper.Decrypt(currentRsa, lastEncryptedBytes, useOaep);
                string decText = Encoding.UTF8.GetString(decBytes);
                txtDecryptedResult.Text = decText;

                // Đối chiếu so sánh với dữ liệu nguồn (Yêu cầu 6)
                if (lastPlainBytes != null)
                {
                    bool isIdentical = decBytes.SequenceEqual(lastPlainBytes);
                    if (isIdentical)
                    {
                        badgeComparison.Text = $"🎉 KHỚP 100% VỚI BẢN GỐC (Bit-by-Bit Identical - {decBytes.Length} bytes)";
                        badgeComparison.BadgeColor = Color.FromArgb(232, 245, 233);
                        badgeComparison.ForeColor = Color.FromArgb(46, 125, 50);
                        AppendLog($"✅ Giải mã thành công: Dữ liệu khớp 100% với nguồn ({decBytes.Length} bytes).");
                    }
                    else
                    {
                        badgeComparison.Text = "⚠️ CẢNH BÁO: Dữ liệu giải mã KHÔNG KHỚP với nguồn!";
                        badgeComparison.BadgeColor = Color.FromArgb(255, 235, 238);
                        badgeComparison.ForeColor = Color.FromArgb(198, 40, 40);
                        AppendLog("⚠️ Cảnh báo: Kết quả giải mã sai lệch so với nguồn ban đầu.");
                    }
                }
                else
                {
                    badgeComparison.Text = $"✅ Giải mã thành công ({decBytes.Length} bytes)";
                    badgeComparison.BadgeColor = Color.FromArgb(232, 245, 233);
                    badgeComparison.ForeColor = Color.FromArgb(46, 125, 50);
                    AppendLog($"✅ Giải mã thành công {decBytes.Length} bytes.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi giải mã RSA: {ex.Message}\n(Lưu ý: Bạn phải dùng đúng Private Key và đúng loại Padding)", "Lỗi Giải Mã", MessageBoxButtons.OK, MessageBoxIcon.Error);
                AppendLog($"❌ Lỗi giải mã: {ex.Message}");
            }
        }
        #endregion

        #region TAB 4: ĐÁNH GIÁ TỐC ĐỘ (BENCHMARK PUBLIC VS PRIVATE) (Yêu cầu 7)
        private TabPage BuildTab4Benchmark()
        {
            TabPage tab = new TabPage("⚡ 4. Đo Tốc Độ (Benchmark)");
            tab.BackColor = Color.FromArgb(252, 250, 255);

            CuteCard cardTop = new CuteCard
            {
                Location = new Point(14, 10),
                Size = new Size(1174, 66),
                CardBackground = Color.White
            };

            Label lblIter = new Label
            {
                Text = "Số lần lặp thử nghiệm:",
                Location = new Point(16, 23),
                AutoSize = true,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(70, 70, 80)
            };

            numIterations = new NumericUpDown
            {
                Location = new Point(190, 20),
                Size = new Size(100, 28),
                Minimum = 50,
                Maximum = 5000,
                Value = 500,
                Increment = 100,
                Font = new Font("Segoe UI", 9.5F)
            };

            CuteButton btnRunBench = new CuteButton
            {
                Text = "🚀 Bắt Đầu Đo Lường Tốc Độ",
                Size = new Size(240, 38),
                Location = new Point(305, 14),
                NormalColor = Color.FromArgb(255, 111, 0),
                HoverColor = Color.FromArgb(230, 81, 0)
            };
            btnRunBench.Click += btnRunBench_Click;

            prgBenchmark = new ProgressBar
            {
                Location = new Point(560, 20),
                Size = new Size(595, 26),
                Style = ProgressBarStyle.Continuous
            };

            cardTop.Controls.AddRange(new Control[] { lblIter, numIterations, btnRunBench, prgBenchmark });
            tab.Controls.Add(cardTop);

            // 3 Card tóm tắt trực quan
            CuteCard cardPubBox = new CuteCard
            {
                Location = new Point(14, 84),
                Size = new Size(375, 96),
                CardBackground = Color.FromArgb(240, 248, 255),
                BorderColor = Color.FromArgb(180, 220, 250)
            };
            Label lblPubT = new Label
            {
                Text = "🌐 PUBLIC KEY OPERATION (e = 65537)",
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                ForeColor = Color.FromArgb(21, 101, 192),
                Location = new Point(14, 10),
                AutoSize = true
            };
            lblPubOps = new Label
            {
                Text = "Tốc độ: -- ops/s",
                Font = new Font("Segoe UI", 15F, FontStyle.Bold),
                ForeColor = Color.FromArgb(13, 71, 161),
                Location = new Point(14, 36),
                AutoSize = true
            };
            cardPubBox.Controls.AddRange(new Control[] { lblPubT, lblPubOps });
            tab.Controls.Add(cardPubBox);

            CuteCard cardPrivBox = new CuteCard
            {
                Location = new Point(405, 84),
                Size = new Size(375, 96),
                CardBackground = Color.FromArgb(255, 245, 245),
                BorderColor = Color.FromArgb(255, 205, 210)
            };
            Label lblPrivT = new Label
            {
                Text = "🔒 PRIVATE KEY OPERATION (d ~ 2048-bit)",
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                ForeColor = Color.FromArgb(198, 40, 40),
                Location = new Point(14, 10),
                AutoSize = true
            };
            lblPrivOps = new Label
            {
                Text = "Tốc độ: -- ops/s",
                Font = new Font("Segoe UI", 15F, FontStyle.Bold),
                ForeColor = Color.FromArgb(183, 28, 28),
                Location = new Point(14, 36),
                AutoSize = true
            };
            cardPrivBox.Controls.AddRange(new Control[] { lblPrivT, lblPrivOps });
            tab.Controls.Add(cardPrivBox);

            CuteCard cardRatioBox = new CuteCard
            {
                Location = new Point(795, 84),
                Size = new Size(393, 96),
                CardBackground = Color.FromArgb(243, 229, 245),
                BorderColor = Color.FromArgb(206, 147, 216)
            };
            Label lblRatioT = new Label
            {
                Text = "⚡ TỶ LỆ CHÊNH LỆCH HIỆU NĂNG",
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                ForeColor = Color.FromArgb(106, 27, 154),
                Location = new Point(14, 10),
                AutoSize = true
            };
            lblSpeedRatio = new Label
            {
                Text = "Public nhanh hơn: -- lần",
                Font = new Font("Segoe UI", 15F, FontStyle.Bold),
                ForeColor = Color.FromArgb(74, 20, 140),
                Location = new Point(14, 36),
                AutoSize = true
            };
            cardRatioBox.Controls.AddRange(new Control[] { lblRatioT, lblSpeedRatio });
            tab.Controls.Add(cardRatioBox);

            // Khung báo cáo chi tiết & Giải thích lý thuyết toán học
            CuteCard cardReport = new CuteCard
            {
                Location = new Point(14, 186),
                Size = new Size(1174, 318),
                CardBackground = Color.White
            };
            Label lblRepT = new Label
            {
                Text = "📑 Báo Cáo Đo Đạc Thực Tế & Phân Tích Cơ Chế Toán Học (Lũy Thừa Nhị Phân & CRT):",
                UseMnemonic = false,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(70, 70, 80),
                Location = new Point(14, 8),
                AutoSize = true
            };
            txtBenchmarkReport = new TextBox
            {
                Location = new Point(14, 30),
                Size = new Size(1146, 276),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 9F),
                ReadOnly = true,
                BackColor = Color.FromArgb(250, 248, 255)
            };
            cardReport.Controls.AddRange(new Control[] { lblRepT, txtBenchmarkReport });
            tab.Controls.Add(cardReport);

            return tab;
        }

        private async void btnRunBench_Click(object? sender, EventArgs e)
        {
            if (currentRsa == null)
            {
                MessageBox.Show("Chưa có khóa RSA để benchmark! Vui lòng sinh khóa ở Tab 1.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            int iters = (int)numIterations.Value;
            AppendLog($"⚡ Bắt đầu thực nghiệm Benchmark RSA-{currentRsa.KeySize} với {iters} phép tính lặp...");

            prgBenchmark.Style = ProgressBarStyle.Marquee;
            prgBenchmark.MarqueeAnimationSpeed = 30;

            try
            {
                BenchmarkResult res = await Task.Run(() => RsaHelper.RunBenchmark(currentRsa, iters));

                lblPubOps.Text = $"{res.PublicOpsPerSec:F1} ops/s";
                lblPrivOps.Text = $"{res.PrivateOpsPerSec:F1} ops/s";
                lblSpeedRatio.Text = $"Public nhanh gấp {res.SpeedRatio:F1}x";

                txtBenchmarkReport.Text = res.GetDetailedReport();
                AppendLog($"✅ Hoàn thành Benchmark: Public Key ({res.PublicOpsPerSec:F0} ops/s) nhanh gấp {res.SpeedRatio:F1} lần so với Private Key ({res.PrivateOpsPerSec:F0} ops/s)!");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi benchmark: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                AppendLog($"❌ Lỗi benchmark: {ex.Message}");
            }
            finally
            {
                prgBenchmark.Style = ProgressBarStyle.Continuous;
                prgBenchmark.Value = 100;
            }
        }
        #endregion

        #region TAB 5: BĂM SHA-256 & HIỆU ỨNG TUYẾT LỞ (Yêu cầu 8)
        private TabPage BuildTab5Sha256()
        {
            TabPage tab = new TabPage("❄️ 5. SHA-256 & Avalanche");
            tab.BackColor = Color.FromArgb(252, 250, 255);

            CuteCard cardTop = new CuteCard
            {
                Location = new Point(14, 10),
                Size = new Size(1174, 118),
                CardBackground = Color.White
            };

            Label lblInputT = new Label
            {
                Text = "✍️ Dữ liệu đầu vào cần băm SHA-256 (Tự động cập nhật realtime khi gõ):",
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(70, 70, 80),
                Location = new Point(14, 10),
                AutoSize = true
            };

            txtShaInput = new TextBox
            {
                Location = new Point(14, 32),
                Size = new Size(720, 75),
                Multiline = true,
                Font = new Font("Consolas", 10F),
                Text = "Nguyen Thi Ngoc Linh - K59KTP.K01"
            };
            txtShaInput.TextChanged += txtShaInput_TextChanged;

            Label lblQuick = new Label
            {
                Text = "Thử nghiệm đổi cực ít dữ liệu đầu vào (Hiệu ứng Tuyết lở):",
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(100, 100, 110),
                Location = new Point(750, 10),
                AutoSize = true
            };

            CuteButton btnTest1 = new CuteButton
            {
                Text = "1. Thêm dấu chấm '.'",
                Size = new Size(195, 34),
                Location = new Point(750, 32),
                NormalColor = Color.FromArgb(124, 77, 255),
                HoverColor = Color.FromArgb(101, 51, 238)
            };
            btnTest1.Click += (s, e) => txtShaInput.Text = txtShaInput.Text.TrimEnd('.') + ".";

            CuteButton btnTest2 = new CuteButton
            {
                Text = "2. Đổi 'N' thành 'n'",
                Size = new Size(195, 34),
                Location = new Point(955, 32),
                NormalColor = Color.FromArgb(156, 39, 176),
                HoverColor = Color.FromArgb(142, 36, 170)
            };
            btnTest2.Click += (s, e) =>
            {
                if (txtShaInput.Text.StartsWith("Nguyen"))
                    txtShaInput.Text = "nguyen" + txtShaInput.Text.Substring(6);
                else
                    txtShaInput.Text = "Nguyen Thi Ngoc Linh - K59KTP.K01";
            };

            CuteButton btnTest3 = new CuteButton
            {
                Text = "3. Lật 1 bit cuối (Flip bit)",
                Size = new Size(195, 34),
                Location = new Point(750, 72),
                NormalColor = Color.FromArgb(233, 30, 99),
                HoverColor = Color.FromArgb(216, 27, 96)
            };
            btnTest3.Click += (s, e) =>
            {
                if (string.IsNullOrEmpty(txtShaInput.Text)) txtShaInput.Text = "A";
                char last = txtShaInput.Text[^1];
                char flipped = (char)(last ^ 1);
                txtShaInput.Text = txtShaInput.Text[..^1] + flipped;
            };

            CuteButton btnResetBaseline = new CuteButton
            {
                Text = "🔄 Đặt làm mốc so sánh",
                Size = new Size(195, 34),
                Location = new Point(955, 72),
                NormalColor = Color.FromArgb(67, 160, 71),
                HoverColor = Color.FromArgb(56, 142, 60)
            };
            btnResetBaseline.Click += (s, e) =>
            {
                byte[] bytes = Encoding.UTF8.GetBytes(txtShaInput.Text);
                previousHash = RsaHelper.ComputeSha256(bytes);
                previousText = txtShaInput.Text;
                txtPrevHashHex.Text = BitConverter.ToString(previousHash).Replace("-", "").ToLower();
                AppendLog($"📍 Đã đặt mốc so sánh mới với dữ liệu: '{previousText}'");
            };

            cardTop.Controls.AddRange(new Control[] { lblInputT, txtShaInput, lblQuick, btnTest1, btnTest2, btnTest3, btnResetBaseline });
            tab.Controls.Add(cardTop);

            // Khung hiển thị Hash & So sánh
            CuteCard cardHash = new CuteCard
            {
                Location = new Point(14, 136),
                Size = new Size(1174, 368),
                CardBackground = Color.White
            };

            Label lblCur = new Label
            {
                Text = "Mã băm SHA-256 Hiện Tại (256 bits = 64 Hex chars):",
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                ForeColor = Color.FromArgb(46, 125, 50),
                Location = new Point(14, 8),
                AutoSize = true
            };
            txtCurrentHashHex = new TextBox
            {
                Location = new Point(14, 28),
                Size = new Size(1146, 26),
                Font = new Font("Consolas", 10.5F, FontStyle.Bold),
                ReadOnly = true,
                BackColor = Color.FromArgb(240, 255, 240)
            };

            Label lblPrev = new Label
            {
                Text = "Mã băm SHA-256 Mốc Trước Đó (Để đánh giá sự thay đổi):",
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                ForeColor = Color.FromArgb(198, 40, 40),
                Location = new Point(14, 58),
                AutoSize = true
            };
            txtPrevHashHex = new TextBox
            {
                Location = new Point(14, 78),
                Size = new Size(1146, 26),
                Font = new Font("Consolas", 10.5F, FontStyle.Bold),
                ReadOnly = true,
                BackColor = Color.FromArgb(255, 245, 245)
            };

            // Badge thống kê Avalanche
            lblFlippedBits = new Label
            {
                Text = "Số bit biến đổi: -- / 256 bits",
                Font = new Font("Segoe UI", 11F, FontStyle.Bold),
                ForeColor = Color.FromArgb(106, 27, 154),
                Location = new Point(14, 112),
                AutoSize = true
            };

            lblAvalanchePct = new Label
            {
                Text = "Tỷ lệ biến đổi (Avalanche Rate): -- % (Lý thuyết tối ưu ~ 50%)",
                Font = new Font("Segoe UI", 11F, FontStyle.Bold),
                ForeColor = Color.FromArgb(198, 40, 40),
                Location = new Point(410, 112),
                AutoSize = true
            };

            Label lblDiffTitle = new Label
            {
                Text = "🔍 Đối chiếu chuỗi nhị phân 256 bits (Các bit bị đảo lật do hiệu ứng tuyết lở):",
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                ForeColor = Color.FromArgb(70, 70, 80),
                Location = new Point(14, 140),
                AutoSize = true
            };

            rtbBitDiff = new RichTextBox
            {
                Location = new Point(14, 162),
                Size = new Size(1146, 192),
                Font = new Font("Consolas", 9.5F),
                ReadOnly = true,
                BackColor = Color.FromArgb(250, 248, 255),
                BorderStyle = BorderStyle.None
            };

            cardHash.Controls.AddRange(new Control[] { lblCur, txtCurrentHashHex, lblPrev, txtPrevHashHex, lblFlippedBits, lblAvalanchePct, lblDiffTitle, rtbBitDiff });
            tab.Controls.Add(cardHash);

            return tab;
        }

        private void txtShaInput_TextChanged(object? sender, EventArgs e)
        {
            byte[] currentBytes = Encoding.UTF8.GetBytes(txtShaInput.Text);
            byte[] curHash = RsaHelper.ComputeSha256(currentBytes);
            string curHex = BitConverter.ToString(curHash).Replace("-", "").ToLower();
            txtCurrentHashHex.Text = curHex;

            if (previousHash == null)
            {
                previousHash = curHash;
                previousText = txtShaInput.Text;
                txtPrevHashHex.Text = curHex;
                lblFlippedBits.Text = "Số bit biến đổi: 0 / 256 bits (Khởi tạo)";
                lblAvalanchePct.Text = "Tỷ lệ biến đổi: 0.0%";
                rtbBitDiff.Text = "Bấm 'Thêm dấu chấm' hoặc sửa 1 ký tự để thấy hiệu ứng tuyết lở (Avalanche Effect).";
                return;
            }

            var (flipped, total, pct, bin1, bin2) = RsaHelper.EvaluateAvalanche(curHash, previousHash);
            lblFlippedBits.Text = $"Số bit biến đổi: {flipped} / {total} bits";
            lblAvalanchePct.Text = $"Tỷ lệ biến đổi: {pct:F2}% (Rất gần mức tối ưu mật mã 50%)";

            // Vẽ trực quan chuỗi bit
            rtbBitDiff.Clear();
            rtbBitDiff.SelectionColor = Color.FromArgb(70, 70, 70);
            rtbBitDiff.AppendText("Gốc  : " + bin2 + "\n");
            rtbBitDiff.AppendText("Mới  : ");

            for (int i = 0; i < bin1.Length; i++)
            {
                if (bin1[i] != bin2[i])
                {
                    rtbBitDiff.SelectionColor = Color.Red;
                    rtbBitDiff.SelectionFont = new Font("Consolas", 10F, FontStyle.Bold);
                }
                else
                {
                    rtbBitDiff.SelectionColor = Color.DarkGreen;
                    rtbBitDiff.SelectionFont = new Font("Consolas", 9.5F, FontStyle.Regular);
                }
                rtbBitDiff.AppendText(bin1[i].ToString());
            }
            rtbBitDiff.AppendText("\n💡 Kết luận: Dù chỉ thay đổi 1 bit đầu vào, hàm SHA-256 làm đảo lật ~50% số bit đầu ra ngẫu nhiên (Avalanche Effect).");
        }
        #endregion

        #region TAB 6: CHỮ KÝ SỐ & CƠ CHẾ RSASSA-PSS (Yêu cầu 9)
        private TabPage BuildTab6DigitalSignature()
        {
            TabPage tab = new TabPage("✍️ 6. Chữ Ký Số & PSS");
            tab.BackColor = Color.FromArgb(252, 250, 255);

            // Phần 1: Ký và Xác Thực Tiêu Chuẩn
            CuteCard cardSign = new CuteCard
            {
                Location = new Point(14, 10),
                Size = new Size(1174, 195),
                CardBackground = Color.White
            };

            Label lblSignT = new Label
            {
                Text = "✍️ Phần 1: Ký Số và Xác Thực Chữ Ký (Digital Signature Standard):",
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(106, 27, 154),
                Location = new Point(14, 8),
                AutoSize = true
            };

            txtSignInput = new TextBox
            {
                Location = new Point(14, 32),
                Size = new Size(560, 42),
                Multiline = true,
                Font = new Font("Consolas", 9.5F),
                Text = "Hop dong mua ban - Nguyen Thi Ngoc Linh - So tien 100.000.000 VND"
            };

            CuteButton btnSign = new CuteButton
            {
                Text = "✍️ Ký Số (Sign Data)",
                Size = new Size(175, 38),
                Location = new Point(585, 32),
                NormalColor = Color.FromArgb(106, 27, 154),
                HoverColor = Color.FromArgb(74, 20, 140)
            };
            btnSign.Click += btnSign_Click;

            CuteButton btnVerify = new CuteButton
            {
                Text = "🔍 Xác Thực (Verify)",
                Size = new Size(175, 38),
                Location = new Point(770, 32),
                NormalColor = Color.FromArgb(46, 125, 50),
                HoverColor = Color.FromArgb(36, 105, 40)
            };
            btnVerify.Click += btnVerify_Click;

            CuteButton btnTamper = new CuteButton
            {
                Text = "😈 Sửa Dữ Liệu (Tamper)",
                Size = new Size(190, 38),
                Location = new Point(955, 32),
                NormalColor = Color.FromArgb(198, 40, 40),
                HoverColor = Color.FromArgb(170, 30, 30)
            };
            btnTamper.Click += (s, e) =>
            {
                txtSignInput.Text += " [ĐÃ BỊ HACKER SỬA]";
                AppendLog("😈 Đã sửa dữ liệu để thử nghiệm kiểm tra tính toàn vẹn chữ ký.");
            };

            badgeSigStatus = new CuteBadge
            {
                Text = "Chờ ký số...",
                Size = new Size(560, 32),
                Location = new Point(585, 74)
            };

            Label lblSigOut = new Label
            {
                Text = "Chữ ký số tạo bởi Private Key (Base64):",
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Location = new Point(14, 80),
                AutoSize = true
            };
            txtSignatureOutput = new TextBox
            {
                Location = new Point(14, 102),
                Size = new Size(1146, 78),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 8.5F),
                ReadOnly = true,
                BackColor = Color.FromArgb(248, 248, 255)
            };

            cardSign.Controls.AddRange(new Control[] { lblSignT, txtSignInput, btnSign, btnVerify, btnTamper, badgeSigStatus, lblSigOut, txtSignatureOutput });
            tab.Controls.Add(cardSign);

            // Phần 2: Đề xuất & Thực nghiệm: Cùng dữ liệu + Cùng người ký -> Chữ ký khác nhau mỗi lần
            CuteCard cardPss = new CuteCard
            {
                Location = new Point(14, 212),
                Size = new Size(1174, 294),
                CardBackground = Color.White
            };

            Label lblPssT = new Label
            {
                Text = "💡 Phần 2: Đề Xuất Giải Pháp - Cùng 1 Dữ Liệu & Cùng 1 Người Ký -> Chữ Ký Khác Nhau Mỗi Lần:",
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                ForeColor = Color.FromArgb(198, 40, 40),
                Location = new Point(14, 8),
                AutoSize = true
            };

            CuteButton btnTestPss3Times = new CuteButton
            {
                Text = "🧪 Ký 3 Lần Bằng Chuẩn RSASSA-PSS (RFC 8017)",
                Size = new Size(380, 36),
                Location = new Point(14, 30),
                NormalColor = Color.FromArgb(198, 40, 40),
                HoverColor = Color.FromArgb(170, 30, 30)
            };
            btnTestPss3Times.Click += btnTestPss3Times_Click;

            CuteButton btnVerifyAll3 = new CuteButton
            {
                Text = "✅ Xác Thực Cả 3 Chữ Ký Bằng Public Key",
                Size = new Size(330, 36),
                Location = new Point(405, 30),
                NormalColor = Color.FromArgb(46, 125, 50),
                HoverColor = Color.FromArgb(36, 105, 40)
            };
            btnVerifyAll3.Click += btnVerifyAll3_Click;

            badgePssVerify = new CuteBadge
            {
                Text = "Chưa thử nghiệm PSS",
                Size = new Size(405, 36),
                Location = new Point(745, 30)
            };

            Label lblP1 = new Label { Text = "Chữ ký 1 (PSS Salt A):", Location = new Point(14, 72), AutoSize = true, Font = new Font("Segoe UI", 8F, FontStyle.Bold) };
            txtPssResult1 = new TextBox { Location = new Point(14, 92), Size = new Size(1146, 24), Font = new Font("Consolas", 8.5F), ReadOnly = true, BackColor = Color.FromArgb(255, 250, 250) };

            Label lblP2 = new Label { Text = "Chữ ký 2 (PSS Salt B):", Location = new Point(14, 118), AutoSize = true, Font = new Font("Segoe UI", 8F, FontStyle.Bold) };
            txtPssResult2 = new TextBox { Location = new Point(14, 138), Size = new Size(1146, 24), Font = new Font("Consolas", 8.5F), ReadOnly = true, BackColor = Color.FromArgb(250, 255, 250) };

            Label lblP3 = new Label { Text = "Chữ ký 3 (PSS Salt C):", Location = new Point(14, 164), AutoSize = true, Font = new Font("Segoe UI", 8F, FontStyle.Bold) };
            txtPssResult3 = new TextBox { Location = new Point(14, 184), Size = new Size(1146, 24), Font = new Font("Consolas", 8.5F), ReadOnly = true, BackColor = Color.FromArgb(250, 250, 255) };

            Label lblExplanation = new Label
            {
                Text = "📌 GIẢI THÍCH PHƯƠNG PHÁP: Áp dụng chuẩn RSASSA-PSS (RFC 8017). Mỗi lần ký, thuật toán sinh ra một chuỗi Muối ngẫu nhiên (Random Salt 32 bytes). Dù văn bản và khóa bí mật hoàn toàn giống nhau, chữ ký số sinh ra luôn khác biệt 100%, chống lại tấn công replay attack, nhưng Public Key vẫn xác thực hợp lệ tuyệt đối!",
                Font = new Font("Segoe UI", 8.25F, FontStyle.Italic),
                ForeColor = Color.FromArgb(80, 80, 90),
                Location = new Point(14, 216),
                Size = new Size(1146, 65)
            };

            cardPss.Controls.AddRange(new Control[] { lblPssT, btnTestPss3Times, btnVerifyAll3, badgePssVerify, lblP1, txtPssResult1, lblP2, txtPssResult2, lblP3, txtPssResult3, lblExplanation });
            tab.Controls.Add(cardPss);

            return tab;
        }

        private void btnSign_Click(object? sender, EventArgs e)
        {
            try
            {
                if (currentRsa == null)
                {
                    MessageBox.Show("Chưa có khóa RSA!", "Cảnh báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                byte[] data = Encoding.UTF8.GetBytes(txtSignInput.Text);
                byte[] signature = RsaHelper.SignData(currentRsa, data, false);
                string b64Sig = Convert.ToBase64String(signature);
                txtSignatureOutput.Text = b64Sig;

                badgeSigStatus.Text = "✅ Đã ký số thành công bằng Private Key!";
                badgeSigStatus.BadgeColor = Color.FromArgb(232, 245, 233);
                badgeSigStatus.ForeColor = Color.FromArgb(46, 125, 50);
                AppendLog($"✍️ Đã ký số văn bản ({data.Length} bytes) bằng RSA Private Key -> Chữ ký {signature.Length} bytes ({Convert.ToBase64String(signature.Take(16).ToArray())}...).");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi ký số: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                AppendLog($"❌ Lỗi ký số: {ex.Message}");
            }
        }

        private void btnVerify_Click(object? sender, EventArgs e)
        {
            try
            {
                if (currentRsa == null)
                {
                    MessageBox.Show("Chưa có khóa RSA!", "Cảnh báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(txtSignatureOutput.Text))
                {
                    MessageBox.Show("Chưa có chữ ký để xác thực!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                byte[] data = Encoding.UTF8.GetBytes(txtSignInput.Text);
                byte[] sig = Convert.FromBase64String(txtSignatureOutput.Text.Trim());

                bool valid = RsaHelper.VerifyData(currentRsa, data, sig, false);
                if (valid)
                {
                    badgeSigStatus.Text = "✅ CHỮ KÝ HỢP LỆ (Dữ liệu nguyên vẹn & đúng người ký)";
                    badgeSigStatus.BadgeColor = Color.FromArgb(232, 245, 233);
                    badgeSigStatus.ForeColor = Color.FromArgb(46, 125, 50);
                    AppendLog("✅ Xác thực chữ ký số THÀNH CÔNG: Dữ liệu nguyên vẹn, tính toàn vẹn và nguồn gốc được đảm bảo.");
                }
                else
                {
                    badgeSigStatus.Text = "❌ CHỮ KÝ KHÔNG HỢP LỆ (Dữ liệu đã bị sửa đổi hoặc giả mạo)";
                    badgeSigStatus.BadgeColor = Color.FromArgb(255, 235, 238);
                    badgeSigStatus.ForeColor = Color.FromArgb(198, 40, 40);
                    AppendLog("❌ CẢNH BÁO: Xác thực chữ ký THẤT BẠI. Dữ liệu đã bị can thiệp trái phép!");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi xác thực: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                AppendLog($"❌ Lỗi xác thực: {ex.Message}");
            }
        }

        private void btnTestPss3Times_Click(object? sender, EventArgs e)
        {
            try
            {
                if (currentRsa == null)
                {
                    MessageBox.Show("Chưa có khóa RSA!", "Cảnh báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                byte[] data = Encoding.UTF8.GetBytes(txtSignInput.Text);

                // Ký 3 lần bằng RSASSA-PSS (mỗi lần sinh salt ngẫu nhiên)
                byte[] sig1 = RsaHelper.SignData(currentRsa, data, true);
                byte[] sig2 = RsaHelper.SignData(currentRsa, data, true);
                byte[] sig3 = RsaHelper.SignData(currentRsa, data, true);

                txtPssResult1.Text = Convert.ToBase64String(sig1);
                txtPssResult2.Text = Convert.ToBase64String(sig2);
                txtPssResult3.Text = Convert.ToBase64String(sig3);

                badgePssVerify.Text = "Đã sinh 3 chữ ký PSS khác nhau hoàn toàn 100%!";
                badgePssVerify.BadgeColor = Color.FromArgb(237, 231, 246);
                badgePssVerify.ForeColor = Color.FromArgb(106, 27, 154);

                AppendLog("🧪 Thực nghiệm RSASSA-PSS: Đã sinh 3 chữ ký khác nhau hoàn toàn cho cùng 1 dữ liệu và cùng 1 private key.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi ký PSS: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                AppendLog($"❌ Lỗi ký PSS: {ex.Message}");
            }
        }

        private void btnVerifyAll3_Click(object? sender, EventArgs e)
        {
            try
            {
                if (currentRsa == null) return;
                if (string.IsNullOrEmpty(txtPssResult1.Text) || string.IsNullOrEmpty(txtPssResult2.Text) || string.IsNullOrEmpty(txtPssResult3.Text))
                {
                    MessageBox.Show("Hãy bấm 'Ký 3 Lần Bằng RSASSA-PSS' trước!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                byte[] data = Encoding.UTF8.GetBytes(txtSignInput.Text);
                bool ok1 = RsaHelper.VerifyData(currentRsa, data, Convert.FromBase64String(txtPssResult1.Text), true);
                bool ok2 = RsaHelper.VerifyData(currentRsa, data, Convert.FromBase64String(txtPssResult2.Text), true);
                bool ok3 = RsaHelper.VerifyData(currentRsa, data, Convert.FromBase64String(txtPssResult3.Text), true);

                if (ok1 && ok2 && ok3)
                {
                    badgePssVerify.Text = "🎉 CẢ 3 CHỮ KÝ ĐỀU HỢP LỆ VỚI CÙNG PUBLIC KEY!";
                    badgePssVerify.BadgeColor = Color.FromArgb(232, 245, 233);
                    badgePssVerify.ForeColor = Color.FromArgb(46, 125, 50);
                    AppendLog("🎉 Xác thực RSASSA-PSS thành công rực rỡ: Cả 3 chữ ký khác biệt đều được xác minh HỢP LỆ với cùng Public Key.");
                }
                else
                {
                    badgePssVerify.Text = "⚠️ Có chữ ký không hợp lệ!";
                    badgePssVerify.BadgeColor = Color.FromArgb(255, 235, 238);
                    badgePssVerify.ForeColor = Color.FromArgb(198, 40, 40);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi xác thực: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                AppendLog($"❌ Lỗi xác thực PSS: {ex.Message}");
            }
        }
        #endregion

        private void AppendLog(string message)
        {
            string line = $"[{DateTime.Now:HH:mm:ss}] {message}";
            if (txtGlobalLog.InvokeRequired)
            {
                txtGlobalLog.Invoke(new Action(() =>
                {
                    txtGlobalLog.AppendText(line + Environment.NewLine);
                }));
            }
            else
            {
                txtGlobalLog.AppendText(line + Environment.NewLine);
            }
        }

        public void AutoCaptureTabs(string imagesDir)
        {
            Directory.CreateDirectory(imagesDir);

            // Tab 1: Sinh & xuất khóa
            tabMain.SelectedIndex = 0;
            Application.DoEvents();
            CaptureForm(Path.Combine(imagesDir, "tab1_keygen.png"));

            // Tab 2: Phân tích PEM
            tabMain.SelectedIndex = 1;
            Application.DoEvents();
            CaptureForm(Path.Combine(imagesDir, "tab2_asn1_pem.png"));

            // Tab 3: Mã hóa và Giải mã
            tabMain.SelectedIndex = 2;
            txtPlainText.Text = "FdK0zE8oO6R0KMUre/oTHYO+5tw38YtHETCarPgtRW8=";
            btnEncrypt_Click(this, EventArgs.Empty);
            btnDecrypt_Click(this, EventArgs.Empty);
            Application.DoEvents();
            CaptureForm(Path.Combine(imagesDir, "tab3_encrypt_decrypt.png"));

            // Tab 4: Benchmark
            tabMain.SelectedIndex = 3;
            Application.DoEvents();
            if (currentRsa != null)
            {
                var res = RsaHelper.RunBenchmark(currentRsa, 500);
                lblPubOps.Text = $"{res.PublicOpsPerSec:F1} ops/s";
                lblPrivOps.Text = $"{res.PrivateOpsPerSec:F1} ops/s";
                lblSpeedRatio.Text = $"Public nhanh hơn: {res.SpeedRatio:F1}x";
                txtBenchmarkReport.Text = res.GetDetailedReport();
                prgBenchmark.Value = 100;
            }
            Application.DoEvents();
            CaptureForm(Path.Combine(imagesDir, "tab4_benchmark.png"));

            // Tab 5: SHA-256 & Avalanche
            tabMain.SelectedIndex = 4;
            txtShaInput.Text = "Nguyen Thi Ngoc Linh - K59KTP.K01";
            byte[] b0 = Encoding.UTF8.GetBytes(txtShaInput.Text);
            previousHash = RsaHelper.ComputeSha256(b0);
            previousText = txtShaInput.Text;
            txtPrevHashHex.Text = BitConverter.ToString(previousHash).Replace("-", "").ToLower();
            Application.DoEvents();
            txtShaInput.Text = "nguyen Thi Ngoc Linh - K59KTP.K01";
            Application.DoEvents();
            CaptureForm(Path.Combine(imagesDir, "tab5_avalanche_sha256.png"));

            // Tab 6: Chữ ký số & PSS
            tabMain.SelectedIndex = 5;
            btnSign_Click(this, EventArgs.Empty);
            btnTestPss3Times_Click(this, EventArgs.Empty);
            btnVerifyAll3_Click(this, EventArgs.Empty);
            Application.DoEvents();
            CaptureForm(Path.Combine(imagesDir, "tab6_signature_pss.png"));
        }

        private void CaptureForm(string filePath)
        {
            this.BringToFront();
            Application.DoEvents();
            System.Threading.Thread.Sleep(150);
            try
            {
                using (Bitmap bmp = new Bitmap(this.Bounds.Width, this.Bounds.Height))
                {
                    using (Graphics g = Graphics.FromImage(bmp))
                    {
                        g.CopyFromScreen(this.Location, Point.Empty, this.Bounds.Size);
                    }
                    bmp.Save(filePath, System.Drawing.Imaging.ImageFormat.Png);
                }
            }
            catch
            {
                using (Bitmap bmp = new Bitmap(this.Width, this.Height))
                {
                    this.DrawToBitmap(bmp, new Rectangle(0, 0, this.Width, this.Height));
                    bmp.Save(filePath, System.Drawing.Imaging.ImageFormat.Png);
                }
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                currentRsa?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
