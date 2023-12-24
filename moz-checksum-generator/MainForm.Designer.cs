namespace moz_checksum_generator
{
    partial class MainForm
    {
        /// <summary>
        /// Erforderliche Designervariable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Verwendete Ressourcen bereinigen.
        /// </summary>
        /// <param name="disposing">True, wenn verwaltete Ressourcen gelöscht werden sollen; andernfalls False.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Vom Windows Form-Designer generierter Code

        /// <summary>
        /// Erforderliche Methode für die Designerunterstützung.
        /// Der Inhalt der Methode darf nicht mit dem Code-Editor geändert werden.
        /// </summary>
        private void InitializeComponent()
        {
            gbProduct = new System.Windows.Forms.GroupBox();
            rbFirefoxAurora = new System.Windows.Forms.RadioButton();
            rbSeaMonkey = new System.Windows.Forms.RadioButton();
            lblVersion = new System.Windows.Forms.Label();
            btnChecksums = new System.Windows.Forms.Button();
            rbThunderbird = new System.Windows.Forms.RadioButton();
            rbFirefoxESR = new System.Windows.Forms.RadioButton();
            rbFirefoxRelease = new System.Windows.Forms.RadioButton();
            gbChecksums = new System.Windows.Forms.GroupBox();
            splitContainer1 = new System.Windows.Forms.SplitContainer();
            rtbBit32 = new System.Windows.Forms.RichTextBox();
            lblBit32 = new System.Windows.Forms.Label();
            rtbBit64 = new System.Windows.Forms.RichTextBox();
            lblBit64 = new System.Windows.Forms.Label();
            gbProduct.SuspendLayout();
            gbChecksums.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)splitContainer1).BeginInit();
            splitContainer1.Panel1.SuspendLayout();
            splitContainer1.Panel2.SuspendLayout();
            splitContainer1.SuspendLayout();
            SuspendLayout();
            // 
            // gbProduct
            // 
            gbProduct.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            gbProduct.Controls.Add(rbFirefoxAurora);
            gbProduct.Controls.Add(rbSeaMonkey);
            gbProduct.Controls.Add(lblVersion);
            gbProduct.Controls.Add(btnChecksums);
            gbProduct.Controls.Add(rbThunderbird);
            gbProduct.Controls.Add(rbFirefoxESR);
            gbProduct.Controls.Add(rbFirefoxRelease);
            gbProduct.Location = new System.Drawing.Point(12, 12);
            gbProduct.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            gbProduct.Name = "gbProduct";
            gbProduct.Padding = new System.Windows.Forms.Padding(4, 3, 4, 3);
            gbProduct.Size = new System.Drawing.Size(677, 146);
            gbProduct.TabIndex = 1;
            gbProduct.TabStop = false;
            gbProduct.Text = "Product";
            // 
            // rbFirefoxAurora
            // 
            rbFirefoxAurora.AutoSize = true;
            rbFirefoxAurora.Location = new System.Drawing.Point(6, 44);
            rbFirefoxAurora.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            rbFirefoxAurora.Name = "rbFirefoxAurora";
            rbFirefoxAurora.Size = new System.Drawing.Size(100, 19);
            rbFirefoxAurora.TabIndex = 6;
            rbFirefoxAurora.Text = "Firefox Aurora";
            rbFirefoxAurora.UseVisualStyleBackColor = true;
            // 
            // rbSeaMonkey
            // 
            rbSeaMonkey.AutoSize = true;
            rbSeaMonkey.Location = new System.Drawing.Point(6, 119);
            rbSeaMonkey.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            rbSeaMonkey.Name = "rbSeaMonkey";
            rbSeaMonkey.Size = new System.Drawing.Size(86, 19);
            rbSeaMonkey.TabIndex = 5;
            rbSeaMonkey.Text = "SeaMonkey";
            rbSeaMonkey.UseVisualStyleBackColor = true;
            rbSeaMonkey.CheckedChanged += rbFirefoxRelease_CheckedChanged;
            // 
            // lblVersion
            // 
            lblVersion.AutoSize = true;
            lblVersion.Location = new System.Drawing.Point(273, 44);
            lblVersion.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            lblVersion.Name = "lblVersion";
            lblVersion.Size = new System.Drawing.Size(0, 15);
            lblVersion.TabIndex = 4;
            // 
            // btnChecksums
            // 
            btnChecksums.Location = new System.Drawing.Point(143, 39);
            btnChecksums.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            btnChecksums.Name = "btnChecksums";
            btnChecksums.Size = new System.Drawing.Size(124, 23);
            btnChecksums.TabIndex = 3;
            btnChecksums.Text = "Get checksums";
            btnChecksums.UseVisualStyleBackColor = true;
            btnChecksums.Click += btnChecksums_Click;
            // 
            // rbThunderbird
            // 
            rbThunderbird.AutoSize = true;
            rbThunderbird.Location = new System.Drawing.Point(6, 94);
            rbThunderbird.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            rbThunderbird.Name = "rbThunderbird";
            rbThunderbird.Size = new System.Drawing.Size(90, 19);
            rbThunderbird.TabIndex = 2;
            rbThunderbird.Text = "Thunderbird";
            rbThunderbird.UseVisualStyleBackColor = true;
            rbThunderbird.CheckedChanged += rbFirefoxRelease_CheckedChanged;
            // 
            // rbFirefoxESR
            // 
            rbFirefoxESR.AutoSize = true;
            rbFirefoxESR.Location = new System.Drawing.Point(6, 69);
            rbFirefoxESR.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            rbFirefoxESR.Name = "rbFirefoxESR";
            rbFirefoxESR.Size = new System.Drawing.Size(83, 19);
            rbFirefoxESR.TabIndex = 1;
            rbFirefoxESR.Text = "Firefox ESR";
            rbFirefoxESR.UseVisualStyleBackColor = true;
            rbFirefoxESR.CheckedChanged += rbFirefoxRelease_CheckedChanged;
            // 
            // rbFirefoxRelease
            // 
            rbFirefoxRelease.AutoSize = true;
            rbFirefoxRelease.Checked = true;
            rbFirefoxRelease.Location = new System.Drawing.Point(6, 19);
            rbFirefoxRelease.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            rbFirefoxRelease.Name = "rbFirefoxRelease";
            rbFirefoxRelease.Size = new System.Drawing.Size(61, 19);
            rbFirefoxRelease.TabIndex = 0;
            rbFirefoxRelease.TabStop = true;
            rbFirefoxRelease.Text = "Firefox";
            rbFirefoxRelease.UseVisualStyleBackColor = true;
            rbFirefoxRelease.CheckedChanged += rbFirefoxRelease_CheckedChanged;
            // 
            // gbChecksums
            // 
            gbChecksums.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            gbChecksums.Controls.Add(splitContainer1);
            gbChecksums.Location = new System.Drawing.Point(12, 164);
            gbChecksums.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            gbChecksums.Name = "gbChecksums";
            gbChecksums.Padding = new System.Windows.Forms.Padding(4, 3, 4, 3);
            gbChecksums.Size = new System.Drawing.Size(677, 209);
            gbChecksums.TabIndex = 2;
            gbChecksums.TabStop = false;
            gbChecksums.Text = "Checksums";
            // 
            // splitContainer1
            // 
            splitContainer1.Dock = System.Windows.Forms.DockStyle.Fill;
            splitContainer1.Location = new System.Drawing.Point(4, 19);
            splitContainer1.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            splitContainer1.Name = "splitContainer1";
            // 
            // splitContainer1.Panel1
            // 
            splitContainer1.Panel1.Controls.Add(rtbBit32);
            splitContainer1.Panel1.Controls.Add(lblBit32);
            splitContainer1.Panel1MinSize = 300;
            // 
            // splitContainer1.Panel2
            // 
            splitContainer1.Panel2.Controls.Add(rtbBit64);
            splitContainer1.Panel2.Controls.Add(lblBit64);
            splitContainer1.Panel2MinSize = 300;
            splitContainer1.Size = new System.Drawing.Size(669, 187);
            splitContainer1.SplitterDistance = 300;
            splitContainer1.SplitterWidth = 5;
            splitContainer1.TabIndex = 0;
            // 
            // rtbBit32
            // 
            rtbBit32.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            rtbBit32.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            rtbBit32.Location = new System.Drawing.Point(3, 18);
            rtbBit32.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            rtbBit32.Name = "rtbBit32";
            rtbBit32.ReadOnly = true;
            rtbBit32.Size = new System.Drawing.Size(292, 147);
            rtbBit32.TabIndex = 1;
            rtbBit32.Text = "";
            // 
            // lblBit32
            // 
            lblBit32.AutoSize = true;
            lblBit32.Location = new System.Drawing.Point(4, 0);
            lblBit32.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            lblBit32.Name = "lblBit32";
            lblBit32.Size = new System.Drawing.Size(39, 15);
            lblBit32.TabIndex = 0;
            lblBit32.Text = "32 bit:";
            // 
            // rtbBit64
            // 
            rtbBit64.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            rtbBit64.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            rtbBit64.Location = new System.Drawing.Point(6, 18);
            rtbBit64.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            rtbBit64.Name = "rtbBit64";
            rtbBit64.ReadOnly = true;
            rtbBit64.Size = new System.Drawing.Size(352, 147);
            rtbBit64.TabIndex = 1;
            rtbBit64.Text = "";
            // 
            // lblBit64
            // 
            lblBit64.AutoSize = true;
            lblBit64.Location = new System.Drawing.Point(4, 0);
            lblBit64.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            lblBit64.Name = "lblBit64";
            lblBit64.Size = new System.Drawing.Size(39, 15);
            lblBit64.TabIndex = 0;
            lblBit64.Text = "64 bit:";
            // 
            // MainForm
            // 
            AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            ClientSize = new System.Drawing.Size(701, 379);
            Controls.Add(gbChecksums);
            Controls.Add(gbProduct);
            Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            MinimumSize = new System.Drawing.Size(600, 300);
            Name = "MainForm";
            Text = "moz-checksum-generator";
            gbProduct.ResumeLayout(false);
            gbProduct.PerformLayout();
            gbChecksums.ResumeLayout(false);
            splitContainer1.Panel1.ResumeLayout(false);
            splitContainer1.Panel1.PerformLayout();
            splitContainer1.Panel2.ResumeLayout(false);
            splitContainer1.Panel2.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)splitContainer1).EndInit();
            splitContainer1.ResumeLayout(false);
            ResumeLayout(false);
        }

        #endregion

        private System.Windows.Forms.GroupBox gbProduct;
        private System.Windows.Forms.RadioButton rbThunderbird;
        private System.Windows.Forms.RadioButton rbFirefoxESR;
        private System.Windows.Forms.RadioButton rbFirefoxRelease;
        private System.Windows.Forms.GroupBox gbChecksums;
        private System.Windows.Forms.SplitContainer splitContainer1;
        private System.Windows.Forms.RichTextBox rtbBit32;
        private System.Windows.Forms.Label lblBit32;
        private System.Windows.Forms.RichTextBox rtbBit64;
        private System.Windows.Forms.Label lblBit64;
        private System.Windows.Forms.Button btnChecksums;
        private System.Windows.Forms.Label lblVersion;
        private System.Windows.Forms.RadioButton rbSeaMonkey;
        private System.Windows.Forms.RadioButton rbFirefoxAurora;
    }
}

