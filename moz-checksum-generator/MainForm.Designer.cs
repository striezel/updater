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
            this.gbProduct = new System.Windows.Forms.GroupBox();
            this.rbFirefoxAurora = new System.Windows.Forms.RadioButton();
            this.rbSeaMonkey = new System.Windows.Forms.RadioButton();
            this.lblVersion = new System.Windows.Forms.Label();
            this.btnChecksums = new System.Windows.Forms.Button();
            this.rbThunderbird = new System.Windows.Forms.RadioButton();
            this.rbFirefoxESR = new System.Windows.Forms.RadioButton();
            this.rbFirefoxRelease = new System.Windows.Forms.RadioButton();
            this.gbChecksums = new System.Windows.Forms.GroupBox();
            this.splitContainer1 = new System.Windows.Forms.SplitContainer();
            this.rtbBit32 = new System.Windows.Forms.RichTextBox();
            this.lblBit32 = new System.Windows.Forms.Label();
            this.rtbBit64 = new System.Windows.Forms.RichTextBox();
            this.lblBit64 = new System.Windows.Forms.Label();
            this.gbProduct.SuspendLayout();
            this.gbChecksums.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).BeginInit();
            this.splitContainer1.Panel1.SuspendLayout();
            this.splitContainer1.Panel2.SuspendLayout();
            this.splitContainer1.SuspendLayout();
            this.SuspendLayout();
            // 
            // gbProduct
            // 
            this.gbProduct.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.gbProduct.Controls.Add(this.rbFirefoxAurora);
            this.gbProduct.Controls.Add(this.rbSeaMonkey);
            this.gbProduct.Controls.Add(this.lblVersion);
            this.gbProduct.Controls.Add(this.btnChecksums);
            this.gbProduct.Controls.Add(this.rbThunderbird);
            this.gbProduct.Controls.Add(this.rbFirefoxESR);
            this.gbProduct.Controls.Add(this.rbFirefoxRelease);
            this.gbProduct.Location = new System.Drawing.Point(12, 12);
            this.gbProduct.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.gbProduct.Name = "gbProduct";
            this.gbProduct.Padding = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.gbProduct.Size = new System.Drawing.Size(677, 146);
            this.gbProduct.TabIndex = 1;
            this.gbProduct.TabStop = false;
            this.gbProduct.Text = "Product";
            // 
            // rbFirefoxAurora
            // 
            this.rbFirefoxAurora.AutoSize = true;
            this.rbFirefoxAurora.Location = new System.Drawing.Point(6, 44);
            this.rbFirefoxAurora.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.rbFirefoxAurora.Name = "rbFirefoxAurora";
            this.rbFirefoxAurora.Size = new System.Drawing.Size(98, 19);
            this.rbFirefoxAurora.TabIndex = 6;
            this.rbFirefoxAurora.Text = "firefox-aurora";
            this.rbFirefoxAurora.UseVisualStyleBackColor = true;
            // 
            // rbSeaMonkey
            // 
            this.rbSeaMonkey.AutoSize = true;
            this.rbSeaMonkey.Location = new System.Drawing.Point(6, 119);
            this.rbSeaMonkey.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.rbSeaMonkey.Name = "rbSeaMonkey";
            this.rbSeaMonkey.Size = new System.Drawing.Size(85, 19);
            this.rbSeaMonkey.TabIndex = 5;
            this.rbSeaMonkey.Text = "seamonkey";
            this.rbSeaMonkey.UseVisualStyleBackColor = true;
            this.rbSeaMonkey.CheckedChanged += new System.EventHandler(this.rbFirefoxRelease_CheckedChanged);
            // 
            // lblVersion
            // 
            this.lblVersion.AutoSize = true;
            this.lblVersion.Location = new System.Drawing.Point(273, 44);
            this.lblVersion.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblVersion.Name = "lblVersion";
            this.lblVersion.Size = new System.Drawing.Size(0, 15);
            this.lblVersion.TabIndex = 4;
            // 
            // btnChecksums
            // 
            this.btnChecksums.Location = new System.Drawing.Point(143, 39);
            this.btnChecksums.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.btnChecksums.Name = "btnChecksums";
            this.btnChecksums.Size = new System.Drawing.Size(124, 23);
            this.btnChecksums.TabIndex = 3;
            this.btnChecksums.Text = "Get checksums";
            this.btnChecksums.UseVisualStyleBackColor = true;
            this.btnChecksums.Click += new System.EventHandler(this.btnChecksums_Click);
            // 
            // rbThunderbird
            // 
            this.rbThunderbird.AutoSize = true;
            this.rbThunderbird.Location = new System.Drawing.Point(6, 94);
            this.rbThunderbird.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.rbThunderbird.Name = "rbThunderbird";
            this.rbThunderbird.Size = new System.Drawing.Size(88, 19);
            this.rbThunderbird.TabIndex = 2;
            this.rbThunderbird.Text = "thunderbird";
            this.rbThunderbird.UseVisualStyleBackColor = true;
            this.rbThunderbird.CheckedChanged += new System.EventHandler(this.rbFirefoxRelease_CheckedChanged);
            // 
            // rbFirefoxESR
            // 
            this.rbFirefoxESR.AutoSize = true;
            this.rbFirefoxESR.Location = new System.Drawing.Point(6, 69);
            this.rbFirefoxESR.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.rbFirefoxESR.Name = "rbFirefoxESR";
            this.rbFirefoxESR.Size = new System.Drawing.Size(79, 19);
            this.rbFirefoxESR.TabIndex = 1;
            this.rbFirefoxESR.Text = "firefox-esr";
            this.rbFirefoxESR.UseVisualStyleBackColor = true;
            this.rbFirefoxESR.CheckedChanged += new System.EventHandler(this.rbFirefoxRelease_CheckedChanged);
            // 
            // rbFirefoxRelease
            // 
            this.rbFirefoxRelease.AutoSize = true;
            this.rbFirefoxRelease.Checked = true;
            this.rbFirefoxRelease.Location = new System.Drawing.Point(6, 19);
            this.rbFirefoxRelease.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.rbFirefoxRelease.Name = "rbFirefoxRelease";
            this.rbFirefoxRelease.Size = new System.Drawing.Size(100, 19);
            this.rbFirefoxRelease.TabIndex = 0;
            this.rbFirefoxRelease.TabStop = true;
            this.rbFirefoxRelease.Text = "firefox-release";
            this.rbFirefoxRelease.UseVisualStyleBackColor = true;
            this.rbFirefoxRelease.CheckedChanged += new System.EventHandler(this.rbFirefoxRelease_CheckedChanged);
            // 
            // gbChecksums
            // 
            this.gbChecksums.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.gbChecksums.Controls.Add(this.splitContainer1);
            this.gbChecksums.Location = new System.Drawing.Point(12, 164);
            this.gbChecksums.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.gbChecksums.Name = "gbChecksums";
            this.gbChecksums.Padding = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.gbChecksums.Size = new System.Drawing.Size(677, 209);
            this.gbChecksums.TabIndex = 2;
            this.gbChecksums.TabStop = false;
            this.gbChecksums.Text = "Checksums";
            // 
            // splitContainer1
            // 
            this.splitContainer1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.splitContainer1.Location = new System.Drawing.Point(4, 19);
            this.splitContainer1.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.splitContainer1.Name = "splitContainer1";
            // 
            // splitContainer1.Panel1
            // 
            this.splitContainer1.Panel1.Controls.Add(this.rtbBit32);
            this.splitContainer1.Panel1.Controls.Add(this.lblBit32);
            this.splitContainer1.Panel1MinSize = 300;
            // 
            // splitContainer1.Panel2
            // 
            this.splitContainer1.Panel2.Controls.Add(this.rtbBit64);
            this.splitContainer1.Panel2.Controls.Add(this.lblBit64);
            this.splitContainer1.Panel2MinSize = 300;
            this.splitContainer1.Size = new System.Drawing.Size(669, 187);
            this.splitContainer1.SplitterDistance = 300;
            this.splitContainer1.SplitterWidth = 5;
            this.splitContainer1.TabIndex = 0;
            // 
            // rtbBit32
            // 
            this.rtbBit32.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.rtbBit32.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.rtbBit32.Location = new System.Drawing.Point(3, 18);
            this.rtbBit32.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.rtbBit32.Name = "rtbBit32";
            this.rtbBit32.ReadOnly = true;
            this.rtbBit32.Size = new System.Drawing.Size(292, 147);
            this.rtbBit32.TabIndex = 1;
            this.rtbBit32.Text = "";
            // 
            // lblBit32
            // 
            this.lblBit32.AutoSize = true;
            this.lblBit32.Location = new System.Drawing.Point(4, 0);
            this.lblBit32.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblBit32.Name = "lblBit32";
            this.lblBit32.Size = new System.Drawing.Size(39, 15);
            this.lblBit32.TabIndex = 0;
            this.lblBit32.Text = "32 bit:";
            // 
            // rtbBit64
            // 
            this.rtbBit64.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.rtbBit64.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.rtbBit64.Location = new System.Drawing.Point(6, 18);
            this.rtbBit64.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.rtbBit64.Name = "rtbBit64";
            this.rtbBit64.ReadOnly = true;
            this.rtbBit64.Size = new System.Drawing.Size(353, 147);
            this.rtbBit64.TabIndex = 1;
            this.rtbBit64.Text = "";
            // 
            // lblBit64
            // 
            this.lblBit64.AutoSize = true;
            this.lblBit64.Location = new System.Drawing.Point(4, 0);
            this.lblBit64.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblBit64.Name = "lblBit64";
            this.lblBit64.Size = new System.Drawing.Size(39, 15);
            this.lblBit64.TabIndex = 0;
            this.lblBit64.Text = "64 bit:";
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(701, 379);
            this.Controls.Add(this.gbChecksums);
            this.Controls.Add(this.gbProduct);
            this.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.MinimumSize = new System.Drawing.Size(600, 300);
            this.Name = "MainForm";
            this.Text = "moz-checksum-generator";
            this.gbProduct.ResumeLayout(false);
            this.gbProduct.PerformLayout();
            this.gbChecksums.ResumeLayout(false);
            this.splitContainer1.Panel1.ResumeLayout(false);
            this.splitContainer1.Panel1.PerformLayout();
            this.splitContainer1.Panel2.ResumeLayout(false);
            this.splitContainer1.Panel2.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).EndInit();
            this.splitContainer1.ResumeLayout(false);
            this.ResumeLayout(false);

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

