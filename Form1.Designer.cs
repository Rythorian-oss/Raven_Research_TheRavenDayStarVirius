// FIX (error CS0111): Dispose(bool) was declared in BOTH Form1.cs and here.
// The Designer file must NOT override Dispose — that belongs exclusively in
// Form1.cs so the partial class has exactly one Dispose override.
// FIX (namespace): RavenAntivirusResearch (not RavenAntivirusResearch.UI).
// FIX (txtLog type): RichTextBox — required for SelectionColor in AppendLog.
namespace RavenAntivirusResearch
{
    partial class Form1
    {
        private System.ComponentModel.IContainer components = null;

        // Controls declared here; initialised in InitializeComponent.
        private System.Windows.Forms.TextBox txtTargetPath;
        private System.Windows.Forms.Button btnBrowseTarget;
        private System.Windows.Forms.TextBox txtPayloadPath;
        private System.Windows.Forms.Button btnBrowsePayload;
        private System.Windows.Forms.NumericUpDown nudTimeout;
        private System.Windows.Forms.Button btnRunSandbox;
        private System.Windows.Forms.Button btnStartEtw;
        private System.Windows.Forms.Button btnStopEtw;
        private System.Windows.Forms.Label lblStatus;
        private System.Windows.Forms.RichTextBox txtLog;   // RichTextBox for SelectionColor

        private void InitializeComponent()
        {
            this.txtTargetPath = new System.Windows.Forms.TextBox();
            this.btnBrowseTarget = new System.Windows.Forms.Button();
            this.txtPayloadPath = new System.Windows.Forms.TextBox();
            this.btnBrowsePayload = new System.Windows.Forms.Button();
            this.nudTimeout = new System.Windows.Forms.NumericUpDown();
            this.btnRunSandbox = new System.Windows.Forms.Button();
            this.btnStartEtw = new System.Windows.Forms.Button();
            this.btnStopEtw = new System.Windows.Forms.Button();
            this.lblStatus = new System.Windows.Forms.Label();
            this.txtLog = new System.Windows.Forms.RichTextBox();

            ((System.ComponentModel.ISupportInitialize)(this.nudTimeout)).BeginInit();
            this.SuspendLayout();

            // ---- txtTargetPath ----
            this.txtTargetPath.Location = new System.Drawing.Point(12, 12);
            this.txtTargetPath.Size = new System.Drawing.Size(490, 23);
            this.txtTargetPath.Text = @"C:\Windows\System32\notepad.exe";
            this.txtTargetPath.TabIndex = 0;

            // ---- btnBrowseTarget ----
            this.btnBrowseTarget.Location = new System.Drawing.Point(508, 10);
            this.btnBrowseTarget.Size = new System.Drawing.Size(75, 25);
            this.btnBrowseTarget.Text = "Browse";
            this.btnBrowseTarget.TabIndex = 1;
            this.btnBrowseTarget.Click += new System.EventHandler(this.btnBrowseTarget_Click);

            // ---- txtPayloadPath ----
            this.txtPayloadPath.Location = new System.Drawing.Point(12, 41);
            this.txtPayloadPath.Size = new System.Drawing.Size(490, 23);
            this.txtPayloadPath.TabIndex = 2;

            // ---- btnBrowsePayload ----
            this.btnBrowsePayload.Location = new System.Drawing.Point(508, 39);
            this.btnBrowsePayload.Size = new System.Drawing.Size(75, 25);
            this.btnBrowsePayload.Text = "Browse";
            this.btnBrowsePayload.TabIndex = 3;
            this.btnBrowsePayload.Click += new System.EventHandler(this.btnBrowsePayload_Click);

            // ---- nudTimeout ----
            this.nudTimeout.Location = new System.Drawing.Point(12, 72);
            this.nudTimeout.Size = new System.Drawing.Size(90, 23);
            this.nudTimeout.Minimum = new decimal(new int[] { 1000, 0, 0, 0 });
            this.nudTimeout.Maximum = new decimal(new int[] { 600000, 0, 0, 0 });
            this.nudTimeout.Value = new decimal(new int[] { 30000, 0, 0, 0 });
            this.nudTimeout.Increment = new decimal(new int[] { 1000, 0, 0, 0 });
            this.nudTimeout.TabIndex = 4;

            // ---- btnRunSandbox ----
            this.btnRunSandbox.Location = new System.Drawing.Point(108, 70);
            this.btnRunSandbox.Size = new System.Drawing.Size(105, 25);
            this.btnRunSandbox.Text = "Run Sandbox";
            this.btnRunSandbox.TabIndex = 5;
            this.btnRunSandbox.Click += new System.EventHandler(this.btnRunSandbox_Click);

            // ---- btnStartEtw ----
            this.btnStartEtw.Location = new System.Drawing.Point(219, 70);
            this.btnStartEtw.Size = new System.Drawing.Size(95, 25);
            this.btnStartEtw.Text = "Start ETW";
            this.btnStartEtw.Enabled = false;  // enabled only after sandbox starts
            this.btnStartEtw.TabIndex = 6;
            this.btnStartEtw.Click += new System.EventHandler(this.btnStartEtw_Click);

            // ---- btnStopEtw ----
            this.btnStopEtw.Location = new System.Drawing.Point(320, 70);
            this.btnStopEtw.Size = new System.Drawing.Size(95, 25);
            this.btnStopEtw.Text = "Stop ETW";
            this.btnStopEtw.Enabled = false;
            this.btnStopEtw.TabIndex = 7;
            this.btnStopEtw.Click += new System.EventHandler(this.btnStopEtw_Click);

            // ---- lblStatus ----
            this.lblStatus.Location = new System.Drawing.Point(12, 102);
            this.lblStatus.Size = new System.Drawing.Size(450, 18);
            this.lblStatus.Text = "Ready.";

            // ---- txtLog ----
            this.txtLog.Location = new System.Drawing.Point(12, 123);
            this.txtLog.Size = new System.Drawing.Size(590, 300);
            this.txtLog.Multiline = true;
            this.txtLog.ScrollBars = System.Windows.Forms.RichTextBoxScrollBars.Vertical;
            this.txtLog.ReadOnly = true;
            this.txtLog.Font = new System.Drawing.Font("Consolas", 8.5f);
            this.txtLog.TabIndex = 8;

            // ---- Form1 ----
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(614, 435);
            this.Text = "Raven Antivirus Research";
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;

            this.Controls.Add(this.txtTargetPath);
            this.Controls.Add(this.btnBrowseTarget);
            this.Controls.Add(this.txtPayloadPath);
            this.Controls.Add(this.btnBrowsePayload);
            this.Controls.Add(this.nudTimeout);
            this.Controls.Add(this.btnRunSandbox);
            this.Controls.Add(this.btnStartEtw);
            this.Controls.Add(this.btnStopEtw);
            this.Controls.Add(this.lblStatus);
            this.Controls.Add(this.txtLog);

            ((System.ComponentModel.ISupportInitialize)(this.nudTimeout)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();
        }
    }
}