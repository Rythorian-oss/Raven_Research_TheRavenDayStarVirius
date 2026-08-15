#nullable enable
using RavenAntivirusResearch.Core;
using RavenAntivirusResearch.Native;
using RavenAntivirusResearch.Utils;
using System;
using System.Configuration;
using System.Drawing;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RavenAntivirusResearch
{
    public partial class Form1 : Form
    {
        private readonly ILogger _logger;
        private readonly SandboxEngine _sandboxEngine;
        private EtwMonitor? _etwMonitor;

        // FIX: Store the active job handle so Stop can actually kill the process.
        private SafeJobHandle? _activeJobHandle;
        private int _activePid;
        private bool _isRunning;
        private bool _disposed;

        private const int MaxLogLines = 2000;

        public Form1()
        {
            InitializeComponent();

            _logger = new Logger("RavenAntivirusResearch.log");

            var jobUtility = new JobObjectUtility();
            var tokenUtility = new TokenUtility(_logger);
            var injector = new RavenInjector(_logger);
            _sandboxEngine = new SandboxEngine(_logger, jobUtility, tokenUtility, injector);

            // Wire logger output to the UI log box.
            AppendLog("Raven Antivirus Research ready.", Color.DarkGreen);

            // Reflect initial button states.
            UpdateButtonStates(sandboxRunning: false, etwRunning: false);
        }

        // ----------------------------------------------------------------
        // Sandbox
        // ----------------------------------------------------------------

        private async void btnRunSandbox_Click(object sender, EventArgs e)
        {
            if (_isRunning)
            {
                MessageBox.Show("A sandbox is already running.", "Info",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string exePath = txtTargetPath.Text.Trim();
            string payloadPath = txtPayloadPath.Text.Trim();

            if (!File.Exists(exePath))
            {
                AppendLog($"Executable not found: {exePath}", Color.DarkRed);
                _logger.LogError($"Executable not found: {exePath}");
                return;
            }

            // Payload is optional; pass an empty array if not specified.
            byte[] payload = Array.Empty<byte>();
            if (!string.IsNullOrWhiteSpace(payloadPath))
            {
                if (!File.Exists(payloadPath))
                {
                    AppendLog($"Payload file not found: {payloadPath}", Color.DarkRed);
                    _logger.LogError($"Payload not found: {payloadPath}");
                    return;
                }
                payload = File.ReadAllBytes(payloadPath);
            }

            int timeoutMs = (int)nudTimeout.Value;

            _isRunning = true;
            UpdateButtonStates(sandboxRunning: true, etwRunning: false);
            lblStatus.Text = "Launching sandbox...";

            try
            {
                SandboxResult result = await Task.Run(() =>
                    _sandboxEngine.RunSandboxed(exePath, "", timeoutMs, payload));

                if (result.Success)
                {
                    // FIX: Store the job handle so Stop can dispose it (kills the process).
                    _activeJobHandle?.Dispose();
                    _activeJobHandle = result.JobHandle;
                    _activePid = result.ProcessId;

                    string msg = $"Sandbox started (PID {result.ProcessId}).";
                    AppendLog(msg, Color.DarkGreen);
                    _logger.LogInfo(msg);
                    lblStatus.Text = $"Running — PID {result.ProcessId}";

                    // FIX: Enable ETW button now that we have a live PID.
                    UpdateButtonStates(sandboxRunning: true, etwRunning: false);
                }
                else
                {
                    string msg = $"Sandbox failed: {result.ErrorMessage}";
                    AppendLog(msg, Color.DarkRed);
                    _logger.LogError(msg);
                    lblStatus.Text = "Sandbox failed.";
                    _isRunning = false;
                    UpdateButtonStates(sandboxRunning: false, etwRunning: false);
                }
            }
            catch (Exception ex)
            {
                AppendLog($"Exception: {ex.Message}", Color.DarkRed);
                _logger.LogError("Sandbox error", ex);
                lblStatus.Text = "Error — see log.";
                _isRunning = false;
                UpdateButtonStates(sandboxRunning: false, etwRunning: false);
            }
        }

        private void StopSandbox()
        {
            // Stop ETW first so it doesn't reference a dead PID.
            if (_etwMonitor != null)
            {
                _etwMonitor.Stop();
                _etwMonitor.Dispose();
                _etwMonitor = null;
            }

            // FIX: Dispose the job handle — KILL_ON_JOB_CLOSE terminates the process.
            _activeJobHandle?.Dispose();
            _activeJobHandle = null;
            _activePid = 0;
            _isRunning = false;

            AppendLog("Sandbox stopped.", Color.DarkOrange);
            _logger.LogInfo("Sandbox stopped by user.");
            lblStatus.Text = "Stopped.";

            UpdateButtonStates(sandboxRunning: false, etwRunning: false);
        }

        // ----------------------------------------------------------------
        // ETW
        // ----------------------------------------------------------------

        // FIX: Replaced missing btnStartEtw_Click / btnStopEtw_Click handlers.

        private void btnStartEtw_Click(object sender, EventArgs e)
        {
            // Respect App.config setting to enable/disable ETW monitoring globally.
            string? enabled = ConfigurationManager.AppSettings["EnableETWMonitoring"];
            if (!string.IsNullOrEmpty(enabled) && enabled.Equals("false", StringComparison.OrdinalIgnoreCase))
            {
                AppendLog("ETW monitoring is disabled by configuration.", Color.Gray);
                return;
            }
            // FIX: Guard — require an active sandbox session before starting ETW.
            if (!_isRunning || _activePid == 0)
            {
                MessageBox.Show("Initialize a sandbox session first.",
                    "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            if (_etwMonitor != null)
            {
                AppendLog("ETW is already running.", Color.Gray);
                return;
            }

            try
            {
                _etwMonitor = new EtwMonitor(_activePid, _logger);
                _etwMonitor.Start();
                AppendLog($"ETW monitoring started for PID {_activePid}.", Color.DarkBlue);
                UpdateButtonStates(sandboxRunning: true, etwRunning: true);
            }
            catch (Exception ex)
            {
                AppendLog($"ETW start failed: {ex.Message}", Color.DarkRed);
                _logger.LogError("ETW start failed", ex);
                _etwMonitor?.Dispose();
                _etwMonitor = null;
            }
        }

        private void btnStopEtw_Click(object sender, EventArgs e)
        {
            if (_etwMonitor == null)
            {
                AppendLog("ETW is not running.", Color.Gray);
                return;
            }
            _etwMonitor.Stop();
            _etwMonitor.Dispose();
            _etwMonitor = null;
            AppendLog("ETW monitoring stopped.", Color.DarkOrange);
            UpdateButtonStates(sandboxRunning: _isRunning, etwRunning: false);
        }

        // ----------------------------------------------------------------
        // Browse buttons
        // ----------------------------------------------------------------

        private void btnBrowseTarget_Click(object sender, EventArgs e)
        {
            using var dlg = new OpenFileDialog
            {
                Title = "Select Target Executable",
                Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
                FilterIndex = 1
            };
            if (dlg.ShowDialog() == DialogResult.OK)
                txtTargetPath.Text = dlg.FileName;
        }

        private void btnBrowsePayload_Click(object sender, EventArgs e)
        {
            using var dlg = new OpenFileDialog
            {
                Title = "Select Payload File",
                Filter = "All files (*.*)|*.*"
            };
            if (dlg.ShowDialog() == DialogResult.OK)
                txtPayloadPath.Text = dlg.FileName;
        }

        // ----------------------------------------------------------------
        // UI helpers
        // ----------------------------------------------------------------

        private void UpdateButtonStates(bool sandboxRunning, bool etwRunning)
        {
            // Run Sandbox enabled only when no sandbox is active.
            btnRunSandbox.Enabled = !sandboxRunning;

            // ETW Start requires an active sandbox and no ETW session.
            btnStartEtw.Enabled = sandboxRunning && !etwRunning;

            // ETW Stop requires an active ETW session.
            btnStopEtw.Enabled = etwRunning;
        }

        private void AppendLog(string message, Color color)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => AppendLog(message, color)));
                return;
            }

            // Trim old lines to prevent memory blowout.
            if (txtLog.Lines.Length > MaxLogLines)
            {
                int removeCount = txtLog.Lines.Length - MaxLogLines / 2;
                txtLog.Text = string.Join(Environment.NewLine,
                    txtLog.Lines, removeCount, txtLog.Lines.Length - removeCount);
            }

            txtLog.SelectionStart = txtLog.TextLength;
            txtLog.SelectionLength = 0;
            txtLog.SelectionColor = color;
            txtLog.AppendText($"{DateTime.Now:HH:mm:ss} - {message}{Environment.NewLine}");
            txtLog.ScrollToCaret();
        }

        // ----------------------------------------------------------------
        // Dispose
        // ----------------------------------------------------------------

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _etwMonitor?.Dispose();
                    _activeJobHandle?.Dispose();
                    _sandboxEngine?.Dispose();
                    (_logger as IDisposable)?.Dispose();
                    components?.Dispose();
                }
                _disposed = true;
            }
            base.Dispose(disposing);
        }
    }
}