#nullable enable
using System;
using System.Collections.Concurrent;
using System.Configuration;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace RavenAntivirusResearch.Utils
{
    public interface ILogger
    {
        void LogInfo(string message);
        void LogDebug(string message);
        void LogWarning(string message);
        void LogError(string message, Exception? ex = null);
    }

    public enum LogLevel
    {
        Debug,
        Info,
        Warning,
        Error
    }

    public class Logger : ILogger, IDisposable
    {
        // FIX: Not readonly because RotateLog reassigns it.
        private StreamWriter _writer;
        private readonly BlockingCollection<string> _queue = new BlockingCollection<string>(4096);
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly Task _worker;
        private readonly LogLevel _minimumLevel;
        private readonly string _filePath;
        private readonly long _maxFileSizeBytes;
        private readonly object _rotateLock = new object();
        private bool _disposed;

        private const long DefaultMaxFileSize = 10 * 1024 * 1024; // 10 MB

        public Logger(string logFilePath, LogLevel? minimumLevel = null, long maxFileSizeBytes = DefaultMaxFileSize)
        {
            _filePath = Path.GetFullPath(logFilePath);
            _maxFileSizeBytes = maxFileSizeBytes;

            Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);

            if (minimumLevel.HasValue)
            {
                _minimumLevel = minimumLevel.Value;
            }
            else
            {
                string configLevel = ConfigurationManager.AppSettings["LogLevel"] ?? "Info";
                if (!Enum.TryParse(configLevel, true, out _minimumLevel))
                    _minimumLevel = LogLevel.Info;
            }

            // FIX: Open with FileShare.ReadWrite so external readers (e.g. log viewer) don't conflict.
            FileStream fs = new FileStream(_filePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            _writer = new StreamWriter(fs) { AutoFlush = false };

            _worker = Task.Run(() => ProcessQueue());
        }

        public void LogInfo(string message) => Enqueue(LogLevel.Info, message);
        public void LogDebug(string message) => Enqueue(LogLevel.Debug, message);
        public void LogWarning(string message) => Enqueue(LogLevel.Warning, message);

        public void LogError(string message, Exception? ex = null)
        {
            string full = ex != null ? $"{message} | Exception: {ex}" : message;
            Enqueue(LogLevel.Error, full);
        }

        private void Enqueue(LogLevel level, string message)
        {
            if (level < _minimumLevel) return;
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            string line = $"{timestamp} [{level}] {message}";

            // Non-blocking add; drop message if queue is full to avoid memory blowout.
            if (!_queue.TryAdd(line))
            {
                try { WriteImmediate(line); } catch { }
            }
        }

        // FIX: Catch OperationCanceledException explicitly so shutdown does not silently
        //      crash the worker task (this was causing the QuickWatch exception in pic1).
        private void ProcessQueue()
        {
            try
            {
                foreach (string line in _queue.GetConsumingEnumerable(_cts.Token))
                {
                    WriteImmediate(line);
                }
            }
            catch (OperationCanceledException)
            {
                // Expected during Dispose — drain whatever is left in the queue.
                while (_queue.TryTake(out string? remaining))
                {
                    try { WriteImmediate(remaining); } catch { }
                }
            }
        }

        private void WriteImmediate(string line)
        {
            lock (_rotateLock)
            {
                try
                {
                    if (_writer.BaseStream.Length > _maxFileSizeBytes)
                        RotateLog();
                    _writer.WriteLine(line);
                    _writer.Flush();
                }
                catch (ObjectDisposedException) { }
                catch (Exception) { /* swallow write errors to keep logger alive */ }
            }
        }

        private void RotateLog()
        {
            try
            {
                _writer.Flush();
                _writer.Close();
                _writer.Dispose();

                string backup = _filePath + ".old";
                if (File.Exists(backup))
                    File.Delete(backup);
                File.Move(_filePath, backup);

                // FIX: Reopen with FileShare.ReadWrite consistent with the constructor.
                FileStream fs = new FileStream(_filePath, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite);
                _writer = new StreamWriter(fs) { AutoFlush = false };
            }
            catch { /* if rotation fails, continue logging to the existing file */ }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            _cts.Cancel();
            _queue.CompleteAdding();

            try { _worker.Wait(TimeSpan.FromSeconds(3)); } catch { }

            lock (_rotateLock)
            {
                try { _writer?.Dispose(); } catch { }
            }

            _cts.Dispose();
            _queue.Dispose();
        }
    }
}