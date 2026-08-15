#nullable enable
using RavenAntivirusResearch.Utils;
using System;
using System.Threading;
using System.Windows.Forms;

namespace RavenAntivirusResearch
{
    static class Program
    {
        // FIX: Logger promoted to static field so the exception handlers can reach it.
        private static ILogger? _logger;

        [STAThread]
        static void Main()
        {
            // AssemblyResolve fallback: some native/nuget combos cause System.Runtime.CompilerServices.Unsafe
            // binding failures at runtime. Intercept unresolved loads and force-load the local copy from the
            // application base directory so TraceEvent can find a compatible implementation.
            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
            {
                try
                {
                    var requested = new System.Reflection.AssemblyName(args.Name).Name;
                    if (!string.Equals(requested, "System.Runtime.CompilerServices.Unsafe", StringComparison.OrdinalIgnoreCase))
                        return null;

                    string candidate = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "System.Runtime.CompilerServices.Unsafe.dll");
                    if (!System.IO.File.Exists(candidate))
                    {
                        // Try variant with explicit versioned filename (if we copied one).
                        string alt = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "System.Runtime.CompilerServices.Unsafe.6.1.0.dll");
                        if (System.IO.File.Exists(alt)) candidate = alt;
                    }

                    if (System.IO.File.Exists(candidate))
                        return System.Reflection.Assembly.LoadFrom(candidate);
                }
                catch { }
                return null;
            };
            // FIX: Initialize logger before registering exception handlers so all
            //      unhandled exceptions are captured from the very start.
            _logger = new Logger("RavenAntivirusResearch.log");

            Application.ThreadException += OnThreadException;
            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            try
            {
                Application.Run(new Form1());
            }
            finally
            {
                // FIX: Ensure logger is fully flushed and file handle released on exit.
                (_logger as IDisposable)?.Dispose();
            }
        }

        private static void OnThreadException(object sender, ThreadExceptionEventArgs e)
        {
            _logger?.LogError("Unhandled UI thread exception", e.Exception);
            MessageBox.Show(
                $"An error occurred in the UI thread:\n{e.Exception.Message}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            // FIX: e.ExceptionObject may not be an Exception (handle both cases).
            string message = e.ExceptionObject?.ToString() ?? "Unknown fatal error";
            _logger?.LogError($"Fatal unhandled exception: {message}",
                e.ExceptionObject as Exception);
            MessageBox.Show(
                $"A fatal error occurred:\n{message}",
                "Fatal Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}