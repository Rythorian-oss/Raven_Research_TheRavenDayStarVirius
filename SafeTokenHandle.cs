using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace RavenAntivirusResearch.Native
{
    /// <summary>
    /// Safe handle wrapper for a Windows access token.
    /// </summary>
    public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        // Parameterless constructor required for P/Invoke out-parameter marshalling
        // (e.g. OpenProcessToken, DuplicateTokenEx).
        public SafeTokenHandle()
            : base(true) { }

        public SafeTokenHandle(IntPtr handle, bool ownsHandle)
            : base(ownsHandle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return CloseHandle(handle);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr h);
    }
}