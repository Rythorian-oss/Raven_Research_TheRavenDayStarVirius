using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace RavenAntivirusResearch.Native
{
    /// <summary>
    /// Safe handle wrapper for a Windows thread handle.
    /// </summary>
    public sealed class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeThreadHandle(IntPtr handle, bool ownsHandle)
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