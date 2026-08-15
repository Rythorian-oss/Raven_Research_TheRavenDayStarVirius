using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RavenAntivirusResearch.Native
{
    /// <summary>
    /// Safe handle wrapper for a Windows process handle.
    ///
    /// FIX (errors CS0104 / CS1061): SandboxEngine.cs previously imported
    /// "using Microsoft.Win32.SafeHandles;" which caused an ambiguous reference
    /// between this type and Microsoft.Win32.SafeHandles.SafeProcessHandle.
    /// That using directive has been removed from SandboxEngine.cs so this
    /// project-local type resolves unambiguously everywhere.
    /// </summary>
    public sealed class SafeProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeProcessHandle(IntPtr handle, bool ownsHandle)
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