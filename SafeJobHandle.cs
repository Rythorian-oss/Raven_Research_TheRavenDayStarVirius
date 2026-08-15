using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RavenAntivirusResearch.Native
{
    /// <summary>
    /// Safe handle wrapper for a Windows Job Object.
    /// Closing this handle terminates all processes assigned to the job
    /// when JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE is set.
    /// </summary>
    public sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeJobHandle(IntPtr handle, bool ownsHandle)
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