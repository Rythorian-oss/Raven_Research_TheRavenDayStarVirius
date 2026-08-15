using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using RavenAntivirusResearch.Native;

// FIX: IJobObjectUtility interface removed from this file.
// It now lives exclusively in IJobObjectUtility.cs.
// This file contains only the JobObjectManager class.

namespace RavenAntivirusResearch.Core
{
    public class JobObjectManager : IJobObjectUtility
    {
        public SafeJobHandle CreateJobObject(string name)
        {
            IntPtr h = NativeMethods.CreateJobObject(IntPtr.Zero, name);
            if (h == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed.");
            return new SafeJobHandle(h, true);
        }

        public void SetJobLimits(SafeJobHandle job, int timeoutMs)
        {
            var info = new NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags =
                NativeMethods.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            int length = Marshal.SizeOf<NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
            IntPtr pInfo = Marshal.AllocHGlobal(length);
            try
            {
                Marshal.StructureToPtr(info, pInfo, false);
                if (!NativeMethods.SetInformationJobObject(
                        job.DangerousGetHandle(),
                        NativeMethods.JobObjectInfoType.ExtendedLimitInformation,
                        pInfo, (uint)length))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(), "SetInformationJobObject failed.");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pInfo);
            }
        }

        public bool AssignProcessToJob(SafeJobHandle job, IntPtr processHandle)
        {
            return NativeMethods.AssignProcessToJobObject(
                job.DangerousGetHandle(), processHandle);
        }
    }
}