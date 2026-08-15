using System;
using RavenAntivirusResearch.Native;

namespace RavenAntivirusResearch.Core
{
    // FIX: Interface was declared in both JobObjectUtility.cs AND JobObjectManager.cs,
    // causing the "ambiguous call" errors. It now lives exclusively here.
    // Both classes below simply implement it — neither re-declares it.
    public interface IJobObjectUtility
    {
        SafeJobHandle CreateJobObject(string name);
        void SetJobLimits(SafeJobHandle job, int timeoutMs);
        bool AssignProcessToJob(SafeJobHandle job, IntPtr processHandle);
    }
}