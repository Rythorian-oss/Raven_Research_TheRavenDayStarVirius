using System;
using RavenAntivirusResearch.Native;

namespace RavenAntivirusResearch.Core
{
    public interface IJobObjectUtility
    {
        SafeJobHandle CreateJobObject(string name);
        void SetJobLimits(SafeJobHandle job, int timeoutMs);
        bool AssignProcessToJob(SafeJobHandle job, IntPtr processHandle);
    }
}
