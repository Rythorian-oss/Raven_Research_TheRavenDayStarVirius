#nullable enable
using System;
using System.Runtime.InteropServices;

// NOTE: SafeJobHandle, SafeTokenHandle, SafeThreadHandle, SafeProcessHandle
//       are each declared in their own files in this namespace.
//       This file contains ONLY P/Invoke declarations, structs, enums, and constants.

namespace RavenAntivirusResearch.Native
{
    /// <summary>
    /// Centralised P/Invoke declarations for the Raven Antivirus Research tool.
    /// </summary>
    internal static class NativeMethods
    {
        // ----------------------------------------------------------------
        // Process creation flags
        // ----------------------------------------------------------------
        public const uint CREATE_SUSPENDED = 0x00000004;
        public const uint CREATE_NEW_CONSOLE = 0x00000010;
        public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;

        // ----------------------------------------------------------------
        // Token access rights
        // ----------------------------------------------------------------
        public const uint TOKEN_DUPLICATE = 0x0002;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const uint TOKEN_ADJUST_GROUPS = 0x0100;

        // ----------------------------------------------------------------
        // Job object limit flags
        // ----------------------------------------------------------------
        public const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;
        public const uint JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x0400;
        public const uint JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x0100;
        public const uint JOB_OBJECT_LIMIT_JOB_MEMORY = 0x0200;
        public const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x0008;

        // ----------------------------------------------------------------
        // PROC_THREAD_ATTRIBUTE constants
        // ----------------------------------------------------------------
        public const uint PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;
        public const ulong PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE = 0x01;
        public const ulong PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE = 0x04;
        public const ulong PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES = 0x100;

        // ----------------------------------------------------------------
        // GetLastError well-known codes
        // ----------------------------------------------------------------
        public const int ERROR_INSUFFICIENT_BUFFER = 122;

        // ----------------------------------------------------------------
        // Enums
        // ----------------------------------------------------------------
        public enum JobObjectInfoType
        {
            ExtendedLimitInformation = 9
        }

        // ----------------------------------------------------------------
        // Structures
        // ----------------------------------------------------------------

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint Control, Status, Tag, ErrorO, ErrorS, DataO, DataS;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;

            public FLOATING_SAVE_AREA(bool _)
            {
                Control = Status = Tag = ErrorO = ErrorS = DataO = DataS = 0;
                RegisterArea = new byte[80];
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT32
        {
            public uint ContextFlags;
            public uint Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            public FLOATING_SAVE_AREA FloatSave;
            public uint SegGs, SegFs, SegEs, SegDs;
            public uint Edi, Esi, Ebx, Edx, Ecx, Eax, Ebp, Eip;
            public uint SegCs, EFlags, Esp, SegSs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;

            public CONTEXT32(bool _)
            {
                ContextFlags = Dr0 = Dr1 = Dr2 = Dr3 = Dr6 = Dr7 = 0;
                FloatSave = new FLOATING_SAVE_AREA(true);
                SegGs = SegFs = SegEs = SegDs = 0;
                Edi = Esi = Ebx = Edx = Ecx = Eax = Ebp = Eip = 0;
                SegCs = EFlags = Esp = SegSs = 0;
                ExtendedRegisters = new byte[512];
            }
        }

        // ----------------------------------------------------------------
        // kernel32.dll — Job objects
        // ----------------------------------------------------------------

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetInformationJobObject(
            IntPtr hJob,
            JobObjectInfoType jobInfoType,
            IntPtr lpJobInfo,
            uint cbJobInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        // ----------------------------------------------------------------
        // kernel32.dll — Process attribute lists
        //
        // FIX: The first call to InitializeProcThreadAttributeList with
        //      lpAttributeList=NULL always returns FALSE with
        //      GetLastError()==ERROR_INSUFFICIENT_BUFFER (122).
        //      Callers MUST ignore that specific error on the first call.
        // ----------------------------------------------------------------

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr Attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

        [DllImport("kernel32.dll")]
        public static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        // ----------------------------------------------------------------
        // kernel32.dll — Memory / process
        // ----------------------------------------------------------------

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualFreeEx(
            IntPtr hProcess, IntPtr lpAddress, int dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process(IntPtr hProcess,
            [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        // ----------------------------------------------------------------
        // advapi32.dll — Tokens / process-as-user
        // ----------------------------------------------------------------

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle, uint DesiredAccess,
            out SafeTokenHandle TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateTokenEx(
            IntPtr hExistingToken, uint dwDesiredAccess,
            IntPtr lpTokenAttributes,
            int ImpersonationLevel, int TokenType,
            out SafeTokenHandle phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle, int TokenInformationClass,
            IntPtr TokenInformation, uint TokenInformationLength,
            out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetTokenInformation(
            IntPtr TokenHandle, int TokenInformationClass,
            IntPtr TokenInformation, uint TokenInformationLength);

        [DllImport("advapi32.dll")]
        public static extern uint GetLengthSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string? lpApplicationName,
            string? lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string? lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        // ----------------------------------------------------------------
        // ntdll.dll
        // ----------------------------------------------------------------

        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationProcess(
            IntPtr processHandle, int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength, out int returnLength);

        [DllImport("ntdll.dll")]
        public static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr baseAddress);
    }
}