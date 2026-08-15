using Microsoft.Win32.SafeHandles;
using RavenAntivirusResearch.Native;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using RavenAntivirusResearch.Utils;

// Make sure this matches your project's namespace
namespace RavenAntivirusResearch.Core
{
    public interface ITokenUtility
    {
        void AddDenyOnlySid(SafeHandle token, SecurityIdentifier sidToDeny);
        Native.SafeTokenHandle CreateRestrictedToken(bool blockNetwork = true);
    }

    public class TokenUtility : ITokenUtility
    {
        private readonly ILogger _logger;

        // --- CONSTANTS ---
        private const uint SE_GROUP_MANDATORY = 0x00000001;
        private const uint SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010;
        private const int TokenGroups = 2; // TokenGroups enum value for Get/SetTokenInformation

        // --- STRUCTURES ---
        [StructLayout(LayoutKind.Sequential)]
        internal struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct TOKEN_GROUPS
        {
            public uint GroupCount;
            // Note: In memory, this is immediately followed by an array of SID_AND_ATTRIBUTES
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct TOKEN_MANDATORY_LABEL
        {
            public SID_AND_ATTRIBUTES Label;
        }

        public TokenUtility(ILogger logger)
        {
            _logger = logger;
        }

        // Ensure you change SafeHandle to whatever specific handle type you are using (e.g., SafeTokenHandle)
        public void AddDenyOnlySid(SafeHandle token, SecurityIdentifier sidToDeny)
        {
            IntPtr pGroups = IntPtr.Zero;
            List<IntPtr> allocatedSids = new List<IntPtr>();
            IntPtr pNew = IntPtr.Zero;

            try
            {
                uint tokenInfoLength = 0;

                // 1. Get the required buffer size
                NativeMethods.GetTokenInformation(token.DangerousGetHandle(), TokenGroups, IntPtr.Zero, 0U, out tokenInfoLength);

                if (tokenInfoLength == 0)
                {
                    throw new Exception("Failed to get token information length.");
                }

                // 2. Allocate memory and retrieve the token groups
                pGroups = Marshal.AllocHGlobal((int)tokenInfoLength);
                if (!NativeMethods.GetTokenInformation(token.DangerousGetHandle(), TokenGroups, pGroups, tokenInfoLength, out tokenInfoLength))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }

                // 3. Read the GroupCount safely
                TOKEN_GROUPS groups = Marshal.PtrToStructure<TOKEN_GROUPS>(pGroups);
                uint groupCount = groups.GroupCount;

                // 4. Calculate offsets. TOKEN_GROUPS starts with a DWORD GroupCount,
                // so the header size is sizeof(uint) (4) regardless of architecture.
                int headerOffset = sizeof(uint);
                int sidAndAttrSize = Marshal.SizeOf<SID_AND_ATTRIBUTES>();
                IntPtr currentGroupPtr = IntPtr.Add(pGroups, headerOffset);

                // 5. Allocate new buffer for the modified groups
                // New size = Header + (Original Count + 1) * Size of SID_AND_ATTRIBUTES
                int newSize = headerOffset + (int)((groupCount + 1) * sidAndAttrSize);
                pNew = Marshal.AllocHGlobal(newSize);

                // Write the new group count (Original + 1) to the start of the new buffer
                Marshal.WriteInt32(pNew, (int)(groupCount + 1));
                IntPtr newGroupPtr = IntPtr.Add(pNew, headerOffset);

                // 6. Iterate through existing groups and copy them safely
                for (int i = 0; i < (int)groupCount; i++)
                {
                    var sidAndAttr = Marshal.PtrToStructure<SID_AND_ATTRIBUTES>(currentGroupPtr);

                    IntPtr writeSidPtr = IntPtr.Zero;
                    uint writeAttr = sidAndAttr.Attributes;

                    if (sidAndAttr.Sid != IntPtr.Zero)
                    {
                        // Copy the SID memory securely
                        uint sidLen = NativeMethods.GetLengthSid(sidAndAttr.Sid);
                        byte[] existingSidBytes = new byte[sidLen];
                        Marshal.Copy(sidAndAttr.Sid, existingSidBytes, 0, (int)sidLen);

                        IntPtr newSidPtr = Marshal.AllocHGlobal((int)sidLen);
                        allocatedSids.Add(newSidPtr);
                        Marshal.Copy(existingSidBytes, 0, newSidPtr, (int)sidLen);

                        writeSidPtr = newSidPtr;
                    }

                    // Always write a SID pointer (possibly zero) and attributes for each entry
                    Marshal.WriteIntPtr(newGroupPtr, writeSidPtr);
                    System.Runtime.InteropServices.Marshal.WriteInt32(IntPtr.Add(newGroupPtr, IntPtr.Size), (int)writeAttr);

                    // Advance pointers
                    currentGroupPtr = IntPtr.Add(currentGroupPtr, sidAndAttrSize);
                    newGroupPtr = IntPtr.Add(newGroupPtr, sidAndAttrSize);
                }

                // 7. Add the new Deny-Only SID to the end of the array
                byte[] newSidBytes = new byte[sidToDeny.BinaryLength];
                sidToDeny.GetBinaryForm(newSidBytes, 0);

                IntPtr pDenySid = Marshal.AllocHGlobal(newSidBytes.Length);
                allocatedSids.Add(pDenySid);
                Marshal.Copy(newSidBytes, 0, pDenySid, newSidBytes.Length);

                Marshal.WriteIntPtr(newGroupPtr, pDenySid);
                Marshal.WriteInt32(newGroupPtr, (int)IntPtr.Size, (int)(SE_GROUP_MANDATORY | SE_GROUP_USE_FOR_DENY_ONLY));

                // 8. Apply the updated token information
                int newCount = (int)groupCount + 1;
                _logger?.LogDebug($"SetTokenInformation(groups): groupCount={groupCount} sidAndAttrSize={sidAndAttrSize} newCount={newCount} newSize={newSize}");
                if (!NativeMethods.SetTokenInformation(token.DangerousGetHandle(), TokenGroups, pNew, (uint)newSize))
                {
                    int err = Marshal.GetLastWin32Error();
                    _logger?.LogError($"SetTokenInformation (groups) failed: error {err}.");
                    throw new System.ComponentModel.Win32Exception(err, "SetTokenInformation (groups) failed.");
                }
            }
            finally
            {
                // 9. Clean up all unmanaged memory
                if (pGroups != IntPtr.Zero) Marshal.FreeHGlobal(pGroups);
                if (pNew != IntPtr.Zero) Marshal.FreeHGlobal(pNew);
                foreach (IntPtr p in allocatedSids)
                {
                    if (p != IntPtr.Zero) Marshal.FreeHGlobal(p);
                }
            }
        }

        // Create a restricted token suitable for launching a sandboxed process.
        public Native.SafeTokenHandle CreateRestrictedToken(bool blockNetwork = true)
        {
            uint access = Native.NativeMethods.TOKEN_DUPLICATE
                        | Native.NativeMethods.TOKEN_QUERY
                        | Native.NativeMethods.TOKEN_ADJUST_DEFAULT
                        | Native.NativeMethods.TOKEN_ASSIGN_PRIMARY
                        | Native.NativeMethods.TOKEN_ADJUST_GROUPS;

            if (!Native.NativeMethods.OpenProcessToken(Native.NativeMethods.GetCurrentProcess(), access, out Native.SafeTokenHandle currentToken))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed.");

            using (currentToken)
            {
                // Duplicate token with desired access
                uint dupAccess = Native.NativeMethods.TOKEN_ASSIGN_PRIMARY
                               | Native.NativeMethods.TOKEN_QUERY
                               | Native.NativeMethods.TOKEN_ADJUST_DEFAULT
                               | Native.NativeMethods.TOKEN_ADJUST_GROUPS;

                if (!Native.NativeMethods.DuplicateTokenEx(currentToken.DangerousGetHandle(), dupAccess, IntPtr.Zero, 2 /*SecurityImpersonation*/, 1 /*TokenPrimary*/, out Native.SafeTokenHandle duplicatedToken))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx failed.");

                // Set low integrity level for the duplicated token so the sandbox runs at low integrity.
                try
                {
                    var lowIntegritySid = new SecurityIdentifier("S-1-16-4096"); // Low integrity
                    SetIntegrityLevel(duplicatedToken, lowIntegritySid);
                }
                catch (Exception ex)
                {
                    _logger?.LogError($"SetTokenInformation (integrity) failed: {ex.Message}");
                    // If integrity setting fails, return the token anyway; caller may handle it.
                }

                // Optionally add deny-only SIDs here (e.g., block network) by calling AddDenyOnlySid.
                if (blockNetwork)
                {
                    try
                    {
                        // Placeholder: callers can add specific deny-only SIDs using AddDenyOnlySid.
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogWarning($"AddDenyOnlySid failed: {ex.Message}");
                    }
                }

                // Return the duplicated token for the caller to use; do not dispose it here.
                return duplicatedToken;
            }
        }

        private void SetIntegrityLevel(Native.SafeTokenHandle token, SecurityIdentifier sid)
        {
            IntPtr pTml = IntPtr.Zero;
            try
            {
                // Prepare SID bytes
                byte[] sidBytes = new byte[sid.BinaryLength];
                sid.GetBinaryForm(sidBytes, 0);

                // Allocate a single buffer that contains TOKEN_MANDATORY_LABEL followed by the SID bytes.
                int tmlStructSize = Marshal.SizeOf<TOKEN_MANDATORY_LABEL>();
                int totalSize = tmlStructSize + sidBytes.Length;
                pTml = Marshal.AllocHGlobal(totalSize);
                // Pointer to where the SID will live inside the buffer
                IntPtr pSidInBuffer = IntPtr.Add(pTml, tmlStructSize);

                // Copy SID bytes into the buffer
                Marshal.Copy(sidBytes, 0, pSidInBuffer, sidBytes.Length);

                // Build the TOKEN_MANDATORY_LABEL that points to the SID inside the buffer
                TOKEN_MANDATORY_LABEL tml = new TOKEN_MANDATORY_LABEL
                {
                    Label = new SID_AND_ATTRIBUTES { Sid = pSidInBuffer, Attributes = 0 }
                };

                // Write the structure at the start of the buffer
                Marshal.StructureToPtr(tml, pTml, false);

                const int TokenIntegrityLevel = 25; // TokenInformationClass for integrity level
                if (!NativeMethods.SetTokenInformation(token.DangerousGetHandle(), TokenIntegrityLevel, pTml, (uint)totalSize))
                {
                    int err = Marshal.GetLastWin32Error();
                    throw new System.ComponentModel.Win32Exception(err, "SetTokenInformation (integrity) failed.");
                }
            }
            finally
            {
                if (pTml != IntPtr.Zero) Marshal.FreeHGlobal(pTml);
            }
        }
    }
}