# Raven_Research_TheRavenDayStarVirius

This code is a process hollowing (RunPE) injector written in C# for Windows. It demonstrates advanced Windows API manipulation techniques to inject a payload into a target process by replacing its original image with a new one. While the comments emphasize educational and legitimate use cases (debugging, sandboxing, testing), the core functionality is identical to techniques exploited by malware for persistence, privilege escalation, and evasion.

⚠️ Critical Security & Ethical Warning
This code is a weaponization tool. Using it on any system you do not own or have explicit written authorization to test is:

Illegal under laws like the Computer Fraud and Abuse Act (CFAA) and similar statutes globally.
Detectable by modern EDR (Endpoint Detection and Response) systems, application whitelisting, and behavioral analysis tools.
Highly Destructive if misused, as it can bypass security controls and compromise system integrity.
Do not use this code outside of a legally authorized, isolated research lab environment.

Technical Deep Dive: How It Works
The RavenInject class implements a classic Process Hollowing attack. Here’s the step-by-step breakdown:

1. Process Creation (Suspended State)
CreateProcessA(..., creationFlags | PROCESS_CREATE_SUSPENDED, ...)
Launches the target executable (e.g., notepad.exe) but pauses its primary thread immediately after creation.
This prevents the legitimate code from running, giving the attacker time to manipulate memory.

2. Architecture Detection & PEB Access
The code distinguishes between:
32-bit targets on 64-bit hosts (WOW64): Uses Wow64GetThreadContext to read the 32-bit context and extracts the PEB address from the EBX register.
Native 64-bit or 32-bit targets: Uses NtQueryInformationProcess to retrieve the PROCESS_BASIC_INFORMATION structure, which contains the PEB base address.
The PEB (Process Environment Block) is a critical data structure in the process memory that holds metadata about the executable, including the ImageBaseAddress.

3. PE Header Parsing:
The ParsePayload method reads the target payload's PE headers:

Validates the PE\0\0 signature.
Extracts ImageBase, SizeOfImage, SizeOfHeaders, and section details.
Checks for .NET CLI headers to potentially patch execution flags.
4. Unmapping the Original Image:
NtUnmapViewOfSection(pi.hProcess, currentImageBase)
If the target process’s ImageBase matches the payload’s ImageBase, the injector calls NtUnmapViewOfSection to remove the legitimate executable from the process memory.
This is the "hollowing" part: the process is running, but its original code is gone.

5. Injecting the Payload:
Allocation: VirtualAllocEx reserves and commits memory at the payload’s specified ImageBase.
Writing: WriteProcessMemory writes:
The PE headers (MZ header, NT headers, section headers).
Each section of the payload (e.g., .text, .data) to the new memory locations.
PEB Update: WriteImageBaseToPEB updates the PEB’s ImageBaseAddress to point to the malicious payload, tricking the system into believing the legitimate code is now at the new location.

6. Resumption
ResumeThread(pi.hThread)
The suspended thread is resumed. The process now executes the injected payload instead of its original code, often appearing legitimate to basic monitoring tools.

Feature	Detail:
Supported Scenarios	32-bit → 32-bit, 64-bit → 64-bit, 64-bit host → 32-bit WOW64 target.
Blocked Scenario	32-bit host → 64-bit target (architecture mismatch).
Base Address Matching	Requires the payload’s ImageBase to match the target’s original ImageBase to unmap successfully. If they differ, the injection may fail or require complex relocation.
Anti-Debugging	No anti-debugging checks; legitimate debuggers can detect the suspension.

Modern EDR Detection	High risk. NtUnmapViewOfSection, VirtualAllocEx on suspended processes, and PEB manipulation are well-known indicators of compromise (IOCs).

Legitimate vs. Malicious Use:

Debugging/Reverse Engineering: Analyzing a process without its original code interfering.	Malware Persistence: Injecting into trusted processes (e.g., svchost.exe) to hide.

Sandboxing/Virtualization: Instrumenting processes for security research.	Bypassing Whitelisting: Running unauthorized code within a whitelisted process.

Security Research: Testing detection capabilities in a controlled lab.	Privilege Escalation: Injecting into high-privilege processes to gain access.

Detection & Mitigation:
Modern security solutions detect this technique by:

Monitoring NtUnmapViewOfSection: This call is rare in legitimate software and highly suspicious in a security context.

Process Memory Integrity: Scanning for mismatches between the PEB’s ImageBase and the actual loaded modules.

Behavioral Analysis: Detecting processes created in CREATE_SUSPENDED state followed by memory manipulation and resumption.

Code Flow Validation: Ensuring the code at the ImageBase matches the expected hash/signature of the legitimate executable.

Conclusion:
This code is a sophisticated but dangerous tool. While it demonstrates deep knowledge of Windows internals, its primary utility is for offensive security operations. If you are researching this for defensive purposes:

Do not run it on any system you do not fully control.
Use it in a VM with network isolation.
Focus on detection strategies rather than implementation.
