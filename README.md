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
  Technical Deep Dive
1. Core Architecture: "Secure Steganography"
The Steganography class doesn't just hide data; it wraps it in a cryptographic envelope before embedding.

The Data Flow:

Input: Plain payload + Key.
Encryption: AES-CBC with a random IV.
Integrity: HMAC-SHA256 over the ciphertext.
Packaging: [4-byte Length] + [32-byte HMAC] + [Ciphertext].
Embedding: The package is hidden using the carrier-specific method (LSB or Appending).
This ensures that even if an attacker extracts the hidden data, they cannot verify its integrity or decrypt it without the key. If the data is tampered with (even by 1 bit), the HMAC check fails.

2. Carrier-Specific Techniques
PNG
LSB (Least Significant Bit)
Modifies the LSB of RGB channels in the pixel buffer. Uses a permutation to avoid clustering.
Lossless (mostly), widely supported, high capacity.
Detectable by statistical analysis (e.g., chi-square tests).
WAV
LSB in Audio Data
Modifies the LSB of the raw audio bytes in the data chunk.
Hard to hear (inaudible), high capacity.
Audio quality degradation is possible if capacity is high.
JPEG
Append-after-EOI
Appends data immediately after the 0xFFD9 (End of Image) marker.
Undetectable by parsers that stop at EOI.
Data is lost if the image is re-encoded or compressed.
3. Key Security Features
A. Deterministic Permutation (Anti-Stego)
Standard LSB steganography is vulnerable because it embeds sequentially. This makes the statistical distribution of the image "noisy" in a predictable way.

How it works: BuildPermutation uses the Key to seed a Random number generator, which shuffles the indices of the bits/bytes to be modified.
Effect: The hidden data is scattered randomly across the carrier. This makes statistical detection (like chi-square analysis) significantly harder because the "noise" is uniform, not clustered.
Reproducibility: Since the seed is derived from the key and the file size, the extraction process uses the exact same shuffled order to read the bits back.
B. Cryptographic Integrity (HMAC)
The code uses HMAC-SHA256 to verify the data hasn't been altered.

Implementation: ComputeHmac generates a hash of the encrypted payload.
Verification: VerifyHmac uses FixedTimeEquals to prevent timing attacks. This is a critical detail: if it used == for byte arrays, an attacker could time the comparison to guess the key.
C. AES-CBC Encryption
Algorithm: Aes.Create() with a user-provided key.
IV Handling: A random IV is generated for each encryption and prepended to the ciphertext. This ensures that encrypting the same payload twice yields different results (semantic security).
4. Code Walkthrough
Step 1: Embedding (EmbedData)
csharp

Copy
byte[] encrypted = EncryptPayload(payload, key); // AES-CBC
byte[] hash = ComputeHmac(encrypted, key);       // HMAC-SHA256
byte[] dataToHide = PackHiddenData(encrypted, hash); // [Len][HMAC][Cipher]

// Carrier selection
if (CarrierIsPng(carrier)) return EmbedPngLsb(carrier, dataToHide, key);
// ... WAV or JPEG logic
Validation: Checks file signatures (PNG, RIFF, FFD8) to ensure the carrier is valid.
Capacity Check: Ensures the payload isn't larger than the carrier's capacity (MaxEmbeddingBits limit).
Step 2: PNG LSB Implementation
The code uses System.Drawing.Bitmap to lock the pixel buffer.

Pixel Format: Format32bppArgb (4 bytes per pixel: B, G, R, A).
Embedding Logic:
Iterates through the permutation sequence.
Calculates the byte offset: row * stride + col * 4 + channel.
Bitwise Operation: buffer[byteOff] = (byte)((buffer[byteOff] & 0xFE) | bitVal);
& 0xFE: Clears the LSB.
| bitVal: Sets the LSB to the data bit.
Permutation: The BuildPermutation method ensures the bits are read/written in a scrambled order based on the key.
Step 3: WAV Parsing
Chunk Scanning: The ParseWav method scans the RIFF header for the data chunk.
Offset Calculation: It finds the exact byte offset of the audio data to avoid modifying the header (which could break the file).
Step 4: JPEG Append
EOI Search: Finds the 0xFFD9 marker (End of Image).
Append: Creates a new buffer, copies the original up to EOI, and appends the payload.
Risk: This is not robust. If the image is saved again with a tool that re-compresses or re-encodes (e.g., Photoshop, browser resizing), the appended data is lost.
Detection & Mitigation Strategies
If you are researching this for defensive purposes (e.g., building a detector), here is what to look for:

PNG
Chi-Square Test: Checks if the LSB distribution is uniform (it shouldn't be if stego is used).
RS Analysis: Detects changes in the "reliability" of pixel groups.
WAV
Spectral Analysis: Look for unnatural patterns in the frequency domain or high-frequency noise.
JPEG
File Size Check: If a file is larger than expected for its quality, or if it contains data after 0xFFD9.
Trailing Data Scanner: Scan all files for non-standard bytes after known EOF markers.
Encryption
HMAC Presence: The [4-byte Len][32-byte HMAC][Cipher] structure is unusual in legitimate media. Detecting this specific header pattern is a strong indicator.
Permutation
Statistical Uniformity: If the LSB noise is perfectly uniform (due to the permutation), it might actually be more suspicious than natural noise.
Code Quality & Security Analysis
Encryption
⭐⭐⭐⭐
Uses AES-CBC with random IV. Good.
Integrity
⭐⭐⭐⭐⭐
HMAC-SHA256 with FixedTimeEquals prevents timing leaks. Excellent.
Anti-Detection
⭐⭐⭐⭐
Permutation adds significant resistance to simple statistical steganalysis.
Robustness
⭐⭐
JPEG is fragile. PNG/WAV are okay, but System.Drawing is heavy and can be slow on large images.
Dependencies
⭐⭐
Relies on System.Drawing (GDI+), which is not recommended for server-side or high-performance applications (it's slow and can leak handles). Consider SkiaSharp or ImageSharp for modern .NET.
Error Handling
⭐⭐⭐
Throws exceptions for invalid inputs, which is good, but could be more specific.
Potential Improvements
Replace System.Drawing: The Bitmap class is slow and not designed for bulk processing. For a research tool, consider using ImageSharp (cross-platform, faster, no GDI+ dependency).

Steganalysis Resistance: The current LSB approach is still detectable by advanced tools. For high-security research, consider using Least Significant Digit (LSD) in decimal or DCT domain steganography (for JPEG), which is harder to detect.

Key Derivation: The code uses the raw key bytes. For better security, consider using PBKDF2 or Argon2 to derive a key from a password, preventing weak keys from being used directly.

JPEG Robustness: The append method with safety/wrappers to protect de-stabilization of critical data. 

Conclusion
This is a high-quality, research-grade steganography tool. It correctly implements cryptographic best practices (HMAC, AES-CBC) and adds a layer of anti-steganalysis (permutation).
