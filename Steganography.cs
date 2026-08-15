#nullable enable
using RavenAntivirusResearch.Utils;
using System;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace RavenAntivirusResearch.Core
{
    /// <summary>
    /// Steganography implementation supporting PNG (LSB in RGB), WAV (LSB in data bytes),
    /// and JPEG (appending after EOI). Uses AES‑CBC with HMAC‑SHA256 for integrity.
    /// </summary>
    public static class Steganography
    {
        private static readonly byte[] PngSignature = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
        private static readonly byte[] WavHeader = { 0x52, 0x49, 0x46, 0x46 };
        private static readonly byte[] JpegStart = { 0xFF, 0xD8 };
        private const int MaxEmbeddingBits = 10_000_000;
        private const int IV_SIZE = 16;

        // ---------------------------------------------------------------
        // Public API
        // ---------------------------------------------------------------

        public static byte[] EmbedData(byte[] carrier, byte[] payload, byte[] key, ILogger? logger = null)
        {
            ValidateInputs(carrier, payload, key);

            // 1. Encrypt payload with a random IV (IV prepended to ciphertext)
            byte[] encrypted = EncryptPayload(payload, key);

            // 2. Compute HMAC over the encrypted payload (not including IV)
            byte[] hash = ComputeHmac(encrypted, key);

            // 3. Pack: [4‑byte length of encrypted] + [32‑byte HMAC] + [encrypted payload]
            byte[] dataToHide = PackHiddenData(encrypted, hash);

            logger?.LogDebug($"Hidden block size: {dataToHide.Length} bytes.");

            if (CarrierIsPng(carrier))
            {
                logger?.LogDebug("PNG carrier – using LSB embedding.");
                return EmbedPngLsb(carrier, dataToHide, key);
            }
            if (CarrierIsWav(carrier))
            {
                logger?.LogDebug("WAV carrier – using LSB embedding.");
                return EmbedWavLsb(carrier, dataToHide, key);
            }
            if (CarrierIsJpeg(carrier))
            {
                logger?.LogDebug("JPEG carrier – appending after EOI.");
                return AppendJpeg(carrier, dataToHide);
            }

            throw new NotSupportedException("Only PNG, WAV, and JPEG carriers are supported.");
        }

        public static byte[] ExtractData(byte[] carrier, byte[] key, ILogger? logger = null)
        {
            if (carrier == null) throw new ArgumentNullException(nameof(carrier));
            if (key == null || key.Length == 0) throw new ArgumentException("Key required.");

            byte[] raw;

            if (CarrierIsPng(carrier))
            {
                logger?.LogDebug("Extracting from PNG…");
                raw = ExtractPngLsb(carrier, key);
            }
            else if (CarrierIsWav(carrier))
            {
                logger?.LogDebug("Extracting from WAV…");
                raw = ExtractWavLsb(carrier, key);
            }
            else if (CarrierIsJpeg(carrier))
            {
                logger?.LogDebug("Extracting from JPEG…");
                raw = ExtractJpegAppended(carrier);
            }
            else
            {
                throw new NotSupportedException("Unsupported carrier format.");
            }

            // Minimum: 4 bytes length + 32 bytes HMAC + at least 1 byte payload
            if (raw.Length < 37)
                throw new InvalidDataException("Extracted data too short.");

            int encLen = BitConverter.ToInt32(raw, 0);
            if (encLen <= 0 || 36 + encLen > raw.Length)
                throw new InvalidDataException("Invalid embedded length.");

            byte[] hash = new byte[32];
            Buffer.BlockCopy(raw, 4, hash, 0, 32);
            byte[] encrypted = new byte[encLen];
            Buffer.BlockCopy(raw, 36, encrypted, 0, encLen);

            if (!VerifyHmac(encrypted, hash, key))
                throw new CryptographicException("Integrity check failed.");

            return DecryptPayload(encrypted, key);
        }

        // ---------------------------------------------------------------
        // Carrier detection
        // ---------------------------------------------------------------
        private static bool CarrierIsPng(byte[] d) => d.AsSpan(0, PngSignature.Length).SequenceEqual(PngSignature);
        private static bool CarrierIsWav(byte[] d) =>
            d.AsSpan(0, 4).SequenceEqual(WavHeader) &&
            d.Length > 11 && d[8] == 'W' && d[9] == 'A' && d[10] == 'V' && d[11] == 'E';
        private static bool CarrierIsJpeg(byte[] d) => d.AsSpan(0, 2).SequenceEqual(JpegStart);

        // ---------------------------------------------------------------
        // Corrected AES‑CBC Encryption / Decryption
        // ---------------------------------------------------------------
        private static byte[] EncryptPayload(byte[] payload, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();
            byte[] iv = aes.IV;

            using var encryptor = aes.CreateEncryptor(aes.Key, iv);
            byte[] ciphertext = encryptor.TransformFinalBlock(payload, 0, payload.Length);

            // Prepend IV to ciphertext
            byte[] result = new byte[IV_SIZE + ciphertext.Length];
            Buffer.BlockCopy(iv, 0, result, 0, IV_SIZE);
            Buffer.BlockCopy(ciphertext, 0, result, IV_SIZE, ciphertext.Length);
            return result;
        }

        private static byte[] DecryptPayload(byte[] encrypted, byte[] key)
        {
            if (encrypted.Length < IV_SIZE)
                throw new ArgumentException("Encrypted data too short to contain IV.");

            byte[] iv = new byte[IV_SIZE];
            Buffer.BlockCopy(encrypted, 0, iv, 0, IV_SIZE);
            byte[] ciphertext = new byte[encrypted.Length - IV_SIZE];
            Buffer.BlockCopy(encrypted, IV_SIZE, ciphertext, 0, ciphertext.Length);

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        }

        private static byte[] ComputeHmac(byte[] data, byte[] key)
        {
            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(data);
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;

            int result = 0;
            for (int i = 0; i < a.Length; i++)
                result |= a[i] ^ b[i];
            return result == 0;
        }

        private static bool VerifyHmac(byte[] data, byte[] expected, byte[] key)
        {
            byte[] actual = ComputeHmac(data, key);
            return FixedTimeEquals(actual, expected);
        }

        private static byte[] PackHiddenData(byte[] encrypted, byte[] hash)
        {
            byte[] result = new byte[4 + hash.Length + encrypted.Length];
            BitConverter.GetBytes(encrypted.Length).CopyTo(result, 0);
            Buffer.BlockCopy(hash, 0, result, 4, hash.Length);
            Buffer.BlockCopy(encrypted, 0, result, 4 + hash.Length, encrypted.Length);
            return result;
        }

        // ---------------------------------------------------------------
        // PNG LSB
        // ---------------------------------------------------------------
        private static byte[] EmbedPngLsb(byte[] carrier, byte[] data, byte[] key)
        {
            using var ms = new MemoryStream(carrier);
            using var bitmap = new Bitmap(ms);

            int width = bitmap.Width, height = bitmap.Height;
            int capacityBits = width * height * 3; // only RGB channels
            int bitsNeeded = data.Length * 8;

            if (bitsNeeded > capacityBits)
                throw new ArgumentException($"Payload too large for this PNG (need {bitsNeeded} bits, have {capacityBits}).");
            if (capacityBits > MaxEmbeddingBits)
                throw new InvalidOperationException($"PNG capacity exceeds safety limit of {MaxEmbeddingBits} bits.");

            var rect = new Rectangle(0, 0, width, height);
            var bmpData = bitmap.LockBits(rect, ImageLockMode.ReadWrite, PixelFormat.Format32bppArgb);
            int stride = bmpData.Stride;
            byte[] buffer = new byte[stride * height];
            Marshal.Copy(bmpData.Scan0, buffer, 0, buffer.Length);

            int[] perm = BuildPermutation(capacityBits, key);
            int bitIdx = 0;
            foreach (int pos in perm)
            {
                if (bitIdx >= bitsNeeded) break;
                int pixelIdx = pos / 3;
                int row = pixelIdx / width;
                int col = pixelIdx % width;
                int chan = pos % 3; // 0=B,1=G,2=R (BGRA order)
                int byteOff = row * stride + col * 4 + chan;
                byte bitVal = (byte)((data[bitIdx / 8] >> (bitIdx % 8)) & 1);
                buffer[byteOff] = (byte)((buffer[byteOff] & 0xFE) | bitVal);
                bitIdx++;
            }

            Marshal.Copy(buffer, 0, bmpData.Scan0, buffer.Length);
            bitmap.UnlockBits(bmpData);

            using var outMs = new MemoryStream();
            bitmap.Save(outMs, ImageFormat.Png);
            return outMs.ToArray();
        }

        private static byte[] ExtractPngLsb(byte[] carrier, byte[] key)
        {
            using var ms = new MemoryStream(carrier);
            using var bitmap = new Bitmap(ms);

            int width = bitmap.Width, height = bitmap.Height;
            int capacityBits = width * height * 3;
            if (capacityBits > MaxEmbeddingBits)
                throw new InvalidOperationException($"PNG capacity exceeds safety limit of {MaxEmbeddingBits} bits.");

            var rect = new Rectangle(0, 0, width, height);
            var bmpData = bitmap.LockBits(rect, ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
            int stride = bmpData.Stride;
            byte[] buffer = new byte[stride * height];
            Marshal.Copy(bmpData.Scan0, buffer, 0, buffer.Length);
            bitmap.UnlockBits(bmpData);

            int[] perm = BuildPermutation(capacityBits, key);
            int totalBytes = capacityBits / 8;
            byte[] result = new byte[totalBytes];
            int bitIdx = 0;
            foreach (int pos in perm)
            {
                if (bitIdx >= capacityBits) break;
                int pixelIdx = pos / 3;
                int row = pixelIdx / width;
                int col = pixelIdx % width;
                int chan = pos % 3;
                int byteOff = row * stride + col * 4 + chan;
                byte bitVal = (byte)(buffer[byteOff] & 1);
                result[bitIdx / 8] |= (byte)(bitVal << (bitIdx % 8));
                bitIdx++;
            }
            return result;
        }

        // ---------------------------------------------------------------
        // WAV LSB
        // ---------------------------------------------------------------
        private static byte[] EmbedWavLsb(byte[] carrier, byte[] data, byte[] key)
        {
            var (dataOff, dataSize, _, _) = ParseWav(carrier);
            int bitsNeeded = data.Length * 8;
            if (bitsNeeded > dataSize * 8)
                throw new ArgumentException("Payload too large for WAV data chunk.");
            if (dataSize * 8 > MaxEmbeddingBits)
                throw new InvalidOperationException($"WAV capacity exceeds safety limit of {MaxEmbeddingBits} bits.");

            byte[] result = new byte[carrier.Length];
            Buffer.BlockCopy(carrier, 0, result, 0, carrier.Length);

            int[] perm = BuildPermutation(dataSize, key);
            int bitIdx = 0;
            foreach (int bytePos in perm)
            {
                if (bitIdx >= bitsNeeded) break;
                int actualOff = dataOff + bytePos;
                byte bitVal = (byte)((data[bitIdx / 8] >> (bitIdx % 8)) & 1);
                result[actualOff] = (byte)((result[actualOff] & 0xFE) | bitVal);
                bitIdx++;
            }
            return result;
        }

        private static byte[] ExtractWavLsb(byte[] carrier, byte[] key)
        {
            var (dataOff, dataSize, _, _) = ParseWav(carrier);
            if (dataSize * 8 > MaxEmbeddingBits)
                throw new InvalidOperationException($"WAV capacity exceeds safety limit of {MaxEmbeddingBits} bits.");

            int totalBytes = dataSize;
            byte[] result = new byte[totalBytes];
            int[] perm = BuildPermutation(dataSize, key);
            int bitIdx = 0;
            foreach (int bytePos in perm)
            {
                if (bitIdx >= dataSize * 8) break;
                int actualOff = dataOff + bytePos;
                byte bitVal = (byte)(carrier[actualOff] & 1);
                result[bitIdx / 8] |= (byte)(bitVal << (bitIdx % 8));
                bitIdx++;
            }
            return result;
        }

        private static (int dataOffset, int dataSize, int bitsPerSample, int channels) ParseWav(byte[] wav)
        {
            if (wav.Length < 44) throw new InvalidDataException("WAV file too small.");
            int bits = BitConverter.ToUInt16(wav, 34);
            int ch = BitConverter.ToUInt16(wav, 22);
            int off = 12;
            while (off < wav.Length - 8)
            {
                string id = Encoding.ASCII.GetString(wav, off, 4);
                uint size = BitConverter.ToUInt32(wav, off + 4);
                if (id == "data")
                    return (off + 8, (int)size, bits, ch);
                off += 8 + (int)size;
            }
            throw new InvalidDataException("WAV data chunk not found.");
        }
   
             // Constants for the safe wrapper
        private static readonly byte[] MagicHeader = { 0x52, 0x41, 0x56, 0x4E }; // "RAVN"
        private static readonly byte[] MagicFooter = { 0x45, 0x4E, 0x44, 0x56 }; // "ENDV"
        private const int HeaderSize = 4 + 4 + 8 + 8 + 32 + 16; // |Magic|Ver|OrigSz|PlySz|Hmac|Iv|
        private const int FooterSize = 4;
        // ---------------------------------------------------------------
        // JPEG append/extract/protective strategy involving critical data remaining stable
        // ---------------------------------------------------------------
      private static byte[] SafeAppendJpeg(byte[] carrier, byte[] payload, byte[] key)
{
    // 1. Validate Carrier
    if (!CarrierIsJpeg(carrier)) throw new ArgumentException("Carrier is not a valid JPEG.");

    // 2. Encrypt and Hash (Reuse existing logic)
    byte[] encrypted = EncryptPayload(payload, key);
    byte[] hash = ComputeHmac(encrypted, key);
    byte[] iv = new byte[16];
    Buffer.BlockCopy(encrypted, 0, iv, 0, 16);
    byte[] cipherData = new byte[encrypted.Length - 16];
    Buffer.BlockCopy(encrypted, 16, cipherData, 0, cipherData.Length);

    // 3. Build the Safe Wrapper
    // [MagicHeader | Version | OriginalSize | PayloadSize | HMAC | IV | CipherData | MagicFooter]
    int payloadSize = payload.Length;
    int originalSize = carrier.Length;
    
    byte[] wrapper = new byte[HeaderSize + payloadSize + FooterSize];
    
    // Write Header
    Buffer.BlockCopy(MagicHeader, 0, wrapper, 0, 4);
    BitConverter.GetBytes(1).CopyTo(wrapper, 4); // Version
    BitConverter.GetBytes(originalSize).CopyTo(wrapper, 8);
    BitConverter.GetBytes(payloadSize).CopyTo(wrapper, 16);
    Buffer.BlockCopy(hash, 0, wrapper, 24, 32);
    Buffer.BlockCopy(iv, 0, wrapper, 56, 16);
    
    // Write Payload
    Buffer.BlockCopy(cipherData, 0, wrapper, 72, payloadSize);
    
    // Write Footer
    Buffer.BlockCopy(MagicFooter, 0, wrapper, wrapper.Length - 4, 4);

    // 4. Safe Write Strategy (Atomic)
    string tempPath = Path.GetTempFileName();
    try
    {
        // Create the new file
        byte[] result = new byte[carrier.Length + wrapper.Length];
        Buffer.BlockCopy(carrier, 0, result, 0, carrier.Length);
        Buffer.BlockCopy(wrapper, 0, result, carrier.Length, wrapper.Length);

        // 5. Validate before committing (Read back and check magic)
        // In a real attempt, you would write to temp, verify, then replace.
        // Here we just return the safe buffer.
        return result;
    }
    catch (Exception ex)
    {
        // Cleanup temp file if created
        if (File.Exists(tempPath)) File.Delete(tempPath);
        throw new IOException("Failed to safely append data to JPEG.", ex);
    }
}

        private static byte[] ExtractJpegAppended(byte[] carrier)
        {
            int eoi = FindJpegEoi(carrier);
            if (eoi + 2 >= carrier.Length) return Array.Empty<byte>();

            int payloadLen = carrier.Length - (eoi + 2);
            byte[] payload = new byte[payloadLen];
            Buffer.BlockCopy(carrier, eoi + 2, payload, 0, payloadLen);
            return payload;
        }

        private static int FindJpegEoi(byte[] jpeg)
        {
            for (int i = jpeg.Length - 2; i >= 0; i--)
                if (jpeg[i] == 0xFF && jpeg[i + 1] == 0xD9) return i;
            throw new InvalidDataException("JPEG EOI marker not found.");
        }

        // ---------------------------------------------------------------
        // Deterministic permutation
        // ---------------------------------------------------------------
        private static int[] BuildPermutation(int n, byte[] key)
        {
            if (n > MaxEmbeddingBits) throw new ArgumentException("Capacity too large for permutation.");

            int[] arr = new int[n];
            for (int i = 0; i < n; i++) arr[i] = i;

            using var hmac = new HMACSHA256(key);
            byte[] seedBytes = hmac.ComputeHash(BitConverter.GetBytes(n));
            int seed = BitConverter.ToInt32(seedBytes, 0);
            var rng = new Random(seed);

            // Fisher-Yates shuffle
            for (int i = n - 1; i > 0; i--)
            {
                int j = rng.Next(i + 1);
                (arr[i], arr[j]) = (arr[j], arr[i]);
            }
            return arr;
        }

        private static void ValidateInputs(byte[] carrier, byte[] payload, byte[] key)
        {
            if (carrier == null) throw new ArgumentNullException(nameof(carrier));
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            if (key == null || key.Length == 0) throw new ArgumentException("Key required.");
            if (carrier.Length == 0) throw new ArgumentException("Carrier empty.");
            if (payload.Length == 0) throw new ArgumentException("Payload empty.");
        }
    }
}
