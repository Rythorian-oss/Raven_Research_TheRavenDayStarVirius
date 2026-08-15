using System;

namespace RavenAntivirusResearch.Utils
{
    public static class ByteExtensions
    {
        /// <summary>
        /// Returns a new byte array containing the first <paramref name="count"/> bytes
        /// from <paramref name="source"/>.  This avoids ambiguity with LINQ's Enumerable.Take.
        /// </summary>
        public static byte[] TakeBytes(this byte[] source, int count)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            count = Math.Min(count, source.Length);
            byte[] result = new byte[count];
            Buffer.BlockCopy(source, 0, result, 0, count);
            return result;
        }
    }
}