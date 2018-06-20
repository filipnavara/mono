using System.Diagnostics;

namespace System.Security.Cryptography
{
    static class IncrementalHashExtensions
    {
        public static void AppendData(this IncrementalHash incrementalHash, ReadOnlySpan<byte> data)
        {
            incrementalHash.AppendData (data.ToArray());
        }

        public static bool TryGetHashAndReset(this IncrementalHash incrementalHash, Span<byte> destination, out int bytesWritten)
        {
            var result = new ReadOnlySpan<byte> (incrementalHash.GetHashAndReset ());
            if (destination.Length <= result.Length) {
                result.CopyTo (destination);
                bytesWritten = result.Length;
                return true;
            }
            bytesWritten = 0;
            return false;
        }
    }
}