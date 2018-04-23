namespace XChaChaDotNet.UnitTests
{
    using System;

    public static class RandomBytesGenerator
    {
        private static readonly Random random = new Random();
        private static readonly object randomLock = new object();

        public static ReadOnlySpan<byte> NextBytes(int length)
        {
            lock (randomLock)
            {
                var buffer = new byte[length];
                random.NextBytes(buffer);
                return buffer;
            }
        }
    }
}