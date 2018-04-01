
namespace XChaChaDotNet.UnitTests
{
    using System;

    public static class RandomBytesGenerator
    {
        private static readonly Random random = new Random(DateTime.Now.Millisecond);

        public static Span<byte> NextBytes(int length)
        {
            var buffer = new byte[length];
            random.NextBytes(buffer);
            return buffer;
        }
    }
}