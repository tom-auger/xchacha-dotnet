
namespace XChaChaDotNet.UnitTests
{
    using System;

    public static class RandomBytesGenerator
    {
        private static readonly Random random = new Random(DateTime.Now.Millisecond);

        public static void NextBytes(Span<byte> bytes)
        {
            random.NextBytes(bytes);
        }
    }
}