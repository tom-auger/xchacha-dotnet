namespace XChaChaDotNet.Benchmarks
{
    using BenchmarkDotNet.Attributes;
    using System;
    using XChaChaDotNet;

    public class EncryptionStreamTest
    {
        private const int N = 1000;
        private readonly byte[] data;

        public EncryptionStreamTest()
        {
            this.data = new byte[N];
            new Random(31).NextBytes(data);
        }

        [Benchmark]
        public long RunTest()
        {
            var key = XChaChaKeyGenerator.GenerateKey();

            using (var devNull = new DevNullStream())
            {
                using (var encryptionStream = new XChaChaBufferedStream(devNull, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.Write(data);
                }

                return devNull.Length;
            }
        }
    }
}