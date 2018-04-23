namespace XChaChaDotNet.Benchmarks
{
    using BenchmarkDotNet.Attributes;
    using System;
    using System.IO;
    using XChaChaDotNet;

    public class StreamEncryptionTest
    {
        private XChaChaKey key;
        private byte[] data;

        [Params(1, 128, 256, 512)]
        public int DataLengthKb { get; set; }

        [GlobalSetup]
        public void GlobalSetup()
        {
            this.data = new byte[this.DataLengthKb * 1024];
            new Random(31).NextBytes(data);
            this.key = XChaChaKey.Generate();
        }

        [Benchmark]
        public void BufferedStream()
        {
            using (var encryptionStream = new XChaChaBufferedStream(Stream.Null, this.key, EncryptionMode.Encrypt))
            {
                encryptionStream.Write(data);
            }
        }

        [Benchmark]
        public void StandardStream()
        {
            using (var encryptionStream = new XChaChaStream(Stream.Null, this.key, EncryptionMode.Encrypt))
            {
                encryptionStream.WriteFinal(data);
            }
        }

        [GlobalCleanup]
        public void GlobalCleanup() => this.key.Dispose();
    }
}