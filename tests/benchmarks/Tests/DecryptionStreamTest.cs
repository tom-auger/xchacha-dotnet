namespace XChaChaDotNet.Benchmarks
{
    using BenchmarkDotNet.Attributes;
    using System;
    using System.IO;
    using XChaChaDotNet;

    public class DecryptionStreamTest
    {
        private XChaChaKey key;
        private MemoryStream nonBufferedCiphertextStream;
        private MemoryStream bufferedCiphertextStream;
        private byte[] bufferedOutput = new byte[1024 * 1024];
        private byte[] nonBufferedOutput = new byte[1024 * 1024];

        [Params(1024, 128 * 1024, 256 * 1024, 512 * 1024)]
        public int N { get; set; }

        [GlobalSetup]
        public void GlobalSetup()
        {
            var data = new byte[N];
            new Random(31).NextBytes(data);
            this.nonBufferedCiphertextStream = new MemoryStream();
            this.bufferedCiphertextStream = new MemoryStream();
            this.key = XChaChaKey.Generate();

            using (var bufferedEncryptionStream = new XChaChaBufferedStream(this.bufferedCiphertextStream, this.key, EncryptionMode.Encrypt, leaveOpen: true))
            {
                bufferedEncryptionStream.Write(data);
            }

            using (var encryptionStream = new XChaChaStream(this.nonBufferedCiphertextStream, this.key, EncryptionMode.Encrypt, leaveOpen: true))
            {
                encryptionStream.WriteFinal(data);
            }
        }

        [Benchmark]
        public void BufferedStream()
        {
            this.bufferedCiphertextStream.Position = 0;
            using (var decryptionStream = new XChaChaBufferedStream(this.bufferedCiphertextStream, this.key, EncryptionMode.Decrypt, leaveOpen: true))
            {
                decryptionStream.Read(this.bufferedOutput);
            }
        }

        [Benchmark]
        public void StandardStream()
        {
            this.nonBufferedCiphertextStream.Position = 0;
            using (var decryptionStream = new XChaChaStream(nonBufferedCiphertextStream, this.key, EncryptionMode.Decrypt, leaveOpen: true))
            {
                decryptionStream.Read(this.nonBufferedOutput);
            }
        }

        [GlobalCleanup]
        public void GlobalCleanup() 
        {
            this.nonBufferedCiphertextStream.Dispose();
            this.bufferedCiphertextStream.Dispose();
            this.key.Dispose();
        }
    }
}