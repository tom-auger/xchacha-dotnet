namespace XChaChaDotNet.Benchmarks
{
    using BenchmarkDotNet.Attributes;
    using System;
    using System.IO;
    using XChaChaDotNet;

    public class BufferSizeTest
    {
        private const int DataLength = 5 * 1024 * 1024;

        private XChaChaKey key;
        private byte[] data = new byte[DataLength];
        private MemoryStream bufferedCiphertextStream = new MemoryStream();
        private byte[] bufferedOutput = new byte[DataLength];

        [Params(32, 64, 128, 256, 512, 1024)]
        public int BufferLengthKb { get; set; }

        [GlobalSetup]
        public void GlobalSetup()
        {
            new Random(31).NextBytes(data);
            this.key = XChaChaKey.Generate();

            using (var bufferedEncryptionStream = new XChaChaBufferedStream(
                this.bufferedCiphertextStream, this.key, EncryptionMode.Encrypt, leaveOpen: true))
            {
                bufferedEncryptionStream.Write(data);
            }
        }

        [Benchmark]
        public void Encryption()
        {
            var bufferLength = this.BufferLengthKb * 1024;
            using (var encryptionStream = new XChaChaBufferedStream(
                Stream.Null, this.key, EncryptionMode.Encrypt, bufferLength))
            {
                encryptionStream.Write(data);
            }
        }

        [Benchmark]
        public void Decryption()
        {
            this.bufferedCiphertextStream.Position = 0;
            using (var decryptionStream = new XChaChaBufferedStream(
                this.bufferedCiphertextStream, this.key, EncryptionMode.Decrypt, leaveOpen: true))
            {
                decryptionStream.Read(this.bufferedOutput);
            }
        }

        [GlobalCleanup]
        public void GlobalCleanup() => this.key.Dispose();
    }
}