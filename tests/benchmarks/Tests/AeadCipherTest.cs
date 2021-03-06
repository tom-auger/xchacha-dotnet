namespace XChaChaDotNet.Benchmarks
{
    using BenchmarkDotNet.Attributes;
    using System;
    using System.IO;
    using XChaChaDotNet;

    public class AeadCipherTest
    {
        private XChaChaKey key;
        private XChaChaNonce nonce;
        private byte[] data;
        private byte[] encryptedData;
        private byte[] decryptOutputBuffer;

        [Params(1, 128, 256, 512)]
        public int DataLengthKb { get; set; }

        [GlobalSetup]
        public void GlobalSetup()
        {
            this.data = new byte[this.DataLengthKb * 1024];
            new Random(31).NextBytes(data);
            this.key = XChaChaKey.Generate();
            this.nonce = XChaChaNonce.Generate();
            var aeadCipher = new XChaChaAeadCipher();

            this.encryptedData = new byte[aeadCipher.GetCipherTextLength(this.data.Length)];
            this.decryptOutputBuffer = new byte[aeadCipher.GetCipherTextLength(this.data.Length)];
            aeadCipher.Encrypt(data, this.encryptedData, this.key, this.nonce);
        }

        [Benchmark]
        public void Encrypt()
        {
            var aeadCipher = new XChaChaAeadCipher();
            aeadCipher.Encrypt(data, this.encryptedData, this.key, this.nonce);
        }

        [Benchmark]
        public void Decrypt()
        {
            var aeadCipher = new XChaChaAeadCipher();
            aeadCipher.Decrypt(this.encryptedData, this.decryptOutputBuffer, this.key, this.nonce);
        }

        [GlobalCleanup]
        public void GlobalCleanup()
        {
            this.key.Dispose();
        }
    }
}