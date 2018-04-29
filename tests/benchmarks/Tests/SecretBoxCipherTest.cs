namespace XChaChaDotNet.Benchmarks
{
    using BenchmarkDotNet.Attributes;
    using System;
    using System.IO;
    using XChaChaDotNet;

    public class SecretBoxCipherTest
    {
        private XChaChaKey key;
        private byte[] nonce;
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

            var nonce = XChaChaNonce.Generate();
            this.nonce = nonce.ToArray();

            var secretBoxCipher = new XChaChaSecretBoxCipher();
            this.encryptedData = new byte[secretBoxCipher.GetCipherTextLength(this.data.Length)];
            this.decryptOutputBuffer = new byte[secretBoxCipher.GetCipherTextLength(this.data.Length)];
            secretBoxCipher.Encrypt(data, this.encryptedData, this.key, nonce);
        }

        [Benchmark]
        public void Encrypt()
        {
            var nonce = new XChaChaNonce(this.nonce);
            var secretBoxCipher = new XChaChaSecretBoxCipher();
            secretBoxCipher.Encrypt(data, this.encryptedData, this.key, nonce);
        }

        [Benchmark]
        public void Decrypt()
        {
            var nonce = new XChaChaNonce(this.nonce);
            var secretBoxCipher = new XChaChaSecretBoxCipher();
            secretBoxCipher.Decrypt(this.encryptedData, this.decryptOutputBuffer, this.key, nonce);
        }

        [GlobalCleanup]
        public void GlobalCleanup()
        {
            this.key.Dispose();
        }
    }
}