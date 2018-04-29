namespace XChaChaDotNet.Benchmarks
{
    using BenchmarkDotNet.Attributes;
    using System;
    using System.IO;
    using XChaChaDotNet;

    public class SecretBoxTest
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
            this.nonce = nonce.ReadOnlySpan.ToArray();

            var secretBox = new XChaChaSecretBoxCipher();
            this.encryptedData = new byte[secretBox.GetCipherTextLength(this.data.Length)];
            this.decryptOutputBuffer = new byte[secretBox.GetCipherTextLength(this.data.Length)];
            secretBox.Encrypt(data, this.encryptedData, this.key, nonce);
        }

        [Benchmark]
        public void Encrypt()
        {
            var nonce = new XChaChaNonce(this.nonce);
            var secretBox = new XChaChaSecretBoxCipher();
            secretBox.Encrypt(data, this.encryptedData, this.key, nonce);
        }

        [Benchmark]
        public void Decrypt()
        {
            var nonce = new XChaChaNonce(this.nonce);
            var secretBox = new XChaChaSecretBoxCipher();
            secretBox.Decrypt(this.encryptedData, this.decryptOutputBuffer, this.key, nonce);
        }

        [GlobalCleanup]
        public void GlobalCleanup()
        {
            this.key.Dispose();
        }
    }
}